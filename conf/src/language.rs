// Copyright 2026 bgpgg Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Generic lexer and root parser for the rogg config language.
//!
//! ## Grammar (root level)
//!
//! ```text
//! root         = service*
//! service      = "service" NAME '{' body '}'
//! setting      = KEY VALUE NEWLINE
//! ```
//!
//! `#` starts a line comment. The parser is context-sensitive recursive descent:
//! each scope has its own parse function with keyword dispatch.
//!
//! ## Pipeline
//!
//! ```text
//! source text -> tokenize() -> Vec<Token> -> parse() -> Root (typed AST)
//! ```

use std::fmt;

use crate::language_bgp::{self, BgpServiceBody};

/// Root of the parsed config file.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Root {
    pub services: Vec<Service>,
}

/// A `service <kind> { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub enum Service {
    Bgp(BgpServiceBody),
}

/// Parse error with line number and description.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

pub(crate) fn parse_err(line: usize, message: impl Into<String>) -> ParseError {
    ParseError {
        line,
        message: message.into(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TokenKind {
    Word(String),
    OpenBrace,
    CloseBrace,
    Newline,
}

pub(crate) const CHAR_OPENING_BRACE: char = '{';
pub(crate) const CHAR_CLOSING_BRACE: char = '}';
pub(crate) const CHAR_COMMENT: char = '#';

/// Lexer. Produces a token stream from source text.
pub(crate) fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();

    for (line_idx, line) in input.lines().enumerate() {
        let line_num = line_idx + 1;

        let line = match line.find(CHAR_COMMENT) {
            Some(pos) => &line[..pos],
            None => line,
        };

        let mut chars = line.chars().peekable();
        while let Some(&ch) = chars.peek() {
            if ch.is_whitespace() {
                chars.next();
                continue;
            }
            if ch == CHAR_OPENING_BRACE {
                tokens.push(Token {
                    kind: TokenKind::OpenBrace,
                    line: line_num,
                });
                chars.next();
            } else if ch == CHAR_CLOSING_BRACE {
                tokens.push(Token {
                    kind: TokenKind::CloseBrace,
                    line: line_num,
                });
                chars.next();
            } else {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || c == CHAR_OPENING_BRACE || c == CHAR_CLOSING_BRACE {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                tokens.push(Token {
                    kind: TokenKind::Word(word),
                    line: line_num,
                });
            }
        }

        tokens.push(Token {
            kind: TokenKind::Newline,
            line: line_num,
        });
    }

    tokens
}

pub(crate) fn current_line(tokens: &[Token], pos: usize) -> usize {
    if pos < tokens.len() {
        tokens[pos].line
    } else {
        tokens.last().map(|t| t.line).unwrap_or(0)
    }
}

pub(crate) fn peek_kind(tokens: &[Token], pos: usize) -> Option<&TokenKind> {
    tokens.get(pos).map(|tok| &tok.kind)
}

/// Consume one Word token, returning (word, line). Error on any other kind or EOF.
pub(crate) fn expect_word(
    tokens: &[Token],
    pos: &mut usize,
) -> Result<(String, usize), ParseError> {
    match tokens.get(*pos) {
        Some(tok) => match &tok.kind {
            TokenKind::Word(word) => {
                let out = (word.clone(), tok.line);
                *pos += 1;
                Ok(out)
            }
            TokenKind::OpenBrace => Err(parse_err(tok.line, "expected word, got '{'")),
            TokenKind::CloseBrace => Err(parse_err(tok.line, "expected word, got '}'")),
            TokenKind::Newline => Err(parse_err(tok.line, "expected word, got end of line")),
        },
        None => Err(parse_err(
            current_line(tokens, *pos),
            "unexpected end of input",
        )),
    }
}

/// If the next token is a Word, consume and return it. Otherwise leave pos unchanged.
pub(crate) fn take_word(tokens: &[Token], pos: &mut usize) -> Option<String> {
    match tokens.get(*pos) {
        Some(Token {
            kind: TokenKind::Word(word),
            ..
        }) => {
            let out = word.clone();
            *pos += 1;
            Some(out)
        }
        _ => None,
    }
}

/// Consume `{`. Caller is responsible for any leading newline skipping.
pub(crate) fn expect_open_brace(tokens: &[Token], pos: &mut usize) -> Result<(), ParseError> {
    match tokens.get(*pos) {
        Some(Token {
            kind: TokenKind::OpenBrace,
            ..
        }) => {
            *pos += 1;
            Ok(())
        }
        Some(tok) => Err(parse_err(tok.line, "expected '{'")),
        None => Err(parse_err(
            current_line(tokens, *pos),
            "unexpected end of input, expected '{'",
        )),
    }
}

/// Consume `}`.
pub(crate) fn expect_close_brace(tokens: &[Token], pos: &mut usize) -> Result<(), ParseError> {
    match tokens.get(*pos) {
        Some(Token {
            kind: TokenKind::CloseBrace,
            ..
        }) => {
            *pos += 1;
            Ok(())
        }
        Some(tok) => Err(parse_err(tok.line, "expected '}'")),
        None => Err(parse_err(
            current_line(tokens, *pos),
            "unexpected end of input, expected '}'",
        )),
    }
}

/// Close out a leaf statement: consume trailing Newline, or leave CloseBrace/EOF untouched
/// for the caller. Any other token is a trailing-token error.
pub(crate) fn finish_statement(tokens: &[Token], pos: &mut usize) -> Result<(), ParseError> {
    match tokens.get(*pos) {
        None => Ok(()),
        Some(tok) => match &tok.kind {
            TokenKind::Newline => {
                *pos += 1;
                Ok(())
            }
            TokenKind::CloseBrace => Ok(()),
            TokenKind::Word(word) => Err(parse_err(
                tok.line,
                format!("unexpected trailing token '{}'", word),
            )),
            TokenKind::OpenBrace => Err(parse_err(tok.line, "unexpected '{'")),
        },
    }
}

pub(crate) fn skip_newlines(tokens: &[Token], pos: &mut usize) {
    while let Some(Token {
        kind: TokenKind::Newline,
        ..
    }) = tokens.get(*pos)
    {
        *pos += 1;
    }
}

/// Parse rogg config text into a typed AST.
pub fn parse(input: &str) -> Result<Root, ParseError> {
    let tokens = tokenize(input);
    let mut pos = 0;
    parse_root(&tokens, &mut pos)
}

fn parse_root(tokens: &[Token], pos: &mut usize) -> Result<Root, ParseError> {
    let mut root = Root::default();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            None => break,
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '{'"));
            }
            Some(TokenKind::CloseBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '}'"));
            }
            _ => {}
        }
        let (kw, line) = expect_word(tokens, pos)?;
        if kw != "service" {
            return Err(parse_err(line, format!("unknown top-level block '{}'", kw)));
        }
        let name = match peek_kind(tokens, *pos) {
            Some(TokenKind::Word(_)) => expect_word(tokens, pos)?.0,
            _ => return Err(parse_err(line, "service requires a name")),
        };
        skip_newlines(tokens, pos);
        expect_open_brace(tokens, pos)?;
        match name.as_str() {
            "bgp" => {
                let body = language_bgp::parse_bgp_body(tokens, pos)?;
                root.services.push(Service::Bgp(body));
            }
            other => {
                return Err(parse_err(line, format!("unknown service '{}'", other)));
            }
        }
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let root = parse("").unwrap();
        assert!(root.services.is_empty());

        let root = parse("  \n\n  ").unwrap();
        assert!(root.services.is_empty());

        let root = parse("# just comments\n# nothing else").unwrap();
        assert!(root.services.is_empty());
    }

    #[test]
    fn test_parse_unknown_service_errors() {
        let err = parse("service ospf { router-id 1.1.1.1 }").unwrap_err();
        assert!(err.message.contains("unknown service 'ospf'"));
    }

    #[test]
    fn test_parse_inline_block() {
        let input = "service bgp { asn 65001\nrouter-id 1.1.1.1 }";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert!(body
            .settings
            .contains(&crate::language_bgp::Setting::Asn(65001)));
    }

    #[test]
    fn test_parse_comments() {
        let input = "\
# Top-level comment
service bgp {
  asn 65001  # inline comment
  # full line comment
  router-id 1.1.1.1
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert!(body
            .settings
            .contains(&crate::language_bgp::Setting::Asn(65001)));
        assert!(body
            .settings
            .contains(&crate::language_bgp::Setting::RouterId(
                "1.1.1.1".parse().unwrap()
            )));
    }

    #[test]
    fn test_parse_errors() {
        let cases = vec![
            ("service bgp {", "unexpected end of input"),
            ("}", "unexpected '}'"),
            ("{", "unexpected '{'"),
            ("service {", "service requires a name"),
            ("hostname router01", "unknown top-level block 'hostname'"),
        ];

        for (input, expected_msg) in cases {
            let err = parse(input).unwrap_err();
            assert!(
                err.message.contains(expected_msg),
                "for {:?}: expected {:?} in {:?}",
                input,
                expected_msg,
                err.message
            );
        }
    }

    #[test]
    fn test_peek_kind() {
        let tokens = tokenize("foo { }");
        assert!(matches!(peek_kind(&tokens, 0), Some(TokenKind::Word(w)) if w == "foo"));
        assert!(matches!(peek_kind(&tokens, 1), Some(TokenKind::OpenBrace)));
        assert!(matches!(peek_kind(&tokens, 2), Some(TokenKind::CloseBrace)));
        assert!(matches!(peek_kind(&tokens, 3), Some(TokenKind::Newline)));
        assert_eq!(peek_kind(&tokens, 99), None);
    }

    #[test]
    fn test_expect_word() {
        let tokens = tokenize("foo");
        let mut pos = 0;
        let (word, line) = expect_word(&tokens, &mut pos).unwrap();
        assert_eq!(word, "foo");
        assert_eq!(line, 1);
        assert_eq!(pos, 1, "should advance past consumed word");

        for input in &["{", "}", "", "\n"] {
            let tokens = tokenize(input);
            let mut pos = 0;
            assert!(
                expect_word(&tokens, &mut pos).is_err(),
                "expected error for {:?}",
                input
            );
            assert_eq!(pos, 0, "pos must not advance on error for {:?}", input);
        }
    }

    #[test]
    fn test_take_word() {
        let tokens = tokenize("foo");
        let mut pos = 0;
        assert_eq!(take_word(&tokens, &mut pos), Some("foo".to_string()));
        assert_eq!(pos, 1);

        for input in &["{", "}", "", "\n"] {
            let tokens = tokenize(input);
            let mut pos = 0;
            assert_eq!(
                take_word(&tokens, &mut pos),
                None,
                "expected None for {:?}",
                input
            );
            assert_eq!(pos, 0, "pos must not advance for {:?}", input);
        }
    }

    #[test]
    fn test_skip_newlines() {
        let tokens = tokenize("\n\n\n");
        let mut pos = 0;
        skip_newlines(&tokens, &mut pos);
        assert_eq!(pos, 3);

        let tokens = tokenize("\n\nfoo");
        let mut pos = 0;
        skip_newlines(&tokens, &mut pos);
        assert_eq!(pos, 2, "should stop at first non-newline");

        let tokens = tokenize("foo");
        let mut pos = 0;
        skip_newlines(&tokens, &mut pos);
        assert_eq!(pos, 0, "no-op when no newlines");

        let tokens: Vec<Token> = vec![];
        let mut pos = 0;
        skip_newlines(&tokens, &mut pos);
        assert_eq!(pos, 0, "no-op on empty input");
    }

    #[test]
    fn test_expect_open_brace() {
        let tokens = tokenize("{");
        let mut pos = 0;
        expect_open_brace(&tokens, &mut pos).unwrap();
        assert_eq!(pos, 1);

        // Pure expect: does NOT skip leading newlines.
        let tokens = tokenize("\n{");
        let mut pos = 0;
        assert!(expect_open_brace(&tokens, &mut pos).is_err());
        assert_eq!(pos, 0);

        for input in &["}", "foo", ""] {
            let tokens = tokenize(input);
            let mut pos = 0;
            assert!(expect_open_brace(&tokens, &mut pos).is_err());
            assert_eq!(pos, 0);
        }
    }

    #[test]
    fn test_expect_close_brace() {
        let tokens = tokenize("}");
        let mut pos = 0;
        expect_close_brace(&tokens, &mut pos).unwrap();
        assert_eq!(pos, 1);

        for input in &["{", "foo", "", "\n"] {
            let tokens = tokenize(input);
            let mut pos = 0;
            assert!(expect_close_brace(&tokens, &mut pos).is_err());
            assert_eq!(pos, 0);
        }
    }

    #[test]
    fn test_finish_statement() {
        let tokens = tokenize("\n");
        let mut pos = 0;
        finish_statement(&tokens, &mut pos).unwrap();
        assert_eq!(pos, 1, "newline consumed");

        let tokens = tokenize("}");
        let mut pos = 0;
        finish_statement(&tokens, &mut pos).unwrap();
        assert_eq!(pos, 0, "close-brace not consumed — parent handles");

        let tokens: Vec<Token> = vec![];
        let mut pos = 0;
        finish_statement(&tokens, &mut pos).unwrap();
        assert_eq!(pos, 0, "EOF ok");

        let tokens = tokenize("trailing");
        let mut pos = 0;
        let err = finish_statement(&tokens, &mut pos).unwrap_err();
        assert!(err.message.contains("unexpected trailing token 'trailing'"));
        assert_eq!(pos, 0);

        let tokens = tokenize("{");
        let mut pos = 0;
        let err = finish_statement(&tokens, &mut pos).unwrap_err();
        assert!(err.message.contains("unexpected '{'"));
        assert_eq!(pos, 0);
    }
}
