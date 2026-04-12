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

/// Parse rogg config text into a typed AST.
pub fn parse(input: &str) -> Result<Root, ParseError> {
    let tokens = tokenize(input);
    let mut pos = 0;
    parse_root(&tokens, &mut pos)
}

fn parse_root(tokens: &[Token], pos: &mut usize) -> Result<Root, ParseError> {
    let mut root = Root::default();
    let mut words: Vec<String> = Vec::new();
    let mut start_line = 0;

    while *pos < tokens.len() {
        let token = &tokens[*pos];
        match &token.kind {
            TokenKind::Word(word) => {
                if words.is_empty() {
                    start_line = token.line;
                }
                words.push(word.clone());
                *pos += 1;
            }
            TokenKind::OpenBrace => {
                if words.is_empty() {
                    return Err(parse_err(token.line, "unexpected '{'"));
                }
                if words[0] != "service" {
                    return Err(parse_err(
                        start_line,
                        format!("unknown top-level block '{}'", words[0]),
                    ));
                }
                if words.len() < 2 {
                    return Err(parse_err(start_line, "service requires a name"));
                }
                if words[1] != "bgp" {
                    return Err(parse_err(
                        start_line,
                        format!("unknown service '{}'", words[1]),
                    ));
                }
                *pos += 1;
                let body = language_bgp::parse_bgp_body(tokens, pos)?;
                root.services.push(Service::Bgp(body));
                words.clear();
            }
            TokenKind::CloseBrace => {
                return Err(parse_err(token.line, "unexpected '}'"));
            }
            TokenKind::Newline => {
                if !words.is_empty() {
                    return Err(parse_err(
                        start_line,
                        format!("unexpected statement '{}' at root level", words.join(" ")),
                    ));
                }
                *pos += 1;
            }
        }
    }

    if !words.is_empty() {
        return Err(parse_err(
            start_line,
            format!("unexpected statement '{}' at root level", words.join(" ")),
        ));
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
            ("hostname router01", "unexpected statement"),
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
}
