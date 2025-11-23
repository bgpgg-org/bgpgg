// Copyright 2025 bgpgg Authors
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

//! Tests for BGP message header error handling per RFC 4271 Section 6.1

mod common;
pub use common::*;

use bgpgg::bgp::msg::{Message, MessageType, BGP_MARKER};
use bgpgg::bgp::msg_keepalive::KeepAliveMessage;
use bgpgg::bgp::msg_notification::{
    BgpError, MessageHeaderError, OpenMessageError, UpdateMessageError,
};
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::bgp::msg_update::{attr_flags, attr_type_code};
use std::net::Ipv4Addr;

// Helper to build raw attribute bytes with intentionally wrong length
fn build_attr_bytes(flags: u8, attr_type: u8, length: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![flags, attr_type, length];
    bytes.extend_from_slice(value);
    bytes
}

// Internal helper that both functions use
fn build_update_internal(
    withdrawn: &[u8],
    attrs: &[&[u8]],
    nlri: &[u8],
    total_attr_len_override: Option<u16>,
) -> Vec<u8> {
    let mut msg = BGP_MARKER.to_vec();
    msg.extend_from_slice(&[0x00, 0x00]); // Placeholder for length
    msg.push(MessageType::UPDATE.as_u8());

    // Withdrawn routes
    msg.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    msg.extend_from_slice(withdrawn);

    // Total path attributes length - use override if provided, else calculate correctly
    let total_attr_len = total_attr_len_override
        .unwrap_or_else(|| attrs.iter().map(|a| a.len()).sum::<usize>() as u16);
    msg.extend_from_slice(&total_attr_len.to_be_bytes());

    // Path attributes
    for attr in attrs {
        msg.extend_from_slice(attr);
    }

    // NLRI
    msg.extend_from_slice(nlri);

    // Fix the length field
    let len = msg.len() as u16;
    msg[16] = (len >> 8) as u8;
    msg[17] = (len & 0xff) as u8;

    msg
}

// Build UPDATE message from raw attribute bytes (correct length)
fn build_update_from_raw_attrs(withdrawn: &[u8], attrs: &[&[u8]], nlri: &[u8]) -> Vec<u8> {
    build_update_internal(withdrawn, attrs, nlri, None)
}

// Build UPDATE with intentionally wrong total attribute length
fn build_update_with_wrong_attr_length(
    withdrawn: &[u8],
    attrs: &[&[u8]],
    nlri: &[u8],
    wrong_total_attr_len: u16,
) -> Vec<u8> {
    build_update_internal(withdrawn, attrs, nlri, Some(wrong_total_attr_len))
}

#[tokio::test]
async fn test_invalid_marker() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // Corrupt first byte of marker
    let mut msg = OpenMessage::new(65002, 300, u32::from(Ipv4Addr::new(2, 2, 2, 2))).serialize();
    msg[0] = 0x00;

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized)
    );
}

#[tokio::test]
async fn test_bad_message_length() {
    let test_cases = vec![
        ("too small", [0x00, 0x12]), // 18: less than minimum (19)
        ("too large", [0x10, 0x01]), // 4097: greater than maximum (4096)
    ];

    for (name, expected_data) in test_cases {
        let server =
            start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
        let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

        let mut msg =
            OpenMessage::new(65002, 300, u32::from(Ipv4Addr::new(2, 2, 2, 2))).serialize();

        // Set the length field
        msg[16] = expected_data[0];
        msg[17] = expected_data[1];

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            "Test case: {}",
            name
        );
        // RFC requires the erroneous Length field in data
        assert_eq!(notif.data(), &expected_data, "Test case: {}", name);
    }
}

#[tokio::test]
async fn test_keepalive_wrong_length() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // KEEPALIVE must be exactly 19 bytes, make it 20
    let mut msg = KeepAliveMessage {}.serialize();
    msg[16] = 0x00;
    msg[17] = 0x14; // 20

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength)
    );
    // RFC requires the erroneous Length field in data
    assert_eq!(notif.data(), &[0x00, 0x14]);
}

#[tokio::test]
async fn test_notification_length_too_small() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // NOTIFICATION minimum length is 21 (19 header + 2 for error code/subcode)
    // Create a message with type=3 (NOTIFICATION) and length=20
    let mut msg = vec![0xff; 16]; // Marker
    msg.extend_from_slice(&[0x00, 0x14]); // Length = 20 (too small)
    msg.push(3); // Type = NOTIFICATION

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength)
    );
    assert_eq!(notif.data(), &[0x00, 0x14]);
}

#[tokio::test]
async fn test_invalid_message_type() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // Create message with invalid type (99)
    let mut msg = OpenMessage::new(65002, 300, u32::from(Ipv4Addr::new(2, 2, 2, 2))).serialize();
    msg[18] = 99; // Invalid type

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::MessageHeaderError(MessageHeaderError::BadMessageType)
    );
    // RFC requires the erroneous Type field in data
    assert_eq!(notif.data(), &[99]);
}

// OPEN Message Error Tests (RFC 4271 Section 6.2)

#[tokio::test]
async fn test_open_unsupported_version() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    let mut msg = OpenMessage::new(65002, 300, u32::from(Ipv4Addr::new(2, 2, 2, 2))).serialize();
    msg[19] = 0x03; // Version 3 (body starts at byte 19)

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber)
    );
    // RFC 4271: Data field contains largest locally-supported version
    assert_eq!(notif.data(), &[0x00, 0x04]);
}

#[tokio::test]
async fn test_open_unacceptable_hold_time() {
    let test_cases = vec![1, 2];

    for hold_time in test_cases {
        let server =
            start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
        let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

        let msg =
            OpenMessage::new(65002, hold_time, u32::from(Ipv4Addr::new(2, 2, 2, 2))).serialize();

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::OpenMessageError(OpenMessageError::UnacceptedHoldTime),
            "Failed for hold_time={}",
            hold_time
        );
        assert_eq!(
            notif.data(),
            &[] as &[u8],
            "Failed for hold_time={}",
            hold_time
        );
    }
}

#[tokio::test]
async fn test_open_bad_bgp_identifier() {
    let test_cases = vec![
        ("zero", 0x00000000),      // 0.0.0.0
        ("broadcast", 0xFFFFFFFF), // 255.255.255.255
        ("multicast", 0xE0000001), // 224.0.0.1
    ];

    for (name, bgp_id) in test_cases {
        let server =
            start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
        let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

        let msg = OpenMessage::new(65002, 300, bgp_id).serialize();

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::OpenMessageError(OpenMessageError::BadBgpIdentifier),
            "Failed for case: {}",
            name
        );
        assert_eq!(notif.data(), &[] as &[u8], "Failed for case: {}", name);
    }
}

// UPDATE Message Error Tests (RFC 4271 Section 6.3)

#[tokio::test]
async fn test_update_malformed_attribute_list() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // Withdrawn route: 10.11.12.0/24 (prefix length byte followed by prefix bytes)
    let withdrawn_data = &[24, 10, 11, 12];

    // Build UPDATE claiming 100 bytes of attributes but provide none
    // Withdrawn Routes Length (4) + Total Attribute Length (100) + 4 exceeds actual message length
    let msg = build_update_with_wrong_attr_length(withdrawn_data, &[], &[], 100);

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList)
    );
    assert_eq!(notif.data(), &[] as &[u8]);
}

#[tokio::test]
async fn test_update_attribute_flags_error_origin_wrong_optional_bit() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // Build ORIGIN attribute with WRONG flags (Optional + Transitive instead of just Transitive)
    let wrong_flags = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
    let malformed_attr = build_attr_bytes(wrong_flags, attr_type_code::ORIGIN, 1, &[0]);
    let msg = build_update_from_raw_attrs(&[], &[&malformed_attr], &[]);

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError)
    );
    assert_eq!(
        &notif.data()[0..3],
        &[wrong_flags, attr_type_code::ORIGIN, 1]
    );
}

#[tokio::test]
async fn test_update_attribute_flags_error_origin_partial_bit() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // Build ORIGIN attribute with WRONG flags (Transitive + Partial)
    let wrong_flags = attr_flags::TRANSITIVE | attr_flags::PARTIAL;
    let malformed_attr = build_attr_bytes(wrong_flags, attr_type_code::ORIGIN, 1, &[0]);
    let msg = build_update_from_raw_attrs(&[], &[&malformed_attr], &[]);

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError)
    );
    assert_eq!(
        &notif.data()[0..3],
        &[wrong_flags, attr_type_code::ORIGIN, 1]
    );
}

#[tokio::test]
async fn test_update_attribute_flags_error_med_missing_optional_bit() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // Build MED attribute with WRONG flags (missing OPTIONAL bit)
    let wrong_flags = attr_flags::TRANSITIVE; // Should have OPTIONAL too
    let malformed_attr = build_attr_bytes(
        wrong_flags,
        attr_type_code::MULTI_EXIT_DISC,
        4,
        &[0, 0, 0, 100],
    );
    let msg = build_update_from_raw_attrs(&[], &[&malformed_attr], &[]);

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError)
    );
    assert_eq!(
        &notif.data()[0..3],
        &[wrong_flags, attr_type_code::MULTI_EXIT_DISC, 4]
    );
}

#[tokio::test]
async fn test_update_attribute_length_error() {
    let test_cases = vec![
        (
            "origin_wrong_length",
            build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 2, &[0]), // WRONG: length=2, should be 1
            vec![attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 2],
        ),
        (
            "next_hop_wrong_length",
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::NEXT_HOP,
                5,
                &[10, 0, 0, 1, 0],
            ), // WRONG: length=5, should be 4
            vec![attr_flags::TRANSITIVE, attr_type_code::NEXT_HOP, 5],
        ),
        (
            "med_wrong_length",
            build_attr_bytes(
                attr_flags::OPTIONAL,
                attr_type_code::MULTI_EXIT_DISC,
                5,
                &[0, 0, 0, 0, 0],
            ), // WRONG: length=5, should be 4
            vec![attr_flags::OPTIONAL, attr_type_code::MULTI_EXIT_DISC, 5],
        ),
        (
            "local_pref_wrong_length",
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::LOCAL_PREF,
                3,
                &[0, 0, 0],
            ), // WRONG: length=3, should be 4
            vec![attr_flags::TRANSITIVE, attr_type_code::LOCAL_PREF, 3],
        ),
        (
            "atomic_aggregate_wrong_length",
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::ATOMIC_AGGREGATE,
                1,
                &[0],
            ), // WRONG: length=1, should be 0
            vec![attr_flags::TRANSITIVE, attr_type_code::ATOMIC_AGGREGATE, 1],
        ),
        (
            "aggregator_wrong_length",
            build_attr_bytes(
                attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                attr_type_code::AGGREGATOR,
                5,
                &[0, 10, 10, 0, 0],
            ), // WRONG: length=5, should be 6
            vec![
                attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                attr_type_code::AGGREGATOR,
                5,
            ],
        ),
    ];

    for (name, malformed_attr, expected_data_prefix) in test_cases {
        let server =
            start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
        let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

        // Build UPDATE with single malformed attribute (no alignment issues!)
        let msg = build_update_from_raw_attrs(&[], &[&malformed_attr], &[]);

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError),
            "Test case: {}",
            name
        );
        assert_eq!(
            &notif.data()[0..expected_data_prefix.len()],
            &expected_data_prefix[..],
            "Test case: {}",
            name
        );
    }
}
