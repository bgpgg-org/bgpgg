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
use bgpgg::bgp::msg_notification::{
    BgpError, MessageHeaderError, OpenMessageError, UpdateMessageError,
};
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::bgp::msg_update::{attr_flags, attr_type_code};
use std::net::Ipv4Addr;

// Build raw OPEN message with optional custom version, marker, length, and message type
fn build_raw_open(
    asn: u16,
    hold_time: u16,
    router_id: u32,
    version_override: Option<u8>,
    marker_override: Option<[u8; 16]>,
    length_override: Option<u16>,
    msg_type_override: Option<u8>,
) -> Vec<u8> {
    let version = version_override.unwrap_or(4);
    let marker = marker_override.unwrap_or(BGP_MARKER);
    let msg_type = msg_type_override.unwrap_or(MessageType::OPEN.as_u8());

    let mut body = Vec::new();
    body.push(version);
    body.extend_from_slice(&asn.to_be_bytes());
    body.extend_from_slice(&hold_time.to_be_bytes());
    body.extend_from_slice(&router_id.to_be_bytes());
    body.push(0); // Optional parameters length = 0

    build_raw_message(marker, length_override, msg_type, &body)
}

// Build raw KEEPALIVE message with optional custom length
fn build_raw_keepalive(length_override: Option<u16>) -> Vec<u8> {
    let body = Vec::new(); // KEEPALIVE has no body
    build_raw_message(
        BGP_MARKER,
        length_override,
        MessageType::KEEPALIVE.as_u8(),
        &body,
    )
}

// Build raw NOTIFICATION message with optional custom length
fn build_raw_notification(
    error_code: u8,
    error_subcode: u8,
    data: &[u8],
    length_override: Option<u16>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(error_code);
    body.push(error_subcode);
    body.extend_from_slice(data);

    build_raw_message(
        BGP_MARKER,
        length_override,
        MessageType::NOTIFICATION.as_u8(),
        &body,
    )
}

#[tokio::test]
async fn test_invalid_marker() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // Corrupt first byte of marker
    let mut corrupted_marker = BGP_MARKER;
    corrupted_marker[0] = 0x00;

    let msg = build_raw_open(
        65002,
        300,
        u32::from(Ipv4Addr::new(2, 2, 2, 2)),
        None,
        Some(corrupted_marker),
        None,
        None,
    );

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

    for (name, length) in test_cases {
        let server =
            start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
        let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

        let wrong_length = u16::from_be_bytes(length);
        let msg = build_raw_open(
            65002,
            300,
            u32::from(Ipv4Addr::new(2, 2, 2, 2)),
            None,
            None,
            Some(wrong_length),
            None,
        );

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            "Test case: {}",
            name
        );
        // RFC requires the erroneous Length field in data
        assert_eq!(notif.data(), &length, "Test case: {}", name);
    }
}

#[tokio::test]
async fn test_keepalive_wrong_length() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // KEEPALIVE must be exactly 19 bytes, make it 20
    let msg = build_raw_keepalive(Some(20));

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
    let msg = build_raw_notification(0, 0, &[], Some(20));

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
    let msg = build_raw_open(
        65002,
        300,
        u32::from(Ipv4Addr::new(2, 2, 2, 2)),
        None,
        None,
        None,
        Some(99),
    );

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

    let msg = build_raw_open(
        65002,
        300,
        u32::from(Ipv4Addr::new(2, 2, 2, 2)),
        Some(3),
        None,
        None,
        None,
    );

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
async fn test_update_missing_well_known_attribute() {
    let test_cases = vec![
        (
            "origin",
            vec![
                build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::AS_PATH, 0, &[]),
                build_attr_bytes(
                    attr_flags::TRANSITIVE,
                    attr_type_code::NEXT_HOP,
                    4,
                    &[10, 0, 0, 1],
                ),
            ],
            attr_type_code::ORIGIN,
        ),
        (
            "as_path",
            vec![
                build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 1, &[0]),
                build_attr_bytes(
                    attr_flags::TRANSITIVE,
                    attr_type_code::NEXT_HOP,
                    4,
                    &[10, 0, 0, 1],
                ),
            ],
            attr_type_code::AS_PATH,
        ),
        (
            "next_hop",
            vec![
                build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 1, &[0]),
                build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::AS_PATH, 0, &[]),
            ],
            attr_type_code::NEXT_HOP,
        ),
    ];

    for (name, attrs, expected_missing_type) in test_cases {
        let server =
            start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
        let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

        let nlri = &[24, 10, 11, 12]; // 10.11.12.0/24
        let msg = build_raw_update(
            &[],
            &attrs.iter().map(|a| a.as_slice()).collect::<Vec<_>>(),
            nlri,
            None,
        );

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::UpdateMessageError(UpdateMessageError::MissingWellKnownAttribute),
            "Test case: {}",
            name
        );
        assert_eq!(
            notif.data(),
            &[expected_missing_type],
            "Test case: {}",
            name
        );
    }
}

#[tokio::test]
async fn test_update_malformed_attribute_list() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // Withdrawn route: 10.11.12.0/24 (prefix length byte followed by prefix bytes)
    let withdrawn_data = &[24, 10, 11, 12];

    // Build UPDATE claiming 100 bytes of attributes but provide none
    // Withdrawn Routes Length (4) + Total Attribute Length (100) + 4 exceeds actual message length
    let msg = build_raw_update(withdrawn_data, &[], &[], Some(100));

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList)
    );
    assert_eq!(notif.data(), &[] as &[u8]);
}

#[tokio::test]
async fn test_update_attribute_flags_error_origin() {
    let test_cases = vec![
        (
            "optional_transitive",
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
        ),
        (
            "transitive_partial",
            attr_flags::TRANSITIVE | attr_flags::PARTIAL,
        ),
    ];

    for (name, wrong_flags) in test_cases {
        let server =
            start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
        let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

        let malformed_attr = build_attr_bytes(wrong_flags, attr_type_code::ORIGIN, 1, &[0]);
        let msg = build_raw_update(&[], &[&malformed_attr], &[], None);

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError),
            "Test case: {}",
            name
        );
        assert_eq!(
            &notif.data()[0..3],
            &[wrong_flags, attr_type_code::ORIGIN, 1],
            "Test case: {}",
            name
        );
    }
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
    let msg = build_raw_update(&[], &[&malformed_attr], &[], None);

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
        let msg = build_raw_update(&[], &[&malformed_attr], &[], None);

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

#[tokio::test]
async fn test_update_unrecognized_well_known_attribute() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    // Build an unrecognized well-known attribute (type 8, OPTIONAL=0)
    let unrecognized_attr = build_attr_bytes(attr_flags::TRANSITIVE, 8, 2, &[0xaa, 0xbb]);
    let msg = build_raw_update(&[], &[&unrecognized_attr], &[], None);

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::UnrecognizedWellKnownAttribute)
    );
    assert_eq!(notif.data(), &[attr_flags::TRANSITIVE, 8, 2, 0xaa, 0xbb]);
}

#[tokio::test]
async fn test_update_invalid_origin_attribute() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    let invalid_origin_attr =
        build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 1, &[3]);
    let as_path_attr = build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::AS_PATH, 0, &[]);
    let next_hop_attr = build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::NEXT_HOP,
        4,
        &[10, 0, 0, 1],
    );

    let nlri = &[24, 10, 11, 12];
    let msg = build_raw_update(
        &[],
        &[&invalid_origin_attr, &as_path_attr, &next_hop_attr],
        nlri,
        None,
    );

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::InvalidOriginAttribute)
    );
    assert_eq!(
        notif.data(),
        &[attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 1, 3]
    );
}
