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
    BgpError, CeaseSubcode, MessageHeaderError, OpenMessageError, UpdateMessageError,
};
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::bgp::msg_update::{attr_flags, attr_type_code, Origin};
use bgpgg::config::{Config, PeerConfig};
use bgpgg::grpc::proto::{
    AdminState, BgpState, MaxPrefixAction, MaxPrefixSetting, Origin as ProtoOrigin, Peer,
    SessionConfig,
};
use std::net::Ipv4Addr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

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
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

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
        let server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;
        let mut peer = FakePeer::connect(None, &server).await;
        peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
            .await;
        peer.handshake_keepalive().await;

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
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

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
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

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
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

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
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

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
        let server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;
        let mut peer = FakePeer::connect(None, &server).await;
        peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
            .await;
        peer.handshake_keepalive().await;

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
        let server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;
        let mut peer = FakePeer::connect(None, &server).await;
        peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
            .await;
        peer.handshake_keepalive().await;

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
                attr_as_path_empty(),
                attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            attr_type_code::ORIGIN,
        ),
        (
            "as_path",
            vec![attr_origin_igp(), attr_next_hop(Ipv4Addr::new(10, 0, 0, 1))],
            attr_type_code::AS_PATH,
        ),
        (
            "next_hop",
            vec![attr_origin_igp(), attr_as_path_empty()],
            attr_type_code::NEXT_HOP,
        ),
    ];

    for (name, attrs, expected_missing_type) in test_cases {
        let server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;
        let mut peer = FakePeer::connect(None, &server).await;
        peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
            .await;
        peer.handshake_keepalive().await;

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
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

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
        let server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;
        let mut peer = FakePeer::connect(None, &server).await;
        peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
            .await;
        peer.handshake_keepalive().await;

        let malformed_attr =
            build_attr_bytes(wrong_flags, attr_type_code::ORIGIN, 1, &[Origin::IGP as u8]);
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
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

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
    // Tests AttributeLengthError for well-known attributes.
    // Optional attributes (MED, AGGREGATOR) use OptionalAttributeError instead.
    let test_cases = vec![
        (
            "origin_wrong_length",
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::ORIGIN,
                2,
                &[Origin::IGP as u8],
            ), // WRONG: length=2, should be 1
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
    ];

    for (name, malformed_attr, expected_data_prefix) in test_cases {
        let server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;
        let mut peer = FakePeer::connect(None, &server).await;
        peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
            .await;
        peer.handshake_keepalive().await;

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
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

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
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    let invalid_origin_attr =
        build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 1, &[3]); // 3 is invalid (only 0, 1, 2 are valid)

    let nlri = &[24, 10, 11, 12];
    let msg = build_raw_update(
        &[],
        &[
            &invalid_origin_attr,
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
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

#[tokio::test]
async fn test_update_invalid_next_hop_attribute() {
    let test_cases = vec![
        ("0.0.0.0", [0x00, 0x00, 0x00, 0x00]),
        ("255.255.255.255", [0xff, 0xff, 0xff, 0xff]),
        ("224.0.0.1", [0xe0, 0x00, 0x00, 0x01]),
    ];

    for (name, ip_bytes) in test_cases {
        let server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;
        let mut peer = FakePeer::connect(None, &server).await;
        peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
            .await;
        peer.handshake_keepalive().await;

        let invalid_next_hop_attr = build_attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type_code::NEXT_HOP,
            4,
            &ip_bytes,
        );

        let nlri = &[24, 10, 11, 12];
        let msg = build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &attr_as_path_empty(),
                &invalid_next_hop_attr,
            ],
            nlri,
            None,
        );

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::UpdateMessageError(UpdateMessageError::InvalidNextHopAttribute),
            "Test case: {}",
            name
        );
        assert_eq!(
            notif.data(),
            &[
                attr_flags::TRANSITIVE,
                attr_type_code::NEXT_HOP,
                4,
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3]
            ],
            "Test case: {}",
            name
        );
    }
}

// RFC 4271 5.1.3 NEXT_HOP semantic validation tests

#[tokio::test]
async fn test_next_hop_is_local_address_rejected() {
    // Server bound to 127.0.0.1, FakePeer sends UPDATE with NEXT_HOP = 127.0.0.1
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    // Send UPDATE with NEXT_HOP = server's local address (127.0.0.1)
    let nlri = &[24, 10, 11, 12]; // 10.11.12.0/24
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(127, 0, 0, 1)), // Server's local addr
        ],
        nlri,
        None,
    );
    peer.send_raw(&msg).await;

    // Give server time to process
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Route should NOT be installed (NEXT_HOP = local address)
    let routes = server
        .client
        .get_routes()
        .await
        .expect("Failed to get routes");
    assert!(
        routes.is_empty(),
        "Route should be rejected when NEXT_HOP is local address"
    );
}

#[tokio::test]
async fn test_update_malformed_as_path() {
    let test_cases = vec![
        (
            "invalid_segment_type",
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::AS_PATH,
                4,
                &[0x00, 0x01, 0x00, 0x0a], // segment_type=0 (invalid), len=1, ASN=10
            ),
        ),
        (
            "truncated_asn_data",
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::AS_PATH,
                4,
                &[0x02, 0x02, 0x00, 0x0a], // AS_SEQUENCE, claims 2 ASNs but only 1 provided
            ),
        ),
        (
            "ebgp_first_as_mismatch",
            // Peer is AS 65002, but AS_PATH starts with 65003 (0xFE03)
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::AS_PATH,
                6,
                &[0x02, 0x02, 0xfe, 0x03, 0xfe, 0x04], // AS_SEQUENCE [65003, 65028]
            ),
        ),
    ];

    for (name, malformed_as_path) in test_cases {
        let server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;
        let mut peer = FakePeer::connect(None, &server).await;
        peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
            .await;
        peer.handshake_keepalive().await;

        let nlri = &[24, 10, 11, 12];
        let msg = build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &malformed_as_path,
                &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            nlri,
            None,
        );

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
            "Test case: {}",
            name
        );
    }
}

#[tokio::test]
async fn test_update_optional_attribute_error() {
    let test_cases = vec![
        (
            "med_invalid_length",
            attr_flags::OPTIONAL,
            attr_type_code::MULTI_EXIT_DISC,
            3,
            vec![0x00, 0x00, 0x01],
        ),
        (
            "aggregator_invalid_length",
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type_code::AGGREGATOR,
            4,
            vec![0x00, 0x01, 0x01, 0x01],
        ),
    ];

    for (name, flags, type_code, len, data) in test_cases {
        let server = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;
        let mut peer = FakePeer::connect(None, &server).await;
        peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
            .await;
        peer.handshake_keepalive().await;

        let invalid_attr = build_attr_bytes(flags, type_code, len, &data);
        let nlri = &[24, 10, 11, 12];
        let msg = build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &attr_as_path_empty(),
                &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
                &invalid_attr,
            ],
            nlri,
            None,
        );

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            "Test case: {}",
            name
        );
        let mut expected_data = vec![flags, type_code, len];
        expected_data.extend(&data);
        assert_eq!(notif.data(), &expected_data, "Test case: {}", name);
    }
}

#[tokio::test]
async fn test_hold_timer_expiry() {
    let hold_timer_secs: u16 = 3;
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        hold_timer_secs as u64,
        true,
    ))
    .await;

    // FakePeer connects with same hold time but won't send keepalives
    let mut fake_peer = FakePeer::connect(None, &server).await;
    fake_peer
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), hold_timer_secs)
        .await;
    fake_peer.handshake_keepalive().await;

    // Verify peer is established
    poll_until(
        || async {
            let peers = server.client.get_peers().await.unwrap_or_default();
            peers
                .iter()
                .any(|p| p.state == BgpState::Established as i32)
        },
        "Timeout waiting for peer to establish",
    )
    .await;

    // FakePeer does nothing - server should detect hold timer expiry and send NOTIFICATION
    let notif = fake_peer.read_notification().await;
    assert_eq!(*notif.error(), BgpError::HoldTimerExpired);

    // Server should have removed the peer
    poll_until(
        || async { verify_peers(&server, vec![]).await },
        "Timeout waiting for peer removal after hold timer expiry",
    )
    .await;
}

#[tokio::test]
async fn test_update_duplicate_attribute() {
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    // Send UPDATE with two ORIGIN attributes (duplicate)
    let msg = build_raw_update(&[], &[&attr_origin_igp(), &attr_origin_igp()], &[], None);

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList)
    );
}

#[tokio::test]
async fn test_update_no_nlri_valid() {
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    // UPDATE with valid attributes but no NLRI
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        &[], // No NLRI
        None,
    );

    peer.send_raw(&msg).await;

    // Wait for UPDATE to be received
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    // Peer should still be established (no NOTIFICATION sent)
    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established, false)]).await,
        "Peer should remain established after valid UPDATE with no NLRI"
    );
}

#[tokio::test]
async fn test_update_multicast_nlri_ignored() {
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    // Send UPDATE with multicast NLRI (224.0.0.0/24)
    let multicast_nlri = &[24, 224, 0, 0];
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        multicast_nlri,
        None,
    );

    peer.send_raw(&msg).await;

    // Wait for UPDATE to be received
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    // Multicast prefix should be silently ignored, not installed
    let routes = server
        .client
        .get_routes()
        .await
        .expect("Failed to get routes");
    assert!(routes.is_empty(), "Multicast NLRI should be ignored");
}

// FSM Error Tests (RFC 4271 Section 6.6)

#[tokio::test]
async fn test_fsm_error_update_in_openconfirm() {
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;

    // Connect and exchange OPEN only - server ends up in OpenConfirm
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;

    // Send UPDATE while server is in OpenConfirm (should trigger FSM Error)
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        &[24, 10, 11, 12], // 10.11.12.0/24
        None,
    );
    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(notif.error(), &BgpError::FiniteStateMachineError);
}

// Cease NOTIFICATION Tests (RFC 4271 Section 6.7)

#[tokio::test]
async fn test_max_prefix_limit() {
    // (name, action, allow_automatic_stop, expect_disconnect)
    let test_cases = vec![
        // Terminate with allow_automatic_stop=true: disconnects
        ("terminate", MaxPrefixAction::Terminate as i32, None, true),
        // Discard: stays connected
        ("discard", MaxPrefixAction::Discard as i32, None, false),
        // Terminate with allow_automatic_stop=false: stays connected
        (
            "terminate_no_auto_stop",
            MaxPrefixAction::Terminate as i32,
            Some(false),
            false,
        ),
    ];

    for (name, action, allow_automatic_stop, expect_disconnect) in test_cases {
        // Server1: will inject routes
        let mut server1 = start_test_server(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
            true,
        ))
        .await;

        // Server2: will receive routes with max_prefix limit
        let mut server2 = start_test_server(Config::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            300,
            true,
        ))
        .await;

        // Server2 connects to Server1 with max_prefix limit of 2
        server2
            .client
            .add_peer(
                format!("127.0.0.1:{}", server1.bgp_port),
                Some(SessionConfig {
                    max_prefix: Some(MaxPrefixSetting { limit: 2, action }),
                    allow_automatic_stop,
                    ..Default::default()
                }),
            )
            .await
            .expect("Failed to add peer");

        // Wait for peering to establish
        poll_until(
            || async {
                verify_peers(&server2, vec![server1.to_peer(BgpState::Established, true)]).await
            },
            "Timeout waiting for peering",
        )
        .await;

        // Server1 adds 3 routes (exceeds limit of 2)
        for i in 0..3 {
            server1
                .client
                .add_route(
                    format!("10.{}.0.0/24", i),
                    "1.1.1.1".to_string(),
                    ProtoOrigin::Igp,
                    vec![],
                    None,
                    None,
                    false,
                )
                .await
                .expect("Failed to add route");
        }

        if expect_disconnect {
            // Terminate: session should be closed (CEASE sent), configured peer stays in Idle
            // AdminState is set to PrefixLimitReached which maps to admin_down=true
            poll_until(
                || async {
                    verify_peers(
                        &server2,
                        vec![Peer {
                            address: server1.address.clone(),
                            asn: server1.asn as u32,
                            state: BgpState::Idle.into(),
                            admin_state: AdminState::PrefixLimitExceeded.into(),
                            configured: true,
                        }],
                    )
                    .await
                },
                &format!("Test case {}: timeout waiting for peer to go Idle", name),
            )
            .await;
        } else {
            // Discard: peer stays connected, routes are limited
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            assert!(
                verify_peers(&server2, vec![server1.to_peer(BgpState::Established, true)]).await,
                "Test case {}: peer should remain established",
                name
            );

            // Verify no CEASE notification was sent
            poll_peer_stats(
                &server2,
                &server1.address,
                ExpectedStats {
                    notification_sent: Some(0),
                    ..Default::default()
                },
            )
            .await;

            let routes = server2
                .client
                .get_routes()
                .await
                .expect("Failed to get routes");
            assert!(
                routes.len() <= 2,
                "Test case {}: should have at most 2 routes, got {}",
                name,
                routes.len()
            );
        }
    }
}

#[tokio::test]
async fn test_remove_peer_sends_cease_notification() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    poll_until(
        || async { verify_peers(&server, vec![peer.to_peer(BgpState::Established, false)]).await },
        "Timeout waiting for peer to establish",
    )
    .await;

    server
        .client
        .remove_peer(peer.address.clone())
        .await
        .expect("Failed to remove peer");

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::Cease(CeaseSubcode::PeerDeconfigured)
    );
}

#[tokio::test]
async fn test_disable_peer_sends_admin_shutdown() {
    let mut server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    poll_until(
        || async { verify_peers(&server, vec![peer.to_peer(BgpState::Established, false)]).await },
        "Timeout waiting for peer to establish",
    )
    .await;

    server
        .client
        .disable_peer(peer.address.clone())
        .await
        .expect("Failed to disable peer");

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::Cease(CeaseSubcode::AdministrativeShutdown)
    );
}

/// RFC 4271 Section 6.8: Connection Collision Detection
/// local < remote -> close existing, accept new
#[tokio::test]
async fn test_collision_local_lower_bgp_id() {
    // Server BGP ID 1.1.1.1 (lower than peer's 2.2.2.2)
    let server = start_test_server(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
        true,
    ))
    .await;

    // Peer 1: connect and reach OpenConfirm
    let mut peer1 = FakePeer::connect(Some("127.0.0.3"), &server).await;
    peer1
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;

    poll_until(
        || async { verify_peers(&server, vec![peer1.to_peer(BgpState::OpenConfirm, false)]).await },
        "Timeout waiting for peer1 to reach OpenConfirm",
    )
    .await;

    // Peer 2: collision - since local < remote, existing (peer1) closed, new (peer2) wins
    let mut peer2 = FakePeer::connect(Some("127.0.0.3"), &server).await;
    peer2
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;

    // Verify peer1 received NOTIFICATION with ConnectionCollisionResolution
    let notif = peer1.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::Cease(CeaseSubcode::ConnectionCollisionResolution),
        "peer1 should receive ConnectionCollisionResolution"
    );

    // Complete handshake on peer2 (the winner)
    peer2.send_keepalive().await;

    // Verify peer2 is Established (same address as peer1 since same IP)
    poll_until(
        || async { verify_peers(&server, vec![peer2.to_peer(BgpState::Established, false)]).await },
        "Timeout waiting for peer2 to reach Established",
    )
    .await;
}

/// RFC 4271 Section 6.8: Connection Collision Detection in OpenConfirm state
#[tokio::test]
async fn test_collision_openconfirm() {
    let test_cases = vec![
        // (server_bgp_id, peer_bgp_id, existing_kept)
        (Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(1, 1, 1, 1), true), // local >= remote -> keep existing
        (Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(3, 3, 3, 3), false), // local < remote -> accept new
    ];

    for (server_bgp_id, peer_bgp_id, existing_kept) in test_cases {
        let server =
            start_test_server(Config::new(65001, "127.0.0.1:0", server_bgp_id, 300, true)).await;

        // Peer 1: connect and reach OpenConfirm
        let mut peer1 = FakePeer::connect(Some("127.0.0.3"), &server).await;
        peer1.handshake_open(65002, peer_bgp_id, 300).await;

        poll_until(
            || async {
                verify_peers(&server, vec![peer1.to_peer(BgpState::OpenConfirm, false)]).await
            },
            "Timeout waiting for peer1 to reach OpenConfirm",
        )
        .await;

        // Peer 2: collision from same IP
        let mut peer2 = FakePeer::connect(Some("127.0.0.3"), &server).await;

        if existing_kept {
            // local >= remote -> existing kept, new rejected
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            assert!(
                verify_peers(&server, vec![peer1.to_peer(BgpState::OpenConfirm, false)]).await,
                "peer1 should still be in OpenConfirm"
            );
        } else {
            // local < remote -> existing closed, new accepted
            // peer1 receives NOTIFICATION
            let notif = peer1.read_notification().await;
            assert_eq!(
                notif.error(),
                &BgpError::Cease(CeaseSubcode::ConnectionCollisionResolution)
            );

            // Complete handshake on peer2
            peer2.read_open().await;
            peer2.send_open(65002, peer_bgp_id, 300).await;
            peer2.read_keepalive().await;
            peer2.send_keepalive().await;

            // Verify peer2 reaches Established
            poll_until(
                || async {
                    let peers = server.client.get_peers().await.unwrap();
                    peers.len() == 1 && peers[0].state == BgpState::Established as i32
                },
                "Timeout waiting for peer2 to reach Established",
            )
            .await;
        }
    }
}

/// RFC 4271 8.1.1 Option 5: CollisionDetectEstablishedState
/// By default (false), collision detection is ignored in Established state.
#[tokio::test]
async fn test_collision_ignored_in_established() {
    // server1 and server2 peer and reach Established
    let (server1, server2) = setup_two_peered_servers(None).await;

    // server3 on same IP as server2 tries to connect to server1 - triggers collision
    let mut config3 = Config::new(65003, "127.0.0.2:0", Ipv4Addr::new(3, 3, 3, 3), 90, true);
    config3.peers.push(PeerConfig {
        address: format!("{}:{}", server1.address, server1.bgp_port),
        ..Default::default()
    });
    let _server3 = start_test_server(config3).await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Original peer should still be Established (collision ignored by default)
    // server1 connected to server2 (configured from server1's view)
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established, true)],).await);
}

/// RFC 4271 6.8: Deferred collision detection for outgoing connections
/// When server has outgoing in OpenSent (no BGP ID), incoming is deferred until OPEN received.
#[tokio::test]
async fn test_collision_deferred() {
    let test_cases = vec![
        // (server_bgp_id, peer_bgp_id, outgoing_wins)
        (Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(1, 1, 1, 1), true), // outgoing wins
        (Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(3, 3, 3, 3), false), // incoming wins
    ];

    for (server_bgp_id, peer_bgp_id, outgoing_wins) in test_cases {
        // Peer listens at 127.0.0.3, server will connect to it
        let listener = TcpListener::bind("127.0.0.3:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let mut config = Config::new(65001, "127.0.0.1:0", server_bgp_id, 300, true);
        config.peers.push(PeerConfig {
            address: listener_addr.to_string(),
            ..Default::default()
        });
        let server = start_test_server(config).await;

        // Accept server's outbound connection (server sends OPEN, but we don't read it yet)
        let mut peer = FakePeer::accept(&listener, 65002).await;

        // Server is in OpenSent (sent OPEN, waiting for response)
        poll_until(
            || async {
                let peers = server.client.get_peers().await.unwrap();
                peers.len() == 1 && peers[0].state == BgpState::OpenSent as i32
            },
            "Timeout waiting for OpenSent",
        )
        .await;

        // Same peer initiates connection to server - triggers deferred collision (no BGP ID yet)
        let mut incoming_stream = peer.connect_to(&server).await;

        // Now exchange OPENs on first connection - server learns BGP ID and resolves collision
        peer.read_open().await;
        peer.send_open(65002, peer_bgp_id, 300).await;

        if outgoing_wins {
            // Complete handshake on outgoing connection
            peer.send_keepalive().await;
            peer.read_keepalive().await;

            // Outgoing wins, collision dropped, session reaches Established
            poll_until(
                || async {
                    let peers = server.client.get_peers().await.unwrap();
                    peers.len() == 1 && peers[0].state == BgpState::Established as i32
                },
                "Timeout waiting for Established (outgoing wins)",
            )
            .await;

            drop(incoming_stream);
        } else {
            // Incoming wins - server closes outgoing (peer gets NOTIFICATION), switches to incoming
            // Complete handshake on incoming connection
            // Wrap incoming_stream in FakePeer to use helper methods
            let mut incoming_peer = FakePeer {
                stream: incoming_stream,
                address: "127.0.0.3".to_string(),
                asn: 65002,
            };

            incoming_peer.read_open().await;
            incoming_peer.send_open(65002, peer_bgp_id, 300).await;
            incoming_peer.read_keepalive().await;
            incoming_peer.send_keepalive().await;

            incoming_stream = incoming_peer.stream;

            // Incoming wins, session reaches Established
            poll_until(
                || async {
                    let peers = server.client.get_peers().await.unwrap();
                    peers.len() == 1 && peers[0].state == BgpState::Established as i32
                },
                "Timeout waiting for Established (incoming wins)",
            )
            .await;

            drop(incoming_stream);
        }
    }
}

/// RFC 4271 8.1.1: SendNOTIFICATIONwithoutOPEN
#[tokio::test]
async fn test_send_notification_without_open() {
    for flag in [true, false] {
        let mut config = Config::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300, false);
        config.peers.push(bgpgg::config::PeerConfig {
            address: "127.0.0.1:179".to_string(),
            passive_mode: true,
            send_notification_without_open: flag,
            delay_open_time_secs: Some(60), // Delay OPEN so we can send invalid msg first
            ..Default::default()
        });
        let server = start_test_server(config).await;

        let mut peer = FakePeer::connect(None, &server).await;

        // Send invalid marker before OPEN is sent (delay_open delays it)
        let mut corrupted_marker = BGP_MARKER;
        corrupted_marker[0] = 0x00;
        let msg = build_raw_open(
            65002,
            300,
            0x02020202,
            None,
            Some(corrupted_marker),
            None,
            None,
        );
        peer.send_raw(&msg).await;

        let mut buf = [0u8; 1];
        let result = timeout(Duration::from_millis(100), peer.stream.read(&mut buf)).await;

        if flag {
            assert!(result.is_ok(), "flag={}: should receive notification", flag);
        } else {
            match result {
                Ok(Ok(0)) | Err(_) => {} // EOF or timeout - no notification sent
                other => panic!("flag={}: unexpected {:?}", flag, other),
            }
        }
    }
}
