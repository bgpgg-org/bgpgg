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

use bgpgg::bgp::msg::Message;
use bgpgg::bgp::msg_keepalive::KeepAliveMessage;
use bgpgg::bgp::msg_notification::{
    BgpError, MessageHeaderError, OpenMessageError, UpdateMessageError,
};
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::bgp::msg_update::UpdateMessage;
use bgpgg::bgp::utils::{IpNetwork, Ipv4Net};
use std::net::Ipv4Addr;

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

    let withdrawn_routes = vec![IpNetwork::V4(Ipv4Net {
        address: Ipv4Addr::new(10, 11, 12, 0),
        prefix_length: 24,
    })];
    let update = UpdateMessage::new_withdraw(withdrawn_routes);
    let mut msg = update.serialize();

    // Corrupt Total Path Attribute Length field (bytes 25-26) to 100
    // Withdrawn Routes Length (4) + Total Attribute Length (100) + 23 = 127 > 27 (message length)
    msg[25] = 0x00;
    msg[26] = 0x64;

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

    use bgpgg::bgp::msg_update::Origin;

    let update = UpdateMessage::new(
        Origin::IGP,
        vec![],
        Ipv4Addr::new(10, 0, 0, 1),
        vec![],
        None,
        None,
        false,
    );
    let mut msg = update.serialize();

    // Corrupt ORIGIN attribute flags byte (first path attribute after total attr length)
    // Position: 19 (header) + 2 (withdrawn len) + 2 (total attr len) = 23
    msg[23] = 0xC0; // Optional + Transitive (WRONG for ORIGIN)

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError)
    );
    assert_eq!(&notif.data()[0..3], &[0xC0, 1, 1]);
}

#[tokio::test]
async fn test_update_attribute_flags_error_origin_partial_bit() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    use bgpgg::bgp::msg_update::Origin;

    let update = UpdateMessage::new(
        Origin::IGP,
        vec![],
        Ipv4Addr::new(10, 0, 0, 1),
        vec![],
        None,
        None,
        false,
    );
    let mut msg = update.serialize();

    msg[23] = 0x60; // Transitive + Partial (WRONG for ORIGIN)

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError)
    );
    assert_eq!(&notif.data()[0..3], &[0x60, 1, 1]);
}

#[tokio::test]
async fn test_update_attribute_flags_error_med_missing_optional_bit() {
    let server = start_test_server(65001, Ipv4Addr::new(1, 1, 1, 1), Some(300), "127.0.0.1").await;
    let mut peer = FakePeer::new(65002, Ipv4Addr::new(2, 2, 2, 2), 300, &server).await;

    use bgpgg::bgp::msg_update::Origin;

    let update = UpdateMessage::new(
        Origin::IGP,
        vec![],
        Ipv4Addr::new(10, 0, 0, 1),
        vec![],
        None,
        Some(100),
        false,
    );
    let mut msg = update.serialize();

    // MED is the 4th attribute (after ORIGIN, AS_PATH, NEXT_HOP)
    // ORIGIN: flags(1) + type(1) + len(1) + value(1) = 4 bytes
    // AS_PATH: flags(1) + type(1) + len(1) + value(0) = 3 bytes
    // NEXT_HOP: flags(1) + type(1) + len(1) + value(4) = 7 bytes
    // MED starts at: 23 + 4 + 3 + 7 = 37
    msg[37] = 0x40; // Transitive only (WRONG for MED)

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError)
    );
    assert_eq!(&notif.data()[0..3], &[0x40, 4, 4]);
}
