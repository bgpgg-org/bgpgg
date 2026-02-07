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

//! Tests for BGP UPDATE message error handling per RFC 4271 Section 6.3

mod utils;
pub use utils::*;

use bgpgg::bgp::msg_notification::{BgpError, UpdateMessageError};
use bgpgg::bgp::msg_update::{attr_flags, attr_type_code, Origin};
use bgpgg::config::Config;
use bgpgg::grpc::proto::BgpState;
use std::net::Ipv4Addr;

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
        let server = start_test_server_for_fake_peer(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
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
    let server = start_test_server_for_fake_peer(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
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
        let server = start_test_server_for_fake_peer(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
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
    let server = start_test_server_for_fake_peer(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
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
        let server = start_test_server_for_fake_peer(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
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
    let server = start_test_server_for_fake_peer(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
    ))
    .await;
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    // Build an unrecognized well-known attribute (type 9, OPTIONAL=0)
    let unrecognized_attr = build_attr_bytes(attr_flags::TRANSITIVE, 9, 2, &[0xaa, 0xbb]);
    let msg = build_raw_update(&[], &[&unrecognized_attr], &[], None);

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::UnrecognizedWellKnownAttribute)
    );
    assert_eq!(notif.data(), &[attr_flags::TRANSITIVE, 9, 2, 0xaa, 0xbb]);
}

#[tokio::test]
async fn test_update_invalid_origin_attribute() {
    let server = start_test_server_for_fake_peer(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
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
        let server = start_test_server_for_fake_peer(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
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
    let server = start_test_server_for_fake_peer(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
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
        let server = start_test_server_for_fake_peer(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
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
        let server = start_test_server_for_fake_peer(Config::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
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
async fn test_update_duplicate_attribute() {
    let server = start_test_server_for_fake_peer(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
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
    let server = start_test_server_for_fake_peer(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
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
        verify_peers(&server, vec![peer.to_peer(BgpState::Established, true)]).await,
        "Peer should remain established after valid UPDATE with no NLRI"
    );
}

#[tokio::test]
async fn test_update_multicast_nlri_ignored() {
    let server = start_test_server_for_fake_peer(Config::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
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
