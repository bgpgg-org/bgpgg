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

use crate::bgp::msg_notification::{BgpError, CeaseSubcode, UpdateMessageError};
use crate::bgp::msg_update::{NextHopAddr, UpdateMessage};
use crate::bgp::msg_update_types::PathAttrValue;
use crate::bgp::multiprotocol::AfiSafi;
use crate::config::MaxPrefixAction;
use crate::net::IpNetwork;
use crate::rib::{Path, RouteSource};
use crate::{info, warn};
use std::net::IpAddr;
use std::sync::Arc;

use super::{Peer, SessionType};

type UpdateResult = (Vec<IpNetwork>, Vec<(IpNetwork, Arc<Path>)>);

impl Peer {
    /// Validate AFI/SAFI is negotiated and not disabled.
    /// Returns true if validation passes, false if UPDATE should be ignored.
    fn validate_afi_safi(&mut self, afi_safi: AfiSafi) -> bool {
        // Check if AFI/SAFI is disabled
        if self.disabled_afi_safi.contains(&afi_safi) {
            warn!(&self.logger, "ignoring UPDATE for disabled AFI/SAFI",
                  "afi_safi" => format!("{}", afi_safi), "peer" => &self.addr);
            return false;
        }

        // Check if AFI/SAFI was negotiated
        if !self.negotiated_capabilities.supports_afi_safi(&afi_safi) {
            warn!(&self.logger, "received UPDATE for non-negotiated AFI/SAFI, disabling",
                  "afi_safi" => format!("{}", afi_safi), "peer" => &self.addr);

            // RFC 4760 Section 7: Delete all routes for this AFI/SAFI
            let deleted_count = self.rib_in.clear_afi_safi(afi_safi);
            warn!(&self.logger, "deleted all routes for AFI/SAFI due to error",
                  "afi_safi" => format!("{}", afi_safi),
                  "deleted_count" => deleted_count,
                  "peer" => &self.addr);

            // Mark AFI/SAFI as disabled for this session
            self.disabled_afi_safi.insert(afi_safi);

            return false;
        }

        true
    }

    /// Validate multiprotocol capabilities in UPDATE message.
    /// Returns true if all AFI/SAFIs are valid, false if UPDATE should be ignored.
    fn validate_multiprotocol_capabilities(&mut self, update_msg: &UpdateMessage) -> bool {
        for attr in update_msg.path_attributes() {
            let afi_safi = match &attr.value {
                PathAttrValue::MpReachNlri(mp_reach) => AfiSafi::new(mp_reach.afi, mp_reach.safi),
                PathAttrValue::MpUnreachNlri(mp_unreach) => {
                    AfiSafi::new(mp_unreach.afi, mp_unreach.safi)
                }
                _ => continue,
            };

            if !self.validate_afi_safi(afi_safi) {
                return false;
            }
        }
        true
    }

    /// Handle a BGP UPDATE message
    /// Returns (withdrawn_prefixes, announced_routes) - only what changed in THIS update
    pub(super) fn handle_update(
        &mut self,
        update_msg: UpdateMessage,
    ) -> Result<UpdateResult, BgpError> {
        // RFC 4760 Section 7: Validate multiprotocol NLRI against negotiated capabilities
        if !self.validate_multiprotocol_capabilities(&update_msg) {
            return Ok((vec![], vec![]));
        }

        // RFC 4271 Section 6.3: For eBGP, check that leftmost AS in AS_PATH equals peer AS.
        // If mismatch, MUST set error subcode to MalformedASPath.
        if self.session_type == Some(SessionType::Ebgp) {
            if let Some(leftmost_as) = update_msg.leftmost_as() {
                if let Some(peer_asn) = self.asn {
                    if leftmost_as != peer_asn {
                        warn!(&self.logger, "AS_PATH first AS does not match peer AS",
                              "peer_ip" => self.addr.to_string(), "leftmost_as" => leftmost_as, "peer_asn" => peer_asn);
                        return Err(BgpError::UpdateMessageError(
                            UpdateMessageError::MalformedASPath,
                        ));
                    }
                }
            }
        }

        let withdrawn = self.process_withdrawals(&update_msg);
        let announced = self.process_announcements(&update_msg)?;
        Ok((withdrawn, announced))
    }

    /// Process withdrawn routes from an UPDATE message
    fn process_withdrawals(&mut self, update_msg: &UpdateMessage) -> Vec<IpNetwork> {
        let mut withdrawn = Vec::new();
        for prefix in update_msg.withdrawn_routes() {
            info!(&self.logger, "withdrawing route", "prefix" => format!("{:?}", prefix), "peer_ip" => self.addr.to_string());
            self.rib_in.remove_route(prefix);
            withdrawn.push(prefix);
        }
        withdrawn
    }

    /// Check if adding new prefixes would exceed max prefix limit.
    /// Returns Ok(true) to proceed, Ok(false) to discard, Err to terminate.
    fn check_max_prefix_limit(&self, incoming_prefix_count: usize) -> Result<bool, BgpError> {
        let Some(setting) = self.config.max_prefix else {
            return Ok(true);
        };
        let current = self.rib_in.prefix_count();
        if current + incoming_prefix_count <= setting.limit as usize {
            return Ok(true);
        }
        match setting.action {
            MaxPrefixAction::Terminate => {
                warn!(&self.logger, "max prefix limit exceeded",
                      "peer_ip" => self.addr.to_string(), "limit" => setting.limit, "current" => current);
                Err(BgpError::Cease(CeaseSubcode::MaxPrefixesReached))
            }
            MaxPrefixAction::Discard => {
                warn!(&self.logger, "max prefix limit reached, discarding new prefixes",
                      "peer_ip" => self.addr.to_string(), "limit" => setting.limit, "current" => current);
                Ok(false)
            }
        }
    }

    fn process_announcements(
        &mut self,
        update_msg: &UpdateMessage,
    ) -> Result<Vec<(IpNetwork, Arc<Path>)>, BgpError> {
        if !self.check_max_prefix_limit(update_msg.nlri_list().len())? {
            return Ok(Vec::new());
        }

        let mut announced = Vec::new();

        let source = RouteSource::from_session(
            self.session_type
                .expect("session_type must be set in Established state"),
            self.addr,
        );

        let Some(path) = Path::from_update_msg(update_msg, source) else {
            if !update_msg.nlri_list().is_empty() {
                warn!(&self.logger, "UPDATE has NLRI but missing required attributes, skipping announcements", "peer_ip" => self.addr.to_string());
            }
            return Ok(announced);
        };

        // RFC 4271 5.1.3(a): NEXT_HOP must not be receiving speaker's IP
        let is_local_nexthop = match (&path.next_hop, self.fsm.local_addr()) {
            (NextHopAddr::Ipv4(nh), IpAddr::V4(local)) => nh == &local,
            (NextHopAddr::Ipv6(nh), IpAddr::V6(local)) => nh == &local,
            _ => false,
        };
        if is_local_nexthop {
            warn!(&self.logger, "rejecting UPDATE: NEXT_HOP is local address",
                  "next_hop" => path.next_hop.to_string(), "peer" => &self.addr);
            return Ok(announced);
        }

        // Wrap path in Arc once
        let path_arc = Arc::new(path);

        for prefix in update_msg.nlri_list() {
            info!(&self.logger, "adding route to Adj-RIB-In", "prefix" => format!("{:?}", prefix), "peer_ip" => self.addr.to_string(), "med" => format!("{:?}", path_arc.med));
            self.rib_in.add_route(prefix, Arc::clone(&path_arc));
            announced.push((prefix, Arc::clone(&path_arc)));
        }

        Ok(announced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, Origin};
    use crate::config::MaxPrefixSetting;
    use crate::net::Ipv4Net;
    use crate::peer::BgpState;
    use crate::peer::PeerCapabilities;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_validate_afi_safi() {
        use crate::bgp::multiprotocol::{Afi, Safi};
        use crate::peer::test_helpers::create_test_peer_with_state;

        let ipv6_unicast = AfiSafi::new(Afi::Ipv6, Safi::Unicast);
        let ipv4_multicast = AfiSafi::new(Afi::Ipv4, Safi::Multicast);

        // (negotiated, disabled, afi_safi, expected_valid, expect_disabled_after)
        let cases = vec![
            (vec![ipv6_unicast], vec![], ipv6_unicast, true, false),
            (vec![ipv6_unicast], vec![], ipv4_multicast, false, true),
            (vec![], vec![ipv4_multicast], ipv4_multicast, false, true),
        ];

        for (negotiated, disabled, test_afi_safi, expected_valid, expect_disabled_after) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.negotiated_capabilities = PeerCapabilities {
                multiprotocol: negotiated.into_iter().collect(),
                route_refresh: false,
            };
            peer.disabled_afi_safi = disabled.into_iter().collect();

            let result = peer.validate_afi_safi(test_afi_safi);
            assert_eq!(result, expected_valid, "{:?}", test_afi_safi);
            assert_eq!(
                peer.disabled_afi_safi.contains(&test_afi_safi),
                expect_disabled_after,
                "{:?}",
                test_afi_safi
            );
        }
    }

    #[tokio::test]
    async fn test_handle_update_first_as_validation() {
        use crate::peer::test_helpers::create_test_peer_with_state;

        // (session_type, peer_asn, first_as_in_path, should_pass)
        let cases = vec![
            (SessionType::Ebgp, 65001, 65002, false), // eBGP mismatch -> fail
            (SessionType::Ebgp, 65001, 65001, true),  // eBGP match -> pass
            (SessionType::Ibgp, 65001, 65002, true),  // iBGP mismatch -> pass (no check)
        ];

        for (session_type, peer_asn, first_as, should_pass) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.session_type = Some(session_type);
            peer.asn = Some(peer_asn);

            let update = UpdateMessage::new(
                Origin::IGP,
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![first_as],
                }],
                NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                vec![],
                None,
                None,
                false,
                vec![],
                vec![],
                vec![],
                vec![],
            );

            let result = peer.handle_update(update);
            assert_eq!(
                result.is_ok(),
                should_pass,
                "{:?} peer_asn={} first_as={}",
                session_type,
                peer_asn,
                first_as
            );
        }
    }

    #[tokio::test]
    async fn test_max_prefix() {
        use crate::peer::test_helpers::create_test_peer_with_state;

        // (max_prefix, initial, new, expected_ok, expected_rib, desc)
        #[allow(clippy::type_complexity)]
        let cases: Vec<(Option<MaxPrefixSetting>, usize, usize, bool, usize, &str)> = vec![
            // No limit: all prefixes accepted
            (None, 0, 10, true, 10, "no limit set"),
            // Under limit: accepted
            (
                Some(MaxPrefixSetting {
                    limit: 5,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                3,
                true,
                3,
                "under limit",
            ),
            // Exactly at limit: accepted
            (
                Some(MaxPrefixSetting {
                    limit: 5,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                5,
                true,
                5,
                "at limit",
            ),
            // Over limit with Terminate: error, no prefixes added
            (
                Some(MaxPrefixSetting {
                    limit: 5,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                6,
                false,
                0,
                "over limit terminate",
            ),
            // Over limit with Discard: ok, but no prefixes added
            (
                Some(MaxPrefixSetting {
                    limit: 5,
                    action: MaxPrefixAction::Discard,
                }),
                0,
                6,
                true,
                0,
                "over limit discard",
            ),
            // Have 4, add 2 would exceed 5: reject new, keep existing 4
            (
                Some(MaxPrefixSetting {
                    limit: 5,
                    action: MaxPrefixAction::Discard,
                }),
                4,
                2,
                true,
                4,
                "existing prefixes preserved on discard",
            ),
        ];

        for (setting, initial, new_prefixes, expected_ok, expected_rib, desc) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.config.max_prefix = setting;

            // Add initial prefixes (use different subnet to avoid overlap)
            if initial > 0 {
                let initial_nlri: Vec<_> = (0..initial)
                    .map(|i| {
                        IpNetwork::V4(Ipv4Net {
                            address: Ipv4Addr::new(192, 168, i as u8, 0),
                            prefix_length: 24,
                        })
                    })
                    .collect();
                let initial_update = UpdateMessage::new(
                    Origin::IGP,
                    vec![AsPathSegment {
                        segment_type: AsPathSegmentType::AsSequence,
                        segment_len: 1,
                        asn_list: vec![65001],
                    }],
                    NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                    initial_nlri,
                    None,
                    None,
                    false,
                    vec![],
                    vec![],
                    vec![],
                    vec![], // large_communities
                );
                peer.handle_update(initial_update).unwrap();
            }

            let nlri: Vec<_> = (0..new_prefixes)
                .map(|i| {
                    IpNetwork::V4(Ipv4Net {
                        address: Ipv4Addr::new(10, 0, i as u8, 0),
                        prefix_length: 24,
                    })
                })
                .collect();

            let update = UpdateMessage::new(
                Origin::IGP,
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                nlri,
                None,
                None,
                false,
                vec![],
                vec![],
                vec![],
                vec![], // large_communities
            );

            let result = peer.handle_update(update);
            assert_eq!(result.is_ok(), expected_ok, "{}", desc);
            assert_eq!(peer.rib_in.prefix_count(), expected_rib, "{}", desc);
        }
    }

    #[tokio::test]
    async fn test_check_max_prefix_limit() {
        use crate::peer::test_helpers::create_test_peer_with_state;
        use crate::test_helpers::{create_test_path, create_test_prefix_n};

        // (setting, rib_count, new_count, expected)
        // expected: Ok(true)=proceed, Ok(false)=discard, Err=terminate
        #[allow(clippy::type_complexity)]
        let cases: Vec<(Option<MaxPrefixSetting>, usize, usize, Result<bool, ()>)> = vec![
            (None, 0, 100, Ok(true)),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                5,
                Ok(true),
            ),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                10,
                Ok(true),
            ),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Terminate,
                }),
                0,
                11,
                Err(()),
            ),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Terminate,
                }),
                8,
                3,
                Err(()),
            ),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Discard,
                }),
                0,
                11,
                Ok(false),
            ),
            (
                Some(MaxPrefixSetting {
                    limit: 10,
                    action: MaxPrefixAction::Discard,
                }),
                8,
                3,
                Ok(false),
            ),
        ];

        for (setting, rib_count, incoming, expected) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.config.max_prefix = setting;
            let test_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            for i in 0..rib_count {
                peer.rib_in
                    .add_route(create_test_prefix_n(i as u8), create_test_path(test_ip));
            }

            let result = peer.check_max_prefix_limit(incoming);
            match expected {
                Ok(b) => assert_eq!(
                    result,
                    Ok(b),
                    "setting={:?} rib={} incoming={}",
                    setting,
                    rib_count,
                    incoming
                ),
                Err(_) => assert!(
                    result.is_err(),
                    "setting={:?} rib={} incoming={}",
                    setting,
                    rib_count,
                    incoming
                ),
            }
        }
    }
}
