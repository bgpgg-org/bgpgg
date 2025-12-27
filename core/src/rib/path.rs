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

use crate::bgp::msg_update::{
    AsPathSegment, AsPathSegmentType, Origin, PathAttribute, UpdateMessage,
};
use crate::rib::types::RouteSource;
use std::cmp::Ordering;
use std::net::Ipv4Addr;

/// Represents a BGP path with all its attributes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Path {
    pub origin: Origin,
    pub as_path: Vec<AsPathSegment>,
    pub next_hop: Ipv4Addr,
    pub source: RouteSource,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub atomic_aggregate: bool,
    pub unknown_attrs: Vec<PathAttribute>,
}

impl Path {
    /// Create a Path from BGP UPDATE message attributes
    pub fn from_attributes(
        origin: Origin,
        as_path: Vec<AsPathSegment>,
        next_hop: Ipv4Addr,
        source: RouteSource,
        local_pref: Option<u32>,
        med: Option<u32>,
        atomic_aggregate: bool,
        unknown_attrs: Vec<PathAttribute>,
    ) -> Self {
        Path {
            origin,
            as_path,
            next_hop,
            source,
            local_pref,
            med,
            atomic_aggregate,
            unknown_attrs,
        }
    }

    /// Create a Path from an UPDATE message. Returns None if required attributes are missing.
    pub fn from_update_msg(update_msg: &UpdateMessage, source: RouteSource) -> Option<Self> {
        let origin = update_msg.get_origin()?;
        let as_path = update_msg.get_as_path()?;
        let next_hop = update_msg.get_next_hop()?;
        Some(Path {
            origin,
            as_path,
            next_hop,
            source,
            local_pref: update_msg.get_local_pref(),
            med: update_msg.get_med(),
            atomic_aggregate: update_msg.get_atomic_aggregate(),
            unknown_attrs: update_msg.get_unknown_attrs(),
        })
    }

    /// Calculate AS_PATH length for best path selection per RFC 4271
    /// AS_SEQUENCE counts each ASN, AS_SET counts as 1 regardless of size
    fn as_path_length(&self) -> usize {
        self.as_path
            .iter()
            .map(|segment| match segment.segment_type {
                AsPathSegmentType::AsSequence => segment.asn_list.len(),
                AsPathSegmentType::AsSet => 1,
            })
            .sum()
    }

    /// Determine neighboring AS per RFC 4271 Section 9.1.2.2(c)
    /// Returns the first AS in the AS_PATH if present, None for locally originated routes
    fn neighboring_as(&self) -> Option<u16> {
        // Find first AS_SEQUENCE segment and return its first ASN
        for segment in &self.as_path {
            if segment.segment_type == AsPathSegmentType::AsSequence {
                if !segment.asn_list.is_empty() {
                    return Some(segment.asn_list[0]);
                }
            }
        }
        // Empty AS_PATH or no AS_SEQUENCE (locally originated or aggregated routes)
        None
    }
}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Path {
    /// Compare paths for BGP best path selection per RFC 4271 Section 9.1.2.2
    /// Returns Ordering::Greater if self is better (higher preference)
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Step 1: Prefer the route with the highest degree of preference (LOCAL_PREF)
        let self_local_pref = self.local_pref.unwrap_or(100);
        let other_local_pref = other.local_pref.unwrap_or(100);
        match self_local_pref.cmp(&other_local_pref) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Step 2: Prefer the route with the shortest AS_PATH
        // AS_SEQUENCE counts each ASN, AS_SET counts as 1
        match other.as_path_length().cmp(&self.as_path_length()) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Step 3: Prefer the route with the lowest ORIGIN type (IGP < EGP < INCOMPLETE)
        let self_origin = self.origin as u8;
        let other_origin = other.origin as u8;
        match other_origin.cmp(&self_origin) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Step 4: Prefer the route with the lowest MULTI_EXIT_DISC (MED)
        // RFC 4271 Section 9.1.2.2(c): MED is only comparable between routes
        // learned from the same neighboring AS
        let self_neighbor = self.neighboring_as();
        let other_neighbor = other.neighboring_as();
        if self_neighbor == other_neighbor {
            let self_med = self.med.unwrap_or(0);
            let other_med = other.med.unwrap_or(0);
            match other_med.cmp(&self_med) {
                Ordering::Greater => return Ordering::Greater,
                Ordering::Less => return Ordering::Less,
                Ordering::Equal => {}
            }
        }
        // If from different neighboring AS, skip MED comparison

        // Step 5: Prefer eBGP-learned routes over iBGP-learned routes
        match (&self.source, &other.source) {
            (RouteSource::Ebgp(_), RouteSource::Ibgp(_)) => return Ordering::Greater,
            (RouteSource::Ibgp(_), RouteSource::Ebgp(_)) => return Ordering::Less,
            // Local routes are considered better than any BGP-learned route
            (RouteSource::Local, RouteSource::Ebgp(_) | RouteSource::Ibgp(_)) => {
                return Ordering::Greater
            }
            (RouteSource::Ebgp(_) | RouteSource::Ibgp(_), RouteSource::Local) => {
                return Ordering::Less
            }
            _ => {}
        }

        // Step 6: If both paths are external, prefer the route from the BGP speaker
        // with the lowest BGP Identifier (using peer address as proxy)
        match (&self.source, &other.source) {
            (RouteSource::Ebgp(a), RouteSource::Ebgp(b)) => {
                b.cmp(a) // reverse for "prefer lower"
            }
            (RouteSource::Ibgp(a), RouteSource::Ibgp(b)) => {
                b.cmp(a) // also break ties for iBGP routes
            }
            _ => Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn make_base_path() -> Path {
        Path {
            origin: Origin::IGP,
            as_path: vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65001],
            }],
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            source: RouteSource::Ebgp(test_ip(1)),
            local_pref: Some(100),
            med: None,
            atomic_aggregate: false,
            unknown_attrs: vec![],
        }
    }

    #[test]
    fn test_local_pref_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.local_pref = Some(200);
        path2.local_pref = Some(100);

        assert!(path1 > path2);
    }

    #[test]
    fn test_as_path_length_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![65001],
        }];
        path2.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65001, 65002],
        }];

        assert!(path1 > path2);
    }

    #[test]
    fn test_as_set_length_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        // path1: AS_SET with 3 ASNs (counts as length 1)
        path1.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSet,
            segment_len: 3,
            asn_list: vec![65001, 65002, 65003],
        }];
        // path2: AS_SEQUENCE with 2 ASNs (counts as length 2)
        path2.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65001, 65002],
        }];

        // path1 (AS_SET, length=1) should be preferred over path2 (AS_SEQUENCE, length=2)
        assert!(path1 > path2);
    }

    #[test]
    fn test_origin_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.origin = Origin::IGP;
        path2.origin = Origin::INCOMPLETE;

        assert!(path1 > path2);
    }

    #[test]
    fn test_med_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.med = Some(50);
        path2.med = Some(100);

        assert!(path1 > path2);
    }

    #[test]
    fn test_med_missing_treated_as_zero() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.med = None; // treated as 0
        path2.med = Some(100);

        // path1 (MED=0) should be preferred over path2 (MED=100)
        assert!(path1 > path2);
    }

    #[test]
    fn test_local_vs_ebgp_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.source = RouteSource::Local;
        path2.source = RouteSource::Ebgp(test_ip(1));

        assert!(path1 > path2);
    }

    #[test]
    fn test_local_vs_ibgp_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.source = RouteSource::Local;
        path2.source = RouteSource::Ibgp(test_ip(1));

        assert!(path1 > path2);
    }

    #[test]
    fn test_ebgp_vs_ibgp_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.source = RouteSource::Ebgp(test_ip(1));
        path2.source = RouteSource::Ibgp(test_ip(2));

        assert!(path1 > path2);
    }

    #[test]
    fn test_peer_address_tiebreaker() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.source = RouteSource::Ebgp(test_ip(1));
        path2.source = RouteSource::Ebgp(test_ip(2));

        // Lower peer address should win
        assert!(path1 > path2);
    }

    #[test]
    fn test_from_update_msg() {
        let source = RouteSource::Ebgp(test_ip(1));

        // Valid UPDATE with all required attrs
        let update = UpdateMessage::new(
            Origin::IGP,
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65001],
            }],
            Ipv4Addr::new(10, 0, 0, 1),
            vec![],
            Some(100),
            Some(50),
            true,
            vec![],
        );
        let path = Path::from_update_msg(&update, source.clone());
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path.origin, Origin::IGP);
        assert_eq!(path.next_hop, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(path.local_pref, Some(100));
        assert_eq!(path.med, Some(50));
        assert!(path.atomic_aggregate);

        // Missing required attrs -> None
        let empty_update = UpdateMessage::new_withdraw(vec![]);
        assert!(Path::from_update_msg(&empty_update, source).is_none());
    }

    #[test]
    fn test_neighboring_as() {
        let tests = [
            (
                "AS_SEQUENCE with multiple ASNs",
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                }],
                Some(65001),
            ),
            ("empty AS_PATH", vec![], None),
            (
                "AS_SET then AS_SEQUENCE",
                vec![
                    AsPathSegment {
                        segment_type: AsPathSegmentType::AsSet,
                        segment_len: 2,
                        asn_list: vec![65001, 65002],
                    },
                    AsPathSegment {
                        segment_type: AsPathSegmentType::AsSequence,
                        segment_len: 1,
                        asn_list: vec![65003],
                    },
                ],
                Some(65003),
            ),
        ];

        for (name, as_path, expected) in tests {
            let mut path = make_base_path();
            path.as_path = as_path;
            assert_eq!(path.neighboring_as(), expected, "test case: {}", name);
        }
    }

    #[test]
    fn test_med_comparison() {
        let tests = [
            (
                "same AS - lower MED wins",
                RouteSource::Ebgp(test_ip(1)),
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Some(50),
                RouteSource::Ebgp(test_ip(1)),
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Some(100),
                Ordering::Greater, // path1 wins due to lower MED
            ),
            (
                "different AS - MED not compared",
                RouteSource::Ebgp(test_ip(1)),
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Some(100),
                RouteSource::Ebgp(test_ip(1)),
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65002],
                }],
                Some(10),
                Ordering::Equal, // MED skipped, both eBGP from same peer
            ),
            (
                "local routes - MED compared",
                RouteSource::Local,
                vec![],
                Some(50),
                RouteSource::Local,
                vec![],
                Some(100),
                Ordering::Greater, // path1 wins due to lower MED
            ),
            (
                "local vs external - MED not compared",
                RouteSource::Local,
                vec![],
                Some(100),
                RouteSource::Ebgp(test_ip(1)),
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Some(10),
                Ordering::Greater, // path1 wins at step 5 (Local > eBGP)
            ),
        ];

        for (name, src1, as_path1, med1, src2, as_path2, med2, expected) in tests {
            let mut path1 = make_base_path();
            path1.source = src1;
            path1.as_path = as_path1;
            path1.med = med1;

            let mut path2 = make_base_path();
            path2.source = src2;
            path2.as_path = as_path2;
            path2.med = med2;

            assert_eq!(path1.cmp(&path2), expected, "test case: {}", name);
        }
    }
}
