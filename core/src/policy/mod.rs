pub mod sets;
pub mod statement;

pub use statement::{
    stmt_default_local_pref, stmt_reject_as_loop, stmt_reject_ibgp, CommunityOp, Policy,
    PolicyResult, RouteType, Statement,
};

// Re-export runtime structures
pub use sets::DefinedSets;

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::bgp::msg_update::Origin;
    use crate::net::{IpNetwork, Ipv4Net};
    use crate::rib::{Path, RouteSource};
    use std::net::Ipv4Addr;

    pub fn create_path(source: RouteSource) -> Path {
        Path {
            origin: Origin::IGP,
            as_path: vec![],
            next_hop: Ipv4Addr::new(10, 0, 0, 1),
            source,
            local_pref: None,
            med: None,
            atomic_aggregate: false,
            communities: vec![],
            unknown_attrs: vec![],
        }
    }

    pub fn test_prefix() -> IpNetwork {
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        })
    }
}
