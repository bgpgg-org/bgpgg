use crate::rib::Path;

/// An action that can modify a route
pub trait Action: std::fmt::Debug + Send + Sync {
    /// Apply the action. Returns true if route should be accepted, false to reject.
    fn apply(&self, path: &mut Path) -> bool;
}

/// Set local preference
#[derive(Debug, Clone)]
pub struct SetLocalPref {
    pub value: u32,
    pub force: bool, // If true, overwrite existing value
}

impl SetLocalPref {
    pub fn new(value: u32) -> Self {
        Self {
            value,
            force: false,
        }
    }

    pub fn force(value: u32) -> Self {
        Self { value, force: true }
    }
}

impl Action for SetLocalPref {
    fn apply(&self, path: &mut Path) -> bool {
        if self.force || path.local_pref.is_none() {
            path.local_pref = Some(self.value);
        }
        true // Accept route
    }
}

/// Set MED attribute
#[derive(Debug, Clone)]
pub struct SetMed {
    pub value: Option<u32>,
}

impl SetMed {
    pub fn new(value: u32) -> Self {
        Self { value: Some(value) }
    }

    pub fn remove() -> Self {
        Self { value: None }
    }
}

impl Action for SetMed {
    fn apply(&self, path: &mut Path) -> bool {
        path.med = self.value;
        true
    }
}

/// Reject route
#[derive(Debug, Clone)]
pub struct Reject;

impl Action for Reject {
    fn apply(&self, _path: &mut Path) -> bool {
        false // Reject route
    }
}

/// Accept route (no-op, just for clarity)
#[derive(Debug, Clone)]
pub struct Accept;

impl Action for Accept {
    fn apply(&self, _path: &mut Path) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::test_helpers::create_path;
    use crate::rib::RouteSource;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    #[test]
    fn test_set_local_pref() {
        let mut path = create_path(RouteSource::Ebgp(test_ip()));
        assert!(SetLocalPref::new(100).apply(&mut path));
        assert_eq!(path.local_pref, Some(100));

        assert!(SetLocalPref::new(200).apply(&mut path));
        assert_eq!(path.local_pref, Some(100)); // Preserves existing

        assert!(SetLocalPref::force(200).apply(&mut path));
        assert_eq!(path.local_pref, Some(200)); // Force overrides
    }

    #[test]
    fn test_set_med() {
        let mut path = create_path(RouteSource::Ebgp(test_ip()));
        assert!(SetMed::new(50).apply(&mut path));
        assert_eq!(path.med, Some(50));

        assert!(SetMed::remove().apply(&mut path));
        assert_eq!(path.med, None);
    }

    #[test]
    fn test_reject() {
        assert!(!Reject.apply(&mut create_path(RouteSource::Ebgp(test_ip()))));
    }

    #[test]
    fn test_accept() {
        assert!(Accept.apply(&mut create_path(RouteSource::Ebgp(test_ip()))));
    }
}
