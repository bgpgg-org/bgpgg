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

//! This module implements the BGP FSM.

use std::time::{Duration, Instant};

/// BGP FSM states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

/// BGP FSM events as defined in RFC 4271 Section 8.1
/// Events now carry necessary data for the FSM to send messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmEvent {
    ManualStart,
    ManualStop,
    ConnectRetryTimerExpires,
    HoldTimerExpires,
    KeepaliveTimerExpires,
    /// Carries parameters needed to send OPEN message
    TcpConnectionConfirmed {
        local_asn: u16,
        hold_time: u16,
        bgp_id: u32,
    },
    TcpConnectionFails,
    /// Carries peer parameters from received OPEN
    BgpOpenReceived {
        peer_asn: u16,
        peer_hold_time: u16,
        local_hold_time: u16,
    },
    BgpKeepaliveReceived,
    BgpUpdateReceived,
    NotificationReceived,
}

/// BGP FSM timers
#[derive(Debug, Clone)]
pub struct FsmTimers {
    /// ConnectRetry timer value (default: 120 seconds)
    pub connect_retry_time: Duration,

    /// Hold timer value (default: 180 seconds, negotiated with peer)
    pub hold_time: Duration,

    /// Keepalive timer value (typically 1/3 of hold_time)
    pub keepalive_time: Duration,

    /// Last time ConnectRetry timer was started
    pub connect_retry_started: Option<Instant>,

    /// Last time Hold timer was started/reset
    pub hold_timer_started: Option<Instant>,

    /// Last time Keepalive timer was started/reset
    pub keepalive_timer_started: Option<Instant>,
}

impl Default for FsmTimers {
    fn default() -> Self {
        FsmTimers {
            connect_retry_time: Duration::from_secs(120),
            hold_time: Duration::from_secs(180),
            keepalive_time: Duration::from_secs(60), // 1/3 of hold_time
            connect_retry_started: None,
            hold_timer_started: None,
            keepalive_timer_started: None,
        }
    }
}

impl FsmTimers {
    /// Check if ConnectRetry timer has expired
    pub fn connect_retry_expired(&self) -> bool {
        if let Some(started) = self.connect_retry_started {
            started.elapsed() >= self.connect_retry_time
        } else {
            false
        }
    }

    /// Check if Hold timer has expired
    pub fn hold_timer_expired(&self) -> bool {
        if let Some(started) = self.hold_timer_started {
            started.elapsed() >= self.hold_time
        } else {
            false
        }
    }

    /// Check if Keepalive timer has expired
    pub fn keepalive_timer_expired(&self) -> bool {
        if let Some(started) = self.keepalive_timer_started {
            started.elapsed() >= self.keepalive_time
        } else {
            false
        }
    }

    /// Start ConnectRetry timer
    pub fn start_connect_retry(&mut self) {
        self.connect_retry_started = Some(Instant::now());
    }

    /// Stop ConnectRetry timer
    pub fn stop_connect_retry(&mut self) {
        self.connect_retry_started = None;
    }

    /// Start Hold timer
    pub fn start_hold_timer(&mut self) {
        self.hold_timer_started = Some(Instant::now());
    }

    /// Reset Hold timer
    pub fn reset_hold_timer(&mut self) {
        self.hold_timer_started = Some(Instant::now());
    }

    /// Stop Hold timer
    pub fn stop_hold_timer(&mut self) {
        self.hold_timer_started = None;
    }

    /// Start Keepalive timer
    pub fn start_keepalive_timer(&mut self) {
        self.keepalive_timer_started = Some(Instant::now());
    }

    /// Reset Keepalive timer
    pub fn reset_keepalive_timer(&mut self) {
        self.keepalive_timer_started = Some(Instant::now());
    }

    /// Stop Keepalive timer
    pub fn stop_keepalive_timer(&mut self) {
        self.keepalive_timer_started = None;
    }

    /// Update negotiated hold time (from received OPEN message)
    pub fn set_negotiated_hold_time(&mut self, hold_time: u16) {
        self.hold_time = Duration::from_secs(hold_time as u64);
        // Keepalive timer should be at most 1/3 of hold time
        self.keepalive_time = Duration::from_secs((hold_time as u64) / 3);
    }
}

/// BGP Finite State Machine
pub struct Fsm {
    /// Current state
    state: BgpState,

    /// FSM timers
    pub timers: FsmTimers,
}

impl Fsm {
    /// Create a new FSM in Idle state
    pub fn new() -> Self {
        Fsm {
            state: BgpState::Idle,
            timers: FsmTimers::default(),
        }
    }

    /// Create a new FSM with a specific initial state
    pub fn with_state(state: BgpState) -> Self {
        Fsm {
            state,
            timers: FsmTimers::default(),
        }
    }

    /// Get current state
    pub fn state(&self) -> BgpState {
        self.state
    }

    /// Handle an event and return the new state
    ///
    /// This implements the state machine logic from RFC 4271 Section 8.2.2
    pub fn handle_event(&mut self, event: &FsmEvent) -> BgpState {
        let new_state = match (&self.state, event) {
            // ===== Idle State =====
            (BgpState::Idle, FsmEvent::ManualStart) => BgpState::Connect,

            // ===== Connect State =====
            (BgpState::Connect, FsmEvent::ManualStop) => BgpState::Idle,
            (BgpState::Connect, FsmEvent::ConnectRetryTimerExpires) => BgpState::Connect,
            (BgpState::Connect, FsmEvent::TcpConnectionConfirmed { .. }) => BgpState::OpenSent,
            (BgpState::Connect, FsmEvent::TcpConnectionFails) => BgpState::Active,

            // ===== Active State =====
            (BgpState::Active, FsmEvent::ManualStop) => BgpState::Idle,
            (BgpState::Active, FsmEvent::ConnectRetryTimerExpires) => BgpState::Connect,
            (BgpState::Active, FsmEvent::TcpConnectionConfirmed { .. }) => BgpState::OpenSent,

            // ===== OpenSent State =====
            (BgpState::OpenSent, FsmEvent::ManualStop) => BgpState::Idle,
            (BgpState::OpenSent, FsmEvent::HoldTimerExpires) => BgpState::Idle,
            (BgpState::OpenSent, FsmEvent::TcpConnectionFails) => BgpState::Active,
            (BgpState::OpenSent, FsmEvent::BgpOpenReceived { .. }) => BgpState::OpenConfirm,
            (BgpState::OpenSent, FsmEvent::NotificationReceived) => BgpState::Idle,

            // ===== OpenConfirm State =====
            (BgpState::OpenConfirm, FsmEvent::ManualStop) => BgpState::Idle,
            (BgpState::OpenConfirm, FsmEvent::HoldTimerExpires) => BgpState::Idle,
            (BgpState::OpenConfirm, FsmEvent::KeepaliveTimerExpires) => BgpState::OpenConfirm,
            (BgpState::OpenConfirm, FsmEvent::TcpConnectionFails) => BgpState::Idle,
            (BgpState::OpenConfirm, FsmEvent::BgpKeepaliveReceived) => BgpState::Established,
            (BgpState::OpenConfirm, FsmEvent::NotificationReceived) => BgpState::Idle,

            // ===== Established State =====
            (BgpState::Established, FsmEvent::ManualStop) => BgpState::Idle,
            (BgpState::Established, FsmEvent::HoldTimerExpires) => BgpState::Idle,
            (BgpState::Established, FsmEvent::KeepaliveTimerExpires) => BgpState::Established,
            (BgpState::Established, FsmEvent::TcpConnectionFails) => BgpState::Idle,
            (BgpState::Established, FsmEvent::BgpKeepaliveReceived) => BgpState::Established,
            (BgpState::Established, FsmEvent::BgpUpdateReceived) => BgpState::Established,
            (BgpState::Established, FsmEvent::NotificationReceived) => BgpState::Idle,

            // Default: Invalid event for current state, stay in same state
            _ => self.state,
        };

        // Update state
        self.state = new_state;

        new_state
    }

    /// Check if FSM is in Established state
    pub fn is_established(&self) -> bool {
        self.state == BgpState::Established
    }
}

impl Default for Fsm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let fsm = Fsm::new();
        assert_eq!(fsm.state(), BgpState::Idle);
    }

    #[test]
    fn test_manual_start_from_idle() {
        let mut fsm = Fsm::new();
        let new_state = fsm.handle_event(&FsmEvent::ManualStart);

        assert_eq!(new_state, BgpState::Connect);
        assert_eq!(fsm.state(), BgpState::Connect);
    }

    #[test]
    fn test_successful_connection_establishment() {
        let mut fsm = Fsm::new();

        // Idle -> Connect
        fsm.handle_event(&FsmEvent::ManualStart);
        assert_eq!(fsm.state(), BgpState::Connect);

        // Connect -> OpenSent
        fsm.handle_event(&FsmEvent::TcpConnectionConfirmed {
            local_asn: 65000,
            hold_time: 180,
            bgp_id: 0x01010101,
        });
        assert_eq!(fsm.state(), BgpState::OpenSent);

        // OpenSent -> OpenConfirm
        fsm.handle_event(&FsmEvent::BgpOpenReceived {
            peer_asn: 65001,
            peer_hold_time: 180,
            local_hold_time: 180,
        });
        assert_eq!(fsm.state(), BgpState::OpenConfirm);

        // OpenConfirm -> Established
        fsm.handle_event(&FsmEvent::BgpKeepaliveReceived);
        assert_eq!(fsm.state(), BgpState::Established);
        assert!(fsm.is_established());
    }

    #[test]
    fn test_connection_failure_handling() {
        let mut fsm = Fsm::new();

        // Idle -> Connect
        fsm.handle_event(&FsmEvent::ManualStart);

        // Connect -> Active (connection failed)
        fsm.handle_event(&FsmEvent::TcpConnectionFails);
        assert_eq!(fsm.state(), BgpState::Active);

        // Active -> Connect (retry)
        fsm.handle_event(&FsmEvent::ConnectRetryTimerExpires);
        assert_eq!(fsm.state(), BgpState::Connect);
    }

    #[test]
    fn test_hold_timer_expiry() {
        let mut fsm = Fsm::new();

        // Move to OpenSent
        fsm.handle_event(&FsmEvent::ManualStart);
        fsm.handle_event(&FsmEvent::TcpConnectionConfirmed {
            local_asn: 65000,
            hold_time: 180,
            bgp_id: 0x01010101,
        });

        // Hold timer expiry should go to Idle
        fsm.handle_event(&FsmEvent::HoldTimerExpires);
        assert_eq!(fsm.state(), BgpState::Idle);
    }

    #[test]
    fn test_all_valid_state_transitions() {
        // Table of (initial_state, event, expected_state)
        let test_cases = vec![
            // From Idle
            (BgpState::Idle, FsmEvent::ManualStart, BgpState::Connect),
            // From Connect
            (BgpState::Connect, FsmEvent::ManualStop, BgpState::Idle),
            (
                BgpState::Connect,
                FsmEvent::ConnectRetryTimerExpires,
                BgpState::Connect,
            ),
            (
                BgpState::Connect,
                FsmEvent::TcpConnectionConfirmed {
                    local_asn: 65000,
                    hold_time: 180,
                    bgp_id: 0x01010101,
                },
                BgpState::OpenSent,
            ),
            (
                BgpState::Connect,
                FsmEvent::TcpConnectionFails,
                BgpState::Active,
            ),
            // From Active
            (BgpState::Active, FsmEvent::ManualStop, BgpState::Idle),
            (
                BgpState::Active,
                FsmEvent::ConnectRetryTimerExpires,
                BgpState::Connect,
            ),
            (
                BgpState::Active,
                FsmEvent::TcpConnectionConfirmed {
                    local_asn: 65000,
                    hold_time: 180,
                    bgp_id: 0x01010101,
                },
                BgpState::OpenSent,
            ),
            // From OpenSent
            (BgpState::OpenSent, FsmEvent::ManualStop, BgpState::Idle),
            (
                BgpState::OpenSent,
                FsmEvent::HoldTimerExpires,
                BgpState::Idle,
            ),
            (
                BgpState::OpenSent,
                FsmEvent::TcpConnectionFails,
                BgpState::Active,
            ),
            (
                BgpState::OpenSent,
                FsmEvent::BgpOpenReceived {
                    peer_asn: 65001,
                    peer_hold_time: 180,
                    local_hold_time: 180,
                },
                BgpState::OpenConfirm,
            ),
            (
                BgpState::OpenSent,
                FsmEvent::NotificationReceived,
                BgpState::Idle,
            ),
            // From OpenConfirm
            (BgpState::OpenConfirm, FsmEvent::ManualStop, BgpState::Idle),
            (
                BgpState::OpenConfirm,
                FsmEvent::HoldTimerExpires,
                BgpState::Idle,
            ),
            (
                BgpState::OpenConfirm,
                FsmEvent::KeepaliveTimerExpires,
                BgpState::OpenConfirm,
            ),
            (
                BgpState::OpenConfirm,
                FsmEvent::TcpConnectionFails,
                BgpState::Idle,
            ),
            (
                BgpState::OpenConfirm,
                FsmEvent::BgpKeepaliveReceived,
                BgpState::Established,
            ),
            (
                BgpState::OpenConfirm,
                FsmEvent::NotificationReceived,
                BgpState::Idle,
            ),
            // From Established
            (BgpState::Established, FsmEvent::ManualStop, BgpState::Idle),
            (
                BgpState::Established,
                FsmEvent::HoldTimerExpires,
                BgpState::Idle,
            ),
            (
                BgpState::Established,
                FsmEvent::KeepaliveTimerExpires,
                BgpState::Established,
            ),
            (
                BgpState::Established,
                FsmEvent::TcpConnectionFails,
                BgpState::Idle,
            ),
            (
                BgpState::Established,
                FsmEvent::BgpKeepaliveReceived,
                BgpState::Established,
            ),
            (
                BgpState::Established,
                FsmEvent::BgpUpdateReceived,
                BgpState::Established,
            ),
            (
                BgpState::Established,
                FsmEvent::NotificationReceived,
                BgpState::Idle,
            ),
        ];

        for (initial_state, event, expected_state) in test_cases {
            let mut fsm = Fsm::with_state(initial_state);
            let new_state = fsm.handle_event(&event);

            assert_eq!(
                new_state, expected_state,
                "Failed transition: {:?} + {:?} should -> {:?}, got {:?}",
                initial_state, event, expected_state, new_state
            );
            assert_eq!(fsm.state(), expected_state);
        }
    }
}
