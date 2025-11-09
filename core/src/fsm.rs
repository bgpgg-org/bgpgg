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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BgpEvent {
    ManualStart = 1,
    ManualStop = 2,
    ConnectRetryTimerExpires = 9,
    HoldTimerExpires = 10,
    KeepaliveTimerExpires = 11,
    TcpConnectionConfirmed = 16,
    TcpConnectionFails = 18,
    BgpOpenReceived = 19,
    BgpKeepaliveReceived = 26,
    BgpUpdateReceived = 27,
    NotificationReceived = 24,
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

    /// Get current state
    pub fn state(&self) -> BgpState {
        self.state
    }

    /// Process an event and return the new state
    ///
    /// This implements the state machine logic from RFC 4271 Section 8.2.2
    pub fn process_event(&mut self, event: BgpEvent) -> BgpState {
        let new_state = match (self.state, event) {
            // ===== Idle State =====
            (BgpState::Idle, BgpEvent::ManualStart) => BgpState::Connect,

            // ===== Connect State =====
            (BgpState::Connect, BgpEvent::ManualStop) => BgpState::Idle,
            (BgpState::Connect, BgpEvent::ConnectRetryTimerExpires) => BgpState::Connect,
            (BgpState::Connect, BgpEvent::TcpConnectionConfirmed) => BgpState::OpenSent,
            (BgpState::Connect, BgpEvent::TcpConnectionFails) => BgpState::Active,

            // ===== Active State =====
            (BgpState::Active, BgpEvent::ManualStop) => BgpState::Idle,
            (BgpState::Active, BgpEvent::ConnectRetryTimerExpires) => BgpState::Connect,
            (BgpState::Active, BgpEvent::TcpConnectionConfirmed) => BgpState::OpenSent,

            // ===== OpenSent State =====
            (BgpState::OpenSent, BgpEvent::ManualStop) => BgpState::Idle,
            (BgpState::OpenSent, BgpEvent::HoldTimerExpires) => BgpState::Idle,
            (BgpState::OpenSent, BgpEvent::TcpConnectionFails) => BgpState::Active,
            (BgpState::OpenSent, BgpEvent::BgpOpenReceived) => BgpState::OpenConfirm,
            (BgpState::OpenSent, BgpEvent::NotificationReceived) => BgpState::Idle,

            // ===== OpenConfirm State =====
            (BgpState::OpenConfirm, BgpEvent::ManualStop) => BgpState::Idle,
            (BgpState::OpenConfirm, BgpEvent::HoldTimerExpires) => BgpState::Idle,
            (BgpState::OpenConfirm, BgpEvent::KeepaliveTimerExpires) => BgpState::OpenConfirm,
            (BgpState::OpenConfirm, BgpEvent::TcpConnectionFails) => BgpState::Idle,
            (BgpState::OpenConfirm, BgpEvent::BgpKeepaliveReceived) => BgpState::Established,
            (BgpState::OpenConfirm, BgpEvent::NotificationReceived) => BgpState::Idle,

            // ===== Established State =====
            (BgpState::Established, BgpEvent::ManualStop) => BgpState::Idle,
            (BgpState::Established, BgpEvent::HoldTimerExpires) => BgpState::Idle,
            (BgpState::Established, BgpEvent::KeepaliveTimerExpires) => BgpState::Established,
            (BgpState::Established, BgpEvent::TcpConnectionFails) => BgpState::Idle,
            (BgpState::Established, BgpEvent::BgpKeepaliveReceived) => BgpState::Established,
            (BgpState::Established, BgpEvent::BgpUpdateReceived) => BgpState::Established,
            (BgpState::Established, BgpEvent::NotificationReceived) => BgpState::Idle,

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

    impl Fsm {
        /// Create a new FSM with a specific initial state (for testing)
        pub fn with_state(state: BgpState) -> Self {
            Fsm {
                state,
                timers: FsmTimers::default(),
            }
        }
    }

    #[test]
    fn test_initial_state() {
        let fsm = Fsm::new();
        assert_eq!(fsm.state(), BgpState::Idle);
    }

    #[test]
    fn test_manual_start_from_idle() {
        let mut fsm = Fsm::new();
        let new_state = fsm.process_event(BgpEvent::ManualStart);

        assert_eq!(new_state, BgpState::Connect);
        assert_eq!(fsm.state(), BgpState::Connect);
    }

    #[test]
    fn test_successful_connection_establishment() {
        let mut fsm = Fsm::new();

        // Idle -> Connect
        fsm.process_event(BgpEvent::ManualStart);
        assert_eq!(fsm.state(), BgpState::Connect);

        // Connect -> OpenSent
        fsm.process_event(BgpEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), BgpState::OpenSent);

        // OpenSent -> OpenConfirm
        fsm.process_event(BgpEvent::BgpOpenReceived);
        assert_eq!(fsm.state(), BgpState::OpenConfirm);

        // OpenConfirm -> Established
        fsm.process_event(BgpEvent::BgpKeepaliveReceived);
        assert_eq!(fsm.state(), BgpState::Established);
        assert!(fsm.is_established());
    }

    #[test]
    fn test_connection_failure_handling() {
        let mut fsm = Fsm::new();

        // Idle -> Connect
        fsm.process_event(BgpEvent::ManualStart);

        // Connect -> Active (connection failed)
        fsm.process_event(BgpEvent::TcpConnectionFails);
        assert_eq!(fsm.state(), BgpState::Active);

        // Active -> Connect (retry)
        fsm.process_event(BgpEvent::ConnectRetryTimerExpires);
        assert_eq!(fsm.state(), BgpState::Connect);
    }

    #[test]
    fn test_hold_timer_expiry() {
        let mut fsm = Fsm::new();

        // Move to OpenSent
        fsm.process_event(BgpEvent::ManualStart);
        fsm.process_event(BgpEvent::TcpConnectionConfirmed);

        // Hold timer expiry should go to Idle
        fsm.process_event(BgpEvent::HoldTimerExpires);
        assert_eq!(fsm.state(), BgpState::Idle);
    }

    #[test]
    fn test_all_valid_state_transitions() {
        // Table of (initial_state, event, expected_state)
        let test_cases = vec![
            // From Idle
            (BgpState::Idle, BgpEvent::ManualStart, BgpState::Connect),
            // From Connect
            (BgpState::Connect, BgpEvent::ManualStop, BgpState::Idle),
            (
                BgpState::Connect,
                BgpEvent::ConnectRetryTimerExpires,
                BgpState::Connect,
            ),
            (
                BgpState::Connect,
                BgpEvent::TcpConnectionConfirmed,
                BgpState::OpenSent,
            ),
            (
                BgpState::Connect,
                BgpEvent::TcpConnectionFails,
                BgpState::Active,
            ),
            // From Active
            (BgpState::Active, BgpEvent::ManualStop, BgpState::Idle),
            (
                BgpState::Active,
                BgpEvent::ConnectRetryTimerExpires,
                BgpState::Connect,
            ),
            (
                BgpState::Active,
                BgpEvent::TcpConnectionConfirmed,
                BgpState::OpenSent,
            ),
            // From OpenSent
            (BgpState::OpenSent, BgpEvent::ManualStop, BgpState::Idle),
            (
                BgpState::OpenSent,
                BgpEvent::HoldTimerExpires,
                BgpState::Idle,
            ),
            (
                BgpState::OpenSent,
                BgpEvent::TcpConnectionFails,
                BgpState::Active,
            ),
            (
                BgpState::OpenSent,
                BgpEvent::BgpOpenReceived,
                BgpState::OpenConfirm,
            ),
            (
                BgpState::OpenSent,
                BgpEvent::NotificationReceived,
                BgpState::Idle,
            ),
            // From OpenConfirm
            (BgpState::OpenConfirm, BgpEvent::ManualStop, BgpState::Idle),
            (
                BgpState::OpenConfirm,
                BgpEvent::HoldTimerExpires,
                BgpState::Idle,
            ),
            (
                BgpState::OpenConfirm,
                BgpEvent::KeepaliveTimerExpires,
                BgpState::OpenConfirm,
            ),
            (
                BgpState::OpenConfirm,
                BgpEvent::TcpConnectionFails,
                BgpState::Idle,
            ),
            (
                BgpState::OpenConfirm,
                BgpEvent::BgpKeepaliveReceived,
                BgpState::Established,
            ),
            (
                BgpState::OpenConfirm,
                BgpEvent::NotificationReceived,
                BgpState::Idle,
            ),
            // From Established
            (BgpState::Established, BgpEvent::ManualStop, BgpState::Idle),
            (
                BgpState::Established,
                BgpEvent::HoldTimerExpires,
                BgpState::Idle,
            ),
            (
                BgpState::Established,
                BgpEvent::KeepaliveTimerExpires,
                BgpState::Established,
            ),
            (
                BgpState::Established,
                BgpEvent::TcpConnectionFails,
                BgpState::Idle,
            ),
            (
                BgpState::Established,
                BgpEvent::BgpKeepaliveReceived,
                BgpState::Established,
            ),
            (
                BgpState::Established,
                BgpEvent::BgpUpdateReceived,
                BgpState::Established,
            ),
            (
                BgpState::Established,
                BgpEvent::NotificationReceived,
                BgpState::Idle,
            ),
        ];

        for (initial_state, event, expected_state) in test_cases {
            let mut fsm = Fsm::with_state(initial_state);
            let new_state = fsm.process_event(event);

            assert_eq!(
                new_state, expected_state,
                "Failed transition: {:?} + {:?} should -> {:?}, got {:?}",
                initial_state, event, expected_state, new_state
            );
            assert_eq!(fsm.state(), expected_state);
        }
    }
}
