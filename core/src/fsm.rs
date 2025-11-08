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

/// Result of a state transition
#[derive(Debug)]
pub struct StateTransition {
    /// New state after transition
    pub new_state: BgpState,

    /// Actions to perform as result of transition
    pub actions: Vec<FsmAction>,
}

/// Actions that should be performed as result of state transitions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmAction {
    /// Initialize all BGP resources
    InitializeResources,

    /// Release all BGP resources
    ReleaseResources,

    /// Start ConnectRetry timer
    StartConnectRetryTimer,

    /// Stop ConnectRetry timer
    StopConnectRetryTimer,

    /// Initiate TCP connection
    InitiateTcpConnection,

    /// Close TCP connection
    CloseTcpConnection,

    /// Send OPEN message
    SendOpen,

    /// Send KEEPALIVE message
    SendKeepalive,

    /// Send NOTIFICATION message with error code
    SendNotification,

    /// Start Hold timer
    StartHoldTimer,

    /// Reset Hold timer
    ResetHoldTimer,

    /// Start Keepalive timer
    StartKeepaliveTimer,
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

    /// Process an event and return the state transition
    ///
    /// This implements the state machine logic from RFC 4271 Section 8.2.2
    pub fn process_event(&mut self, event: BgpEvent) -> StateTransition {
        let transition = match (self.state, event) {
            // ===== Idle State =====
            (BgpState::Idle, BgpEvent::ManualStart) => StateTransition {
                new_state: BgpState::Connect,
                actions: vec![
                    FsmAction::InitializeResources,
                    FsmAction::StartConnectRetryTimer,
                    FsmAction::InitiateTcpConnection,
                ],
            },

            // ===== Connect State =====
            (BgpState::Connect, BgpEvent::ManualStop) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            (BgpState::Connect, BgpEvent::ConnectRetryTimerExpires) => StateTransition {
                new_state: BgpState::Connect,
                actions: vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::StartConnectRetryTimer,
                    FsmAction::InitiateTcpConnection,
                ],
            },

            (BgpState::Connect, BgpEvent::TcpConnectionConfirmed) => StateTransition {
                new_state: BgpState::OpenSent,
                actions: vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::SendOpen,
                    FsmAction::StartHoldTimer,
                ],
            },

            (BgpState::Connect, BgpEvent::TcpConnectionFails) => StateTransition {
                new_state: BgpState::Active,
                actions: vec![FsmAction::StartConnectRetryTimer],
            },

            // ===== Active State =====
            (BgpState::Active, BgpEvent::ManualStop) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            (BgpState::Active, BgpEvent::ConnectRetryTimerExpires) => StateTransition {
                new_state: BgpState::Connect,
                actions: vec![
                    FsmAction::StartConnectRetryTimer,
                    FsmAction::InitiateTcpConnection,
                ],
            },

            (BgpState::Active, BgpEvent::TcpConnectionConfirmed) => StateTransition {
                new_state: BgpState::OpenSent,
                actions: vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::SendOpen,
                    FsmAction::StartHoldTimer,
                ],
            },

            // ===== OpenSent State =====
            (BgpState::OpenSent, BgpEvent::ManualStop) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::SendNotification,
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            (BgpState::OpenSent, BgpEvent::HoldTimerExpires) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::SendNotification,
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            (BgpState::OpenSent, BgpEvent::TcpConnectionFails) => StateTransition {
                new_state: BgpState::Active,
                actions: vec![
                    FsmAction::CloseTcpConnection,
                    FsmAction::StartConnectRetryTimer,
                ],
            },

            (BgpState::OpenSent, BgpEvent::BgpOpenReceived) => StateTransition {
                new_state: BgpState::OpenConfirm,
                actions: vec![
                    FsmAction::ResetHoldTimer,
                    FsmAction::SendKeepalive,
                    FsmAction::StartKeepaliveTimer,
                ],
            },

            (BgpState::OpenSent, BgpEvent::NotificationReceived) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            // ===== OpenConfirm State =====
            (BgpState::OpenConfirm, BgpEvent::ManualStop) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::SendNotification,
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            (BgpState::OpenConfirm, BgpEvent::HoldTimerExpires) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::SendNotification,
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            (BgpState::OpenConfirm, BgpEvent::KeepaliveTimerExpires) => StateTransition {
                new_state: BgpState::OpenConfirm,
                actions: vec![FsmAction::SendKeepalive, FsmAction::StartKeepaliveTimer],
            },

            (BgpState::OpenConfirm, BgpEvent::TcpConnectionFails) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::ReleaseResources,
                ],
            },

            (BgpState::OpenConfirm, BgpEvent::BgpKeepaliveReceived) => StateTransition {
                new_state: BgpState::Established,
                actions: vec![FsmAction::ResetHoldTimer],
            },

            (BgpState::OpenConfirm, BgpEvent::NotificationReceived) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            // ===== Established State =====
            (BgpState::Established, BgpEvent::ManualStop) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::SendNotification,
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            (BgpState::Established, BgpEvent::HoldTimerExpires) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::SendNotification,
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            (BgpState::Established, BgpEvent::KeepaliveTimerExpires) => StateTransition {
                new_state: BgpState::Established,
                actions: vec![FsmAction::SendKeepalive, FsmAction::StartKeepaliveTimer],
            },

            (BgpState::Established, BgpEvent::TcpConnectionFails) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::ReleaseResources,
                ],
            },

            (BgpState::Established, BgpEvent::BgpKeepaliveReceived) => StateTransition {
                new_state: BgpState::Established,
                actions: vec![FsmAction::ResetHoldTimer],
            },

            (BgpState::Established, BgpEvent::BgpUpdateReceived) => StateTransition {
                new_state: BgpState::Established,
                actions: vec![FsmAction::ResetHoldTimer],
            },

            (BgpState::Established, BgpEvent::NotificationReceived) => StateTransition {
                new_state: BgpState::Idle,
                actions: vec![
                    FsmAction::StopConnectRetryTimer,
                    FsmAction::CloseTcpConnection,
                    FsmAction::ReleaseResources,
                ],
            },

            // Default: Invalid event for current state, stay in same state
            _ => StateTransition {
                new_state: self.state,
                actions: vec![],
            },
        };

        // Update state
        self.state = transition.new_state;

        transition
    }

    /// Check if FSM is in Established state
    pub fn is_established(&self) -> bool {
        self.state == BgpState::Established
    }

    /// Check if message type is valid for current state
    pub fn is_message_valid(&self, event: BgpEvent) -> bool {
        match (self.state, event) {
            // OPEN messages are only valid in OpenSent
            (BgpState::OpenSent, BgpEvent::BgpOpenReceived) => true,

            // KEEPALIVE messages are valid in OpenConfirm and Established
            (BgpState::OpenConfirm, BgpEvent::BgpKeepaliveReceived) => true,
            (BgpState::Established, BgpEvent::BgpKeepaliveReceived) => true,

            // UPDATE messages are only valid in Established
            (BgpState::Established, BgpEvent::BgpUpdateReceived) => true,

            // NOTIFICATION messages are valid in any state (except Idle)
            (state, BgpEvent::NotificationReceived) if state != BgpState::Idle => true,

            _ => false,
        }
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
        let transition = fsm.process_event(BgpEvent::ManualStart);

        assert_eq!(transition.new_state, BgpState::Connect);
        assert_eq!(fsm.state(), BgpState::Connect);
        assert!(transition.actions.contains(&FsmAction::InitializeResources));
        assert!(transition
            .actions
            .contains(&FsmAction::StartConnectRetryTimer));
        assert!(transition
            .actions
            .contains(&FsmAction::InitiateTcpConnection));
    }

    #[test]
    fn test_successful_connection_establishment() {
        let mut fsm = Fsm::new();

        // Idle -> Connect
        fsm.process_event(BgpEvent::ManualStart);
        assert_eq!(fsm.state(), BgpState::Connect);

        // Connect -> OpenSent
        let transition = fsm.process_event(BgpEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), BgpState::OpenSent);
        assert!(transition.actions.contains(&FsmAction::SendOpen));

        // OpenSent -> OpenConfirm
        let transition = fsm.process_event(BgpEvent::BgpOpenReceived);
        assert_eq!(fsm.state(), BgpState::OpenConfirm);
        assert!(transition.actions.contains(&FsmAction::SendKeepalive));

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
    fn test_message_validation() {
        let mut fsm = Fsm::new();

        // UPDATE not valid in Idle
        assert!(!fsm.is_message_valid(BgpEvent::BgpUpdateReceived));

        // Move to OpenSent
        fsm.process_event(BgpEvent::ManualStart);
        fsm.process_event(BgpEvent::TcpConnectionConfirmed);

        // OPEN valid in OpenSent
        assert!(fsm.is_message_valid(BgpEvent::BgpOpenReceived));

        // Move to Established
        fsm.process_event(BgpEvent::BgpOpenReceived);
        fsm.process_event(BgpEvent::BgpKeepaliveReceived);

        // UPDATE valid in Established
        assert!(fsm.is_message_valid(BgpEvent::BgpUpdateReceived));
        assert!(fsm.is_message_valid(BgpEvent::BgpKeepaliveReceived));
    }

    #[test]
    fn test_hold_timer_expiry() {
        let mut fsm = Fsm::new();

        // Move to OpenSent
        fsm.process_event(BgpEvent::ManualStart);
        fsm.process_event(BgpEvent::TcpConnectionConfirmed);

        // Hold timer expiry should go to Idle
        let transition = fsm.process_event(BgpEvent::HoldTimerExpires);
        assert_eq!(fsm.state(), BgpState::Idle);
        assert!(transition.actions.contains(&FsmAction::SendNotification));
    }
}
