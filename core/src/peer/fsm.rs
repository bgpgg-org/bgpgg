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

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::bgp::msg_notification::{CeaseSubcode, NotifcationMessage};

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

/// Parameters from received BGP OPEN message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgpOpenParams {
    pub peer_asn: u16,
    pub peer_hold_time: u16,
    pub peer_bgp_id: u32,
    pub local_asn: u16,
    pub local_hold_time: u16,
}

/// BGP FSM events as defined in RFC 4271 Section 8.1
/// Events now carry necessary data for the FSM to send messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmEvent {
    /// Event 1: ManualStart
    ManualStart,
    /// Event 2: ManualStop
    ManualStop,
    /// Event 3: AutomaticStart - triggered when IdleHoldTimer expires
    AutomaticStart,
    /// Event 4: ManualStart_with_PassiveTcpEstablishment
    ManualStartPassive,
    /// Event 5: AutomaticStart_with_PassiveTcpEstablishment
    AutomaticStartPassive,
    /// Event 8: AutomaticStop - automatic stop based on implementation logic (e.g., max prefix)
    AutomaticStop(CeaseSubcode),
    /// Event 9: ConnectRetryTimerExpires
    ConnectRetryTimerExpires,
    /// Event 10: HoldTimer_Expires
    HoldTimerExpires,
    /// Event 11: KeepaliveTimer_Expires
    KeepaliveTimerExpires,
    /// Event 12: DelayOpenTimerExpires (RFC 4271 8.1.3)
    DelayOpenTimerExpires,
    /// Event 13: IdleHoldTimer_Expires
    IdleHoldTimerExpires,
    /// TCP connection is confirmed, ready to send OPEN
    TcpConnectionConfirmed,
    TcpConnectionFails,
    /// Event 19: BGPOpen - OPEN message received (generic)
    BgpOpenReceived(BgpOpenParams),
    /// Event 20: BGPOpen with DelayOpenTimer running
    BgpOpenWithDelayOpenTimer(BgpOpenParams),
    /// Event 21: BGP Message Header Error - carries NOTIFICATION to send
    BgpHeaderErr(NotifcationMessage),
    /// Event 22: BGP OPEN Message Error - carries NOTIFICATION to send
    BgpOpenMsgErr(NotifcationMessage),
    BgpKeepaliveReceived,
    BgpUpdateReceived,
    /// Event 28: UPDATE Message Error - carries NOTIFICATION to send
    BgpUpdateMsgErr(NotifcationMessage),
    /// Event 24: NotifMsgVerErr - NOTIFICATION with version error
    NotifMsgVerErr,
    /// Event 25: NotifMsg - NOTIFICATION without version error
    NotifMsg,
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

    /// DelayOpen timer value (RFC 4271 8.1.3). None means DelayOpen disabled.
    pub delay_open_time: Option<Duration>,

    /// Last time ConnectRetry timer was started
    pub connect_retry_started: Option<Instant>,

    /// Last time Hold timer was started/reset
    pub hold_timer_started: Option<Instant>,

    /// Last time Keepalive timer was started/reset
    pub keepalive_timer_started: Option<Instant>,

    /// Last time DelayOpen timer was started
    pub delay_open_timer_started: Option<Instant>,
}

impl FsmTimers {
    pub fn new(delay_open_time: Option<Duration>) -> Self {
        Self {
            connect_retry_time: Duration::from_secs(120),
            hold_time: Duration::from_secs(180),
            keepalive_time: Duration::from_secs(60), // 1/3 of hold_time
            delay_open_time,
            connect_retry_started: None,
            hold_timer_started: None,
            keepalive_timer_started: None,
            delay_open_timer_started: None,
        }
    }
}

impl Default for FsmTimers {
    fn default() -> Self {
        Self::new(None)
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

    /// Set initial hold time (RFC 4271: 4 minutes suggested for OpenSent state)
    pub fn set_initial_hold_time(&mut self, hold_time: Duration) {
        self.hold_time = hold_time;
    }

    /// Check if DelayOpen timer has expired
    pub fn delay_open_timer_expired(&self) -> bool {
        match (self.delay_open_timer_started, self.delay_open_time) {
            (Some(started), Some(delay)) => started.elapsed() >= delay,
            _ => false,
        }
    }

    /// Start DelayOpen timer
    pub fn start_delay_open_timer(&mut self) {
        self.delay_open_timer_started = Some(Instant::now());
    }

    /// Stop DelayOpen timer
    pub fn stop_delay_open_timer(&mut self) {
        self.delay_open_timer_started = None;
    }

    /// Check if DelayOpen timer is running
    pub fn delay_open_timer_running(&self) -> bool {
        self.delay_open_timer_started.is_some()
    }
}

/// BGP Finite State Machine
pub struct Fsm {
    /// Current state
    state: BgpState,

    /// FSM timers
    pub timers: FsmTimers,

    /// ConnectRetryCounter (RFC 4271 8.2.2)
    pub connect_retry_counter: u32,

    /// Local BGP configuration
    local_asn: u16,
    local_hold_time: u16,
    local_bgp_id: u32,
    local_addr: Ipv4Addr,

    /// Passive mode: if true, wait for incoming connections (Active state)
    /// if false, initiate connections (Connect state)
    passive_mode: bool,
}

impl Fsm {
    /// Create a new FSM in Idle state (RFC 4271 8.2.2).
    pub fn new(
        local_asn: u16,
        local_hold_time: u16,
        local_bgp_id: u32,
        local_addr: Ipv4Addr,
        delay_open_time: Option<Duration>,
        passive_mode: bool,
    ) -> Self {
        Fsm {
            state: BgpState::Idle,
            timers: FsmTimers::new(delay_open_time),
            connect_retry_counter: 0,
            local_asn,
            local_hold_time,
            local_bgp_id,
            local_addr,
            passive_mode,
        }
    }

    /// Create a new FSM with a specific initial state (for testing)
    #[cfg(test)]
    pub fn with_state(
        state: BgpState,
        local_asn: u16,
        local_hold_time: u16,
        local_bgp_id: u32,
        local_addr: Ipv4Addr,
        passive_mode: bool,
    ) -> Self {
        Fsm {
            state,
            timers: FsmTimers::default(),
            connect_retry_counter: 0,
            local_asn,
            local_hold_time,
            local_bgp_id,
            local_addr,
            passive_mode,
        }
    }

    /// Get current state
    pub fn state(&self) -> BgpState {
        self.state
    }

    /// Get local ASN
    pub fn local_asn(&self) -> u16 {
        self.local_asn
    }

    /// Get local hold time
    pub fn local_hold_time(&self) -> u16 {
        self.local_hold_time
    }

    /// Get local BGP ID
    pub fn local_bgp_id(&self) -> u32 {
        self.local_bgp_id
    }

    /// Get local address
    pub fn local_addr(&self) -> Ipv4Addr {
        self.local_addr
    }

    /// Reset ConnectRetryCounter to zero (RFC 4271 8.2.2)
    pub fn reset_connect_retry_counter(&mut self) {
        self.connect_retry_counter = 0;
    }

    /// Increment ConnectRetryCounter (RFC 4271 8.2.2)
    pub fn increment_connect_retry_counter(&mut self) {
        self.connect_retry_counter += 1;
    }

    /// Handle an event and return new state.
    ///
    /// This implements the state machine logic from RFC 4271 Section 8.2.2.
    /// Error handling (notifications, cleanup) is done by the caller based on state transitions.
    pub fn handle_event(&mut self, event: &FsmEvent) -> BgpState {
        let new_state = match (&self.state, event) {
            // ===== Idle State =====
            // Event 1, 3: ManualStart/AutomaticStart -> Connect
            (BgpState::Idle, FsmEvent::ManualStart) => BgpState::Connect,
            (BgpState::Idle, FsmEvent::AutomaticStart) => BgpState::Connect,
            // Event 4: ManualStartPassive -> Active (RFC 4271 8.2.2)
            (BgpState::Idle, FsmEvent::ManualStartPassive) => BgpState::Active,
            // Event 5: AutomaticStartPassive -> Active (RFC 4271 8.2.2)
            (BgpState::Idle, FsmEvent::AutomaticStartPassive) => BgpState::Active,
            // Event 13: IdleHoldTimer expires
            (BgpState::Idle, FsmEvent::IdleHoldTimerExpires) => {
                if self.passive_mode {
                    BgpState::Active
                } else {
                    BgpState::Connect
                }
            }

            // ===== Connect State =====
            (BgpState::Connect, FsmEvent::ManualStop) => BgpState::Idle,
            (BgpState::Connect, FsmEvent::ConnectRetryTimerExpires) => BgpState::Connect,
            (BgpState::Connect, FsmEvent::DelayOpenTimerExpires) => BgpState::OpenSent,
            (BgpState::Connect, FsmEvent::TcpConnectionConfirmed { .. }) => BgpState::OpenSent,
            // RFC 4271 8.2.2 Event 18: If DelayOpenTimer running -> Active, else -> Idle
            (BgpState::Connect, FsmEvent::TcpConnectionFails) => {
                if self.timers.delay_open_timer_running() {
                    BgpState::Active
                } else {
                    BgpState::Idle
                }
            }
            // RFC 4271 8.2.2 Event 19: BGPOpen without DelayOpenTimer -> Idle (any other event)
            (BgpState::Connect, FsmEvent::BgpOpenReceived(_)) => BgpState::Idle,
            // RFC 4271 8.2.2 Event 20: BGPOpen with DelayOpenTimer running -> OpenConfirm
            (BgpState::Connect, FsmEvent::BgpOpenWithDelayOpenTimer(_)) => BgpState::OpenConfirm,
            // RFC 4271 Events 21, 22: BGP header/OPEN message errors -> Idle
            (BgpState::Connect, FsmEvent::BgpHeaderErr(_)) => BgpState::Idle,
            (BgpState::Connect, FsmEvent::BgpOpenMsgErr(_)) => BgpState::Idle,
            // RFC 4271 Event 24: NOTIFICATION with version error -> Idle
            (BgpState::Connect, FsmEvent::NotifMsgVerErr) => BgpState::Idle,
            // RFC 4271 Event 25: NOTIFICATION without version error -> Idle
            (BgpState::Connect, FsmEvent::NotifMsg) => BgpState::Idle,
            // RFC 4271 8.2.2: Any other events (8, 10-11, 13, 26-28) -> Idle (no NOTIFICATION)
            (BgpState::Connect, FsmEvent::AutomaticStop(_))
            | (BgpState::Connect, FsmEvent::HoldTimerExpires)
            | (BgpState::Connect, FsmEvent::KeepaliveTimerExpires)
            | (BgpState::Connect, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Connect, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Connect, FsmEvent::BgpUpdateReceived)
            | (BgpState::Connect, FsmEvent::BgpUpdateMsgErr(_)) => BgpState::Idle,

            // ===== Active State =====
            (BgpState::Active, FsmEvent::ManualStop) => BgpState::Idle,
            (BgpState::Active, FsmEvent::ConnectRetryTimerExpires) => BgpState::Connect,
            (BgpState::Active, FsmEvent::DelayOpenTimerExpires) => BgpState::OpenSent,
            (BgpState::Active, FsmEvent::TcpConnectionConfirmed { .. }) => BgpState::OpenSent,
            // RFC 4271 Events 21, 22: BGP header/OPEN message errors -> Idle
            (BgpState::Active, FsmEvent::BgpHeaderErr(_)) => BgpState::Idle,
            (BgpState::Active, FsmEvent::BgpOpenMsgErr(_)) => BgpState::Idle,
            // RFC 4271 Event 24: NOTIFICATION with version error -> Idle
            (BgpState::Active, FsmEvent::NotifMsgVerErr) => BgpState::Idle,
            // RFC 4271 Event 25: NOTIFICATION without version error -> Idle
            (BgpState::Active, FsmEvent::NotifMsg) => BgpState::Idle,
            // RFC 4271 8.2.2: Any other events (8, 10-11, 13, 19, 26-28) in Active state -> Idle (no NOTIFICATION)
            (BgpState::Active, FsmEvent::AutomaticStop(_))
            | (BgpState::Active, FsmEvent::HoldTimerExpires)
            | (BgpState::Active, FsmEvent::KeepaliveTimerExpires)
            | (BgpState::Active, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Active, FsmEvent::BgpOpenReceived(_))
            | (BgpState::Active, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Active, FsmEvent::BgpUpdateReceived)
            | (BgpState::Active, FsmEvent::BgpUpdateMsgErr(_)) => BgpState::Idle,

            // ===== OpenSent State =====
            (BgpState::OpenSent, FsmEvent::ManualStop) => BgpState::Idle,
            (BgpState::OpenSent, FsmEvent::AutomaticStop(_)) => BgpState::Idle,
            (BgpState::OpenSent, FsmEvent::HoldTimerExpires) => BgpState::Idle,
            (BgpState::OpenSent, FsmEvent::TcpConnectionFails) => BgpState::Active,
            (BgpState::OpenSent, FsmEvent::BgpOpenReceived(_)) => BgpState::OpenConfirm,
            (BgpState::OpenSent, FsmEvent::BgpOpenWithDelayOpenTimer(_)) => BgpState::OpenConfirm,
            (BgpState::OpenSent, FsmEvent::BgpUpdateMsgErr(_)) => BgpState::Idle,
            (BgpState::OpenSent, FsmEvent::NotifMsgVerErr) => BgpState::Idle,
            (BgpState::OpenSent, FsmEvent::NotifMsg) => BgpState::Idle,

            // ===== OpenConfirm State =====
            (BgpState::OpenConfirm, FsmEvent::ManualStop) => BgpState::Idle,
            (BgpState::OpenConfirm, FsmEvent::AutomaticStop(_)) => BgpState::Idle,
            (BgpState::OpenConfirm, FsmEvent::HoldTimerExpires) => BgpState::Idle,
            (BgpState::OpenConfirm, FsmEvent::KeepaliveTimerExpires) => BgpState::OpenConfirm,
            (BgpState::OpenConfirm, FsmEvent::TcpConnectionFails) => BgpState::Idle,
            (BgpState::OpenConfirm, FsmEvent::BgpKeepaliveReceived) => BgpState::Established,
            (BgpState::OpenConfirm, FsmEvent::BgpUpdateMsgErr(_)) => BgpState::Idle,
            (BgpState::OpenConfirm, FsmEvent::NotifMsgVerErr) => BgpState::Idle,
            (BgpState::OpenConfirm, FsmEvent::NotifMsg) => BgpState::Idle,
            // RFC 4271 6.6: Events 9, 27 in OpenConfirm -> FSM Error
            (BgpState::OpenConfirm, FsmEvent::ConnectRetryTimerExpires)
            | (BgpState::OpenConfirm, FsmEvent::BgpUpdateReceived) => BgpState::Idle,

            // ===== Established State =====
            (BgpState::Established, FsmEvent::ManualStop) => BgpState::Idle,
            (BgpState::Established, FsmEvent::AutomaticStop(_)) => BgpState::Idle,
            (BgpState::Established, FsmEvent::HoldTimerExpires) => BgpState::Idle,
            (BgpState::Established, FsmEvent::KeepaliveTimerExpires) => BgpState::Established,
            (BgpState::Established, FsmEvent::TcpConnectionFails) => BgpState::Idle,
            (BgpState::Established, FsmEvent::BgpKeepaliveReceived) => BgpState::Established,
            (BgpState::Established, FsmEvent::BgpUpdateReceived) => BgpState::Established,
            (BgpState::Established, FsmEvent::BgpUpdateMsgErr(_)) => BgpState::Idle,
            (BgpState::Established, FsmEvent::NotifMsgVerErr) => BgpState::Idle,
            (BgpState::Established, FsmEvent::NotifMsg) => BgpState::Idle,
            // RFC 4271 6.6: Event 9 in Established -> FSM Error
            (BgpState::Established, FsmEvent::ConnectRetryTimerExpires) => BgpState::Idle,

            // Default: Invalid event for current state, stay in same state
            _ => self.state,
        };

        self.state = new_state;
        new_state
    }

    /// Check if FSM is in Established state
    pub fn is_established(&self) -> bool {
        self.state == BgpState::Established
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_LOCAL_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

    #[test]
    fn test_initial_state() {
        let fsm = Fsm::with_state(
            BgpState::Connect,
            65000,
            180,
            0x01010101,
            TEST_LOCAL_ADDR,
            false,
        );
        assert_eq!(fsm.state(), BgpState::Connect);
    }

    #[test]
    fn test_tcp_connection_confirmed() {
        let mut fsm = Fsm::with_state(
            BgpState::Connect,
            65000,
            180,
            0x01010101,
            TEST_LOCAL_ADDR,
            false,
        );

        // Connect -> OpenSent
        let new_state = fsm.handle_event(&FsmEvent::TcpConnectionConfirmed);
        assert_eq!(new_state, BgpState::OpenSent);
        assert_eq!(fsm.state(), BgpState::OpenSent);
    }

    #[test]
    fn test_successful_connection_establishment() {
        let mut fsm = Fsm::with_state(
            BgpState::Connect,
            65000,
            180,
            0x01010101,
            TEST_LOCAL_ADDR,
            false,
        );

        // Connect -> OpenSent
        fsm.handle_event(&FsmEvent::TcpConnectionConfirmed);
        assert_eq!(fsm.state(), BgpState::OpenSent);

        // OpenSent -> OpenConfirm
        fsm.handle_event(&FsmEvent::BgpOpenReceived(BgpOpenParams {
            peer_asn: 65001,
            peer_hold_time: 180,
            peer_bgp_id: 0x02020202,
            local_asn: 65000,
            local_hold_time: 180,
        }));
        assert_eq!(fsm.state(), BgpState::OpenConfirm);

        // OpenConfirm -> Established
        fsm.handle_event(&FsmEvent::BgpKeepaliveReceived);
        assert_eq!(fsm.state(), BgpState::Established);
        assert!(fsm.is_established());
    }

    #[test]
    fn test_connection_failure_handling() {
        {
            // RFC 4271 Event 18: TcpConnectionFails without DelayOpenTimer -> Idle
            let mut fsm = Fsm::with_state(
                BgpState::Connect,
                65000,
                180,
                0x01010101,
                TEST_LOCAL_ADDR,
                false,
            );
            fsm.handle_event(&FsmEvent::TcpConnectionFails);
            assert_eq!(fsm.state(), BgpState::Idle);
        }

        {
            // RFC 4271 Event 18: TcpConnectionFails with DelayOpenTimer running -> Active
            let mut fsm = Fsm::with_state(
                BgpState::Connect,
                65000,
                180,
                0x01010101,
                TEST_LOCAL_ADDR,
                false,
            );
            fsm.timers.start_delay_open_timer();
            fsm.handle_event(&FsmEvent::TcpConnectionFails);
            assert_eq!(fsm.state(), BgpState::Active);

            // Active -> Connect (retry)
            fsm.handle_event(&FsmEvent::ConnectRetryTimerExpires);
            assert_eq!(fsm.state(), BgpState::Connect);
        }
    }

    #[test]
    fn test_hold_timer_expiry() {
        let mut fsm = Fsm::with_state(
            BgpState::Connect,
            65000,
            180,
            0x01010101,
            TEST_LOCAL_ADDR,
            false,
        );

        // Move to OpenSent
        fsm.handle_event(&FsmEvent::TcpConnectionConfirmed);

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
            (BgpState::Idle, FsmEvent::AutomaticStart, BgpState::Connect),
            (
                BgpState::Idle,
                FsmEvent::ManualStartPassive,
                BgpState::Active,
            ),
            (
                BgpState::Idle,
                FsmEvent::AutomaticStartPassive,
                BgpState::Active,
            ),
            // From Connect
            (BgpState::Connect, FsmEvent::ManualStop, BgpState::Idle),
            (
                BgpState::Connect,
                FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached),
                BgpState::Idle,
            ),
            (
                BgpState::Connect,
                FsmEvent::ConnectRetryTimerExpires,
                BgpState::Connect,
            ),
            (
                BgpState::Connect,
                FsmEvent::TcpConnectionConfirmed,
                BgpState::OpenSent,
            ),
            // DelayOpen: Connect + DelayOpenTimerExpires -> OpenSent
            (
                BgpState::Connect,
                FsmEvent::DelayOpenTimerExpires,
                BgpState::OpenSent,
            ),
            // DelayOpen: Connect + BgpOpenWithDelayOpenTimer -> OpenConfirm (peer sent OPEN first)
            (
                BgpState::Connect,
                FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
                    peer_asn: 65001,
                    peer_hold_time: 180,
                    peer_bgp_id: 0x02020202,
                    local_asn: 65000,
                    local_hold_time: 180,
                }),
                BgpState::OpenConfirm,
            ),
            // From Active
            (BgpState::Active, FsmEvent::ManualStop, BgpState::Idle),
            (
                BgpState::Active,
                FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached),
                BgpState::Idle,
            ),
            (
                BgpState::Active,
                FsmEvent::ConnectRetryTimerExpires,
                BgpState::Connect,
            ),
            (
                BgpState::Active,
                FsmEvent::DelayOpenTimerExpires,
                BgpState::OpenSent,
            ),
            (
                BgpState::Active,
                FsmEvent::TcpConnectionConfirmed,
                BgpState::OpenSent,
            ),
            // From OpenSent
            (BgpState::OpenSent, FsmEvent::ManualStop, BgpState::Idle),
            (
                BgpState::OpenSent,
                FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached),
                BgpState::Idle,
            ),
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
                FsmEvent::BgpOpenReceived(BgpOpenParams {
                    peer_asn: 65001,
                    peer_hold_time: 180,
                    peer_bgp_id: 0x02020202,
                    local_asn: 65000,
                    local_hold_time: 180,
                }),
                BgpState::OpenConfirm,
            ),
            (BgpState::OpenSent, FsmEvent::NotifMsg, BgpState::Idle),
            // From OpenConfirm
            (BgpState::OpenConfirm, FsmEvent::ManualStop, BgpState::Idle),
            (
                BgpState::OpenConfirm,
                FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached),
                BgpState::Idle,
            ),
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
            (BgpState::OpenConfirm, FsmEvent::NotifMsg, BgpState::Idle),
            // From Established
            (BgpState::Established, FsmEvent::ManualStop, BgpState::Idle),
            (
                BgpState::Established,
                FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached),
                BgpState::Idle,
            ),
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
            (BgpState::Established, FsmEvent::NotifMsg, BgpState::Idle),
        ];

        for (initial_state, event, expected_state) in test_cases {
            let mut fsm = Fsm::with_state(
                initial_state,
                65000,
                180,
                0x01010101,
                TEST_LOCAL_ADDR,
                false,
            );
            let new_state = fsm.handle_event(&event);

            assert_eq!(
                new_state, expected_state,
                "Failed transition: {:?} + {:?} should -> {:?}, got {:?}",
                initial_state, event, expected_state, new_state
            );
            assert_eq!(fsm.state(), expected_state);
        }
    }

    #[test]
    fn test_fsm_errors() {
        // FSM error events transition to Idle (RFC 4271 6.6)
        // Error handling (notifications) is done by states.rs
        let test_cases = vec![
            // OpenConfirm + UPDATE -> Idle (Event 27)
            (BgpState::OpenConfirm, FsmEvent::BgpUpdateReceived),
            // OpenConfirm + ConnectRetryTimerExpires -> Idle (Event 9)
            (BgpState::OpenConfirm, FsmEvent::ConnectRetryTimerExpires),
            // Established + ConnectRetryTimerExpires -> Idle (Event 9)
            (BgpState::Established, FsmEvent::ConnectRetryTimerExpires),
        ];

        for (initial_state, event) in test_cases {
            let mut fsm = Fsm::with_state(
                initial_state,
                65000,
                180,
                0x01010101,
                TEST_LOCAL_ADDR,
                false,
            );
            let new_state = fsm.handle_event(&event);

            assert_eq!(
                new_state,
                BgpState::Idle,
                "{:?} + {:?} should transition to Idle",
                initial_state,
                event
            );
        }
    }

    #[test]
    fn test_reset_connect_retry_counter() {
        let mut fsm = Fsm::new(65000, 180, 0x01010101, TEST_LOCAL_ADDR, None, false);

        fsm.connect_retry_counter = 5;
        assert_eq!(fsm.connect_retry_counter, 5);

        fsm.reset_connect_retry_counter();
        assert_eq!(fsm.connect_retry_counter, 0);
    }

    #[test]
    fn test_idle_hold_timer_expires() {
        // Passive mode: Idle -> Active
        let mut fsm = Fsm::new(65000, 180, 0x01010101, TEST_LOCAL_ADDR, None, true);
        let new_state = fsm.handle_event(&FsmEvent::IdleHoldTimerExpires);
        assert_eq!(new_state, BgpState::Active);

        // Active mode: Idle -> Connect
        let mut fsm = Fsm::new(65000, 180, 0x01010101, TEST_LOCAL_ADDR, None, false);
        let new_state = fsm.handle_event(&FsmEvent::IdleHoldTimerExpires);
        assert_eq!(new_state, BgpState::Connect);
    }

    #[test]
    fn test_update_msg_err() {
        use crate::bgp::msg_notification::{BgpError, NotifcationMessage, UpdateMessageError};

        let notif = NotifcationMessage::new(
            BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
            vec![],
        );

        // All states: UpdateMsgErr -> Idle
        // Notification handling is done in states.rs
        for state in [
            BgpState::Connect,
            BgpState::Active,
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ] {
            let mut fsm = Fsm::with_state(state, 65000, 180, 0x01010101, TEST_LOCAL_ADDR, false);
            let new_state = fsm.handle_event(&FsmEvent::BgpUpdateMsgErr(notif.clone()));
            assert_eq!(new_state, BgpState::Idle);
        }
    }
}
