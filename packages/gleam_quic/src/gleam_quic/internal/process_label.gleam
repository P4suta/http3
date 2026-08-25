//// Fixed, package-private process identities for optional BEAM diagnostics.
////
//// Roles deliberately carry no runtime fields. In particular, peer names,
//// addresses, ports, connection IDs, stream IDs, SNI, and certificate data
//// cannot reach the process dictionary through this module.

/// A QUIC runtime process role with a fixed, non-secret label.
pub type Role {
  Client
  Listener
  ConnectCandidate
  DnsResolver
  UdpRelay
  ReplayGuard
  QlogWriter
}

/// Label the calling process with one allowlisted role.
pub fn set(role: Role) -> Nil {
  set_role(role_code(role))
}

/// Return the fixed diagnostic label for a role.
pub fn name(role: Role) -> String {
  case role {
    Client -> "gleam_quic.client"
    Listener -> "gleam_quic.listener"
    ConnectCandidate -> "gleam_quic.connect_candidate"
    DnsResolver -> "gleam_quic.dns_resolver"
    UdpRelay -> "gleam_quic.udp_relay"
    ReplayGuard -> "gleam_quic.replay_guard"
    QlogWriter -> "gleam_quic.qlog_writer"
  }
}

/// Return every allowlisted role for direct package tests.
pub fn all() -> List(Role) {
  [
    Client,
    Listener,
    ConnectCandidate,
    DnsResolver,
    UdpRelay,
    ReplayGuard,
    QlogWriter,
  ]
}

/// Read the calling process label for direct package tests.
@external(erlang, "gleam_quic_process_label_ffi", "current")
pub fn current() -> String

fn role_code(role: Role) -> Int {
  case role {
    Client -> 1
    Listener -> 2
    ConnectCandidate -> 3
    DnsResolver -> 4
    UdpRelay -> 5
    ReplayGuard -> 6
    QlogWriter -> 7
  }
}

@external(erlang, "gleam_quic_process_label_ffi", "set_role")
fn set_role(role: Int) -> Nil
