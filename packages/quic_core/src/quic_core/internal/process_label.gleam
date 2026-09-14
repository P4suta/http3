//// Fixed, package-private process identities for optional BEAM diagnostics.
////
//// Roles deliberately carry no runtime fields. In particular, peer names,
//// addresses, ports, connection IDs, stream IDs, SNI, and certificate data
//// cannot reach the process dictionary through this module.

/// A QUIC runtime process role with a fixed, non-secret label.
pub type Role {
  Client
  Listener
  Connection
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
    Client -> "quic_core.client"
    Listener -> "quic_core.listener"
    Connection -> "quic_core.connection"
    ConnectCandidate -> "quic_core.connect_candidate"
    DnsResolver -> "quic_core.dns_resolver"
    UdpRelay -> "quic_core.udp_relay"
    ReplayGuard -> "quic_core.replay_guard"
    QlogWriter -> "quic_core.qlog_writer"
  }
}

/// Return every allowlisted role for direct package tests.
pub fn all() -> List(Role) {
  [
    Client,
    Listener,
    Connection,
    ConnectCandidate,
    DnsResolver,
    UdpRelay,
    ReplayGuard,
    QlogWriter,
  ]
}

/// Read the calling process label for direct package tests.
@external(erlang, "quic_core_process_label_ffi", "current")
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
    Connection -> 8
  }
}

@external(erlang, "quic_core_process_label_ffi", "set_role")
fn set_role(role: Int) -> Nil
