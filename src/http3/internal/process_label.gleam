//// Fixed, package-private process identities for optional BEAM diagnostics.
////
//// Roles deliberately carry no runtime fields. In particular, peer names,
//// addresses, ports, connection IDs, stream IDs, SNI, and certificate data
//// cannot reach the process dictionary through this module.

/// An HTTP/3 runtime process role with a fixed, non-secret label.
pub type Role {
  Client
  Listener
  ConnectCandidate
}

/// Label the calling process with one allowlisted role.
pub fn set(role: Role) -> Nil {
  set_role(role_code(role))
}

/// Return the fixed diagnostic label for a role.
pub fn name(role: Role) -> String {
  case role {
    Client -> "http3.client"
    Listener -> "http3.listener"
    ConnectCandidate -> "http3.connect_candidate"
  }
}

/// Return every allowlisted role for direct package tests.
pub fn all() -> List(Role) {
  [Client, Listener, ConnectCandidate]
}

/// Read the calling process label for direct package tests.
@external(erlang, "http3_process_label_ffi", "current")
pub fn current() -> String

fn role_code(role: Role) -> Int {
  case role {
    Client -> 1
    Listener -> 2
    ConnectCandidate -> 3
  }
}

@external(erlang, "http3_process_label_ffi", "set_role")
fn set_role(role: Int) -> Nil
