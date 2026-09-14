//// QUIC server anti-amplification accounting before address validation.

/// Endpoint role determines whether the three-times limit applies.
pub type Role {
  Client
  Server
}

/// Path-local bytes received and sent before validation.
pub opaque type Budget {
  Budget(role: Role, validated: Bool, received: Int, sent: Int)
}

/// Invalid byte accounting or an exhausted anti-amplification budget.
pub type Error {
  InvalidInput
  AmplificationLimited(Int)
}

/// Create a fresh path budget. Clients are not amplification-limited.
pub fn new(role: Role) -> Result(Budget, Error) {
  Ok(Budget(role, role == Client, 0, 0))
}

/// Credit all bytes in successfully received UDP datagrams.
pub fn record_received(
  budget: Budget,
  datagram_bytes: Int,
) -> Result(Budget, Error) {
  case datagram_bytes < 0 {
    True -> Error(InvalidInput)
    False -> Ok(Budget(..budget, received: budget.received + datagram_bytes))
  }
}

/// Debit an outgoing datagram only when the current budget permits it.
pub fn record_sent(
  budget: Budget,
  datagram_bytes: Int,
) -> Result(Budget, Error) {
  case datagram_bytes < 0 {
    True -> Error(InvalidInput)
    False ->
      case can_send(budget, datagram_bytes) {
        True -> Ok(Budget(..budget, sent: budget.sent + datagram_bytes))
        False -> Error(AmplificationLimited(available(budget)))
      }
  }
}

/// Remove the limit after Retry, token, or path validation proves ownership.
pub fn validate(budget: Budget) -> Budget {
  Budget(..budget, validated: True)
}

/// Check one complete datagram against remaining amplification credit.
pub fn can_send(budget: Budget, datagram_bytes: Int) -> Bool {
  datagram_bytes >= 0
  && {
    budget.validated
    || budget.role == Client
    || budget.sent + datagram_bytes <= 3 * budget.received
  }
}

fn available(budget: Budget) -> Int {
  let remaining = 3 * budget.received - budget.sent
  case remaining > 0 {
    True -> remaining
    False -> 0
  }
}
