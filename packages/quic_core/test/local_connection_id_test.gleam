import gleam/int
import gleam/option.{None, Some}
import quic_core/internal/connection_id
import quic_core/internal/local_connection_id as local

// The public runtimes always issue routable, non-zero local identifiers.
// This makes the RFC 9000 shared-socket exception for multiple zero-length local connection IDs unreachable by construction.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn local_issuer_requires_a_nonzero_byte_aligned_identifier_test() -> Nil {
  assert local.new(<<>>) == Error(connection_id.InvalidConnectionId)
  assert local.new(<<1:size(1)>>) == Error(connection_id.InvalidConnectionId)
  assert local.new(<<0:168>>) == Error(connection_id.InvalidConnectionId)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn local_issuance_obeys_peer_and_resident_limits_test() -> Nil {
  let assert Ok(issuer) = local.new(<<0:64>>)
  assert local.available(issuer, 2) == 1
  let assert Ok(#(issuer, entry)) = local.issue(issuer, 2, <<1:64>>, <<1:128>>)
  assert entry.sequence == 1
  assert local.issue(issuer, 2, <<2:64>>, <<2:128>>)
    == Error(connection_id.ActiveLimitExceeded(2))
  let assert Ok(#(issuer, _)) = local.issue(issuer, 10_000, <<2:64>>, <<2:128>>)
  let assert Ok(#(issuer, _)) = local.issue(issuer, 10_000, <<3:64>>, <<3:128>>)
  assert local.available(issuer, 10_000) == 0
  assert local.snapshot(issuer) == local.Snapshot(4, 4, 0, 4096)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retirement_is_idempotent_and_cannot_name_the_carrying_destination_test() -> Nil {
  let assert Ok(issuer) = local.new(<<0:64>>)
  let assert Ok(#(issuer, _)) = local.issue(issuer, 2, <<1:64>>, <<1:128>>)
  assert local.validate_retirement(issuer, 0, Some(<<0:64>>))
    == Error(connection_id.InvalidConnectionId)
  assert local.retire(issuer, 2) == Error(connection_id.InvalidSequence)
  let assert Ok(#(retired, Some(<<0:64>>))) = local.retire(issuer, 0)
  assert local.retire(retired, 0) == Ok(#(retired, None))
  assert !local.accepts(retired, <<0:64>>)
  assert local.accepts(retired, <<1:64>>)
  assert local.available(retired, 2) == 1
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retired_identifiers_and_tokens_are_never_reused_test() -> Nil {
  let assert Ok(issuer) = local.new(<<0:64>>)
  let assert Ok(#(issuer, _)) = local.issue(issuer, 2, <<1:64>>, <<1:128>>)
  let issuer = local.record_sent(issuer, 1)
  let assert Ok(#(issuer, _)) = local.retire(issuer, 1)
  assert local.issue(issuer, 2, <<1:64>>, <<2:128>>)
    == Error(connection_id.ConnectionIdReused)
  assert local.issue(issuer, 2, <<2:64>>, <<1:128>>)
    == Error(connection_id.ResetTokenReused)
  assert local.issue(issuer, 2, <<0:64>>, <<2:128>>)
    == Error(connection_id.ConnectionIdReused)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn local_history_exhaustion_is_finite_and_keeps_a_routable_identifier_test() -> Nil {
  let assert Ok(issuer) = local.new(<<0:64>>)
  let issuer =
    int.range(1, 4096, issuer, fn(issuer, sequence) {
      let assert Ok(#(issuer, entry)) =
        local.issue(issuer, 2, <<sequence:64>>, <<sequence:128>>)
      assert entry.sequence == sequence
      let issuer = local.record_sent(issuer, sequence)
      let assert Ok(#(issuer, Some(_))) = local.retire(issuer, sequence - 1)
      issuer
    })
  assert local.snapshot(issuer) == local.Snapshot(1, 4096, 4095, 4096)
  assert local.available(issuer, 1000) == 0
  assert local.accepts(issuer, <<4095:64>>)
  assert local.issue(issuer, 2, <<4096:64>>, <<4096:128>>)
    == Error(connection_id.HistoryLimitExceeded(4096))
}
