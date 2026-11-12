import gleam/option.{None, Some}
import gleam/order.{Eq, Gt, Lt}
import quic_core/internal/runtime/destination_order as destination
import quic_core/internal/udp

fn address(bytes: BitArray) -> udp.Address {
  let assert Ok(address) = udp.address_from_bytes(bytes)
  address
}

fn candidate(destination: BitArray, source: BitArray) -> destination.Candidate {
  destination.Candidate(
    address(destination),
    destination.Available(address(source), Some(64)),
    None,
    None,
    None,
  )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn known_source_route_precedes_known_unreachable_destination_test() -> Nil {
  let preferred = candidate(<<192, 0, 2, 1>>, <<192, 0, 2, 2>>)
  let alternative =
    destination.Candidate(
      ..candidate(<<0x2001:16, 0xdb8:16, 0:96>>, <<1:128>>),
      source: destination.Unreachable,
    )
  assert destination.compare(preferred, alternative) == Lt
  assert destination.compare(alternative, preferred) == Gt
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn matching_scope_precedes_default_policy_precedence_test() -> Nil {
  let preferred = candidate(<<192, 0, 2, 1>>, <<192, 0, 2, 2>>)
  let alternative = candidate(<<0x2001:16, 0xdb8:16, 0:96>>, <<1:128>>)
  assert destination.compare(preferred, alternative) == Lt
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn observed_deprecation_precedes_destination_precedence_test() -> Nil {
  let preferred =
    destination.Candidate(
      ..candidate(<<192, 0, 2, 1>>, <<192, 0, 2, 2>>),
      deprecated: Some(False),
    )
  let alternative =
    destination.Candidate(
      ..candidate(<<0x2001:16, 0xdb8:16, 0:96>>, <<0x2001:16, 0xdb8:16, 1:96>>),
      deprecated: Some(True),
    )
  assert destination.compare(preferred, alternative) == Lt
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn unknown_deprecation_does_not_claim_preferred_source_status_test() -> Nil {
  let preferred =
    destination.Candidate(
      ..candidate(<<0x2001:16, 0xdb8:16, 2:96>>, <<0x2001:16, 0xdb8:16, 1:96>>),
      deprecated: Some(True),
    )
  let alternative =
    candidate(<<0x2001:16, 0xdb8:16, 3:96>>, <<0x2001:16, 0xdb8:16, 1:96>>)
  assert destination.compare(preferred, alternative) == Eq
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn observed_home_address_precedes_care_of_address_test() -> Nil {
  let preferred =
    destination.Candidate(
      ..candidate(<<192, 0, 2, 1>>, <<192, 0, 2, 2>>),
      mobility: Some(destination.Home),
    )
  let alternative =
    destination.Candidate(..preferred, mobility: Some(destination.CareOf))
  assert destination.compare(preferred, alternative) == Lt
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn matching_policy_label_precedes_higher_precedence_test() -> Nil {
  let preferred = candidate(<<0xfd:8, 1:120>>, <<0xfd:8, 2:120>>)
  let alternative = candidate(<<0x2001:16, 0xdb8:16, 1:96>>, <<0xfd:8, 2:120>>)
  assert destination.compare(preferred, alternative) == Lt
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn default_precedence_prefers_ipv6_with_matching_sources_test() -> Nil {
  let preferred =
    candidate(<<0x2001:16, 0xdb8:16, 1:96>>, <<0x2001:16, 0xdb8:16, 2:96>>)
  let alternative = candidate(<<192, 0, 2, 1>>, <<192, 0, 2, 2>>)
  assert destination.compare(preferred, alternative) == Lt
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn native_transport_preference_requires_both_observations_test() -> Nil {
  let preferred =
    destination.Candidate(
      ..candidate(<<0x2001:16, 0xdb8:16, 1:96>>, <<0x2001:16, 0xdb8:16, 2:96>>),
      native_transport: Some(True),
    )
  let alternative =
    destination.Candidate(..preferred, native_transport: Some(False))
  assert destination.compare(preferred, alternative) == Lt
  assert destination.compare(
      preferred,
      destination.Candidate(..alternative, native_transport: None),
    )
    == Eq
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn prefix_preference_is_capped_at_observed_source_prefix_length_test() -> Nil {
  let preferred =
    candidate(<<0x2001:16, 0xdb8:16, 0:32, 1:64>>, <<
      0x2001:16,
      0xdb8:16,
      0:32,
      1:64,
    >>)
  let alternative =
    candidate(<<0x2001:16, 0xdb8:16, 0:32, 2:64>>, <<
      0x2001:16,
      0xdb8:16,
      0:32,
      1:64,
    >>)
  assert destination.compare(preferred, alternative) == Eq
  let shorter_prefix =
    candidate(<<0x2001:16, 0xdb8:16, 1:32, 0:64>>, <<
      0x2001:16,
      0xdb8:16,
      0:32,
      1:64,
    >>)
  assert destination.compare(preferred, shorter_prefix) == Lt
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn actual_route_source_probe_does_not_transmit_a_datagram_test() -> Nil {
  let loopback = address(<<127, 0, 0, 1>>)
  let assert Ok(bind) = udp.endpoint(loopback, 0)
  let assert Ok(listener) = udp.open(bind)
  let assert Ok(endpoint) = udp.local_endpoint(listener)
  let observed = destination.observe(loopback, udp.endpoint_parts(endpoint).1)
  let received = udp.receive(listener, 20)
  let closed = udp.close(listener)
  let assert destination.Available(source, _) = observed.source
  assert source == loopback
  assert received == Error(udp.Timeout)
  assert closed == Ok(Nil)
  assert observed.mobility == None
  assert observed.native_transport == None
}
