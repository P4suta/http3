//// RFC 6724 destination ordering over explicitly observed source attributes.
//// Missing platform attributes remain unknown and cannot acquire a preference.

import gleam/bit_array
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/order.{type Order, Eq, Gt, Lt}
import quic_core/internal/udp

/// Route selection distinguishes known absence from an unsupported observation.
pub type Source {
  Available(address: udp.Address, prefix_length: Option(Int))
  Unreachable
  Unobserved
}

/// Source mobility properties require an actual platform observation.
pub type Mobility {
  Home
  CareOf
  HomeAndCareOf
  Neither
}

/// Internal candidate evidence.
/// It is never part of public diagnostics.
pub type Candidate {
  Candidate(
    address: udp.Address,
    source: Source,
    deprecated: Option(Bool),
    mobility: Option(Mobility),
    native_transport: Option(Bool),
  )
}

/// Compare rules in order; stable sorting supplies RFC 6724 rule 10.
pub fn compare(a: Candidate, b: Candidate) -> Order {
  prefer_true(usable(a.source), usable(b.source))
  |> order.break_tie(prefer_true(matches_scope(a), matches_scope(b)))
  |> order.break_tie(prefer_true(b.deprecated, a.deprecated))
  |> order.break_tie(prefer_home(a.mobility, b.mobility))
  |> order.break_tie(prefer_true(matches_label(a), matches_label(b)))
  |> order.break_tie(int.compare(policy(b.address).0, policy(a.address).0))
  |> order.break_tie(prefer_true(a.native_transport, b.native_transport))
  |> order.break_tie(int.compare(scope(a.address), scope(b.address)))
  |> order.break_tie(prefer_prefix(a, b))
}

/// Source probes are current for this resolution, without a stale address cache.
pub fn observe(address: udp.Address, port: Int) -> Candidate {
  let source = case udp.route_source(address, port) {
    Ok(#(source, prefix)) -> Available(source, prefix)
    Error(udp.AddressUnavailable) -> Unreachable
    Error(udp.InvalidInput)
    | Error(udp.Timeout)
    | Error(udp.Closed)
    | Error(udp.PermissionDenied)
    | Error(udp.AddressInUse)
    | Error(udp.EcnUnavailable)
    | Error(udp.MessageTooLarge)
    | Error(udp.UnverifiedPathError)
    | Error(udp.SocketFailure) -> Unobserved
  }
  Candidate(address, source, preferred_status(source), None, None)
}

fn preferred_status(source: Source) -> Option(Bool) {
  case source {
    Available(address, _) ->
      case udp.address_bytes(address) {
        <<_:32>> | <<1:128>> -> Some(False)
        _ -> None
      }
    _ -> None
  }
}

fn usable(source: Source) -> Option(Bool) {
  case source {
    Available(_, _) -> Some(True)
    Unreachable -> Some(False)
    Unobserved -> None
  }
}

fn matches_scope(candidate: Candidate) -> Option(Bool) {
  case candidate.source {
    Available(source, _) -> Some(scope(candidate.address) == scope(source))
    _ -> None
  }
}

fn matches_label(candidate: Candidate) -> Option(Bool) {
  case candidate.source {
    Available(source, _) ->
      Some(policy(candidate.address).1 == policy(source).1)
    _ -> None
  }
}

fn prefer_true(a: Option(Bool), b: Option(Bool)) -> Order {
  case a, b {
    Some(True), Some(False) -> Lt
    Some(False), Some(True) -> Gt
    _, _ -> Eq
  }
}

fn prefer_home(a: Option(Mobility), b: Option(Mobility)) -> Order {
  case a, b {
    Some(HomeAndCareOf), Some(HomeAndCareOf) -> Eq
    Some(HomeAndCareOf), Some(_) | Some(Home), Some(CareOf) -> Lt
    Some(_), Some(HomeAndCareOf) | Some(CareOf), Some(Home) -> Gt
    _, _ -> Eq
  }
}

fn prefer_prefix(a: Candidate, b: Candidate) -> Order {
  case a.source, b.source {
    Available(source_a, Some(prefix_a)), Available(source_b, Some(prefix_b)) -> {
      let bytes_a = udp.address_bytes(a.address)
      let bytes_b = udp.address_bytes(b.address)
      case bit_array.byte_size(bytes_a) == bit_array.byte_size(bytes_b) {
        False -> Eq
        True ->
          int.compare(
            matching_prefix(udp.address_bytes(source_b), bytes_b, prefix_b),
            matching_prefix(udp.address_bytes(source_a), bytes_a, prefix_a),
          )
      }
    }
    _, _ -> Eq
  }
}

fn matching_prefix(a: BitArray, b: BitArray, remaining: Int) -> Int {
  case remaining <= 0 {
    True -> 0
    False ->
      case a, b {
        <<a:1, rest_a:bits>>, <<b:1, rest_b:bits>> if a == b ->
          1 + matching_prefix(rest_a, rest_b, remaining - 1)
        _, _ -> 0
      }
  }
}

fn scope(address: udp.Address) -> Int {
  case udp.address_bytes(address) {
    <<127, _:24>> | <<169, 254, _:16>> | <<1:128>> -> 2
    <<0xff, _:4, scope:4, _:112>> -> scope
    <<0x3fa:10, _:118>> -> 2
    <<0x3fb:10, _:118>> -> 5
    _ -> 14
  }
}

fn policy(address: udp.Address) -> #(Int, Int) {
  case udp.address_bytes(address) {
    <<_:32>> | <<0:80, 0xffff:16, _:32>> -> #(35, 4)
    <<1:128>> -> #(50, 0)
    <<0x2002:16, _:112>> -> #(30, 2)
    <<0x20010000:32, _:96>> -> #(5, 5)
    <<0x7e:7, _:121>> -> #(3, 13)
    <<0:96, _:32>> -> #(1, 3)
    <<0x3fb:10, _:118>> -> #(1, 11)
    <<0x3ffe:16, _:112>> -> #(1, 12)
    _ -> #(40, 1)
  }
}
