//// Finite, clock-injected connection-attempt scheduling, without runtime I/O.

import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order.{type Order}

/// The two independently resolved destination families.
pub type Family {
  Ipv4
  Ipv6
}

/// Payload-free resolver lifecycle evidence, independent for each family.
pub type ResolutionOutcome {
  ResolutionStarted
  ResolutionUsable
  ResolutionEmpty
  ResolutionRejected
  ResolutionExpired
  ResolutionCancelled
  ResolutionWorkerExited
  ResolutionStartFailed
}

type Candidate(a) {
  Candidate(value: a, family: Family)
}

/// At most sixteen attempted plus queued destinations; only launched work is active.
/// A late family may replace unstarted tail entries, never live work.
pub opaque type State(a) {
  State(
    pending: List(Family),
    queued: List(Candidate(a)),
    attempted: List(a),
    active: List(Int),
    launched: Int,
    last_family: Option(Family),
    last_launch: Option(Int),
    next_launch: Option(Int),
    ipv4_ready: Option(Int),
    dns_deadline: Int,
    total_deadline: Int,
    compare: fn(a, a) -> Order,
  )
}

/// Exactly one next operation.
/// The runtime owns joining stopped processes.
pub type Step(a) {
  Launch(value: a, ordinal: Int, state: State(a))
  Wait(until: Int, state: State(a))
  DnsExpired(state: State(a))
  TotalExpired
  Exhausted
}

/// The deterministic resolver launch order.
/// When both families are enabled,
/// the IPv6 resolver is admitted before the immediately following IPv4 one.
pub fn resolution_order(ipv4: Bool, ipv6: Bool) -> List(Family) {
  case ipv4, ipv6 {
    True, True -> [Ipv6, Ipv4]
    True, False -> [Ipv4]
    False, True -> [Ipv6]
    False, False -> []
  }
}

/// Start one finite schedule under already-computed absolute deadlines.
pub fn new(
  ipv4: Bool,
  ipv6: Bool,
  dns_deadline: Int,
  total_deadline: Int,
  compare: fn(a, a) -> Order,
) -> State(a) {
  let pending = resolution_order(ipv4, ipv6)
  State(
    pending,
    [],
    [],
    [],
    0,
    None,
    None,
    None,
    None,
    dns_deadline,
    total_deadline,
    compare,
  )
}

/// Incorporate one bounded family result.
/// Repeated completion is inert.
pub fn answer(
  state: State(a),
  family: Family,
  addresses: List(a),
  now: Int,
) -> State(a) {
  case list.contains(state.pending, family) {
    False -> state
    True -> {
      let incoming =
        distinct_candidates(addresses, state.attempted, [], 16)
        |> list.map(fn(value) { Candidate(value, family) })
      let candidates =
        list.append(state.queued, incoming)
        |> list.unique
        |> list.sort(fn(a, b) { state.compare(a.value, b.value) })
        |> interleave(state.last_family)
        |> list.take(16 - state.launched)
      State(
        ..state,
        pending: list.filter(state.pending, fn(item) { item != family }),
        queued: candidates,
        ipv4_ready: case family, incoming, state.ipv4_ready {
          Ipv4, [_, ..], None -> Some(now + 50)
          _, _, current -> current
        },
      )
    }
  }
}

// Capacity measures distinct unattempted values.
// Bound the retained working set while scanning duplicate rows, rather than truncating the input first.
fn distinct_candidates(
  addresses: List(a),
  attempted: List(a),
  reversed: List(a),
  remaining: Int,
) -> List(a) {
  case addresses, remaining {
    [], _ | _, 0 -> list.reverse(reversed)
    [address, ..rest], _ ->
      case
        list.contains(attempted, address) || list.contains(reversed, address)
      {
        True -> distinct_candidates(rest, attempted, reversed, remaining)
        False ->
          distinct_candidates(
            rest,
            attempted,
            [address, ..reversed],
            remaining - 1,
          )
      }
  }
}

/// A failed active attempt may accelerate the next launch to the fixed 100 ms lower bound.
/// Duplicate and unknown completions cannot change it.
pub fn failed(state: State(a), ordinal: Int) -> State(a) {
  case list.contains(state.active, ordinal) {
    False -> state
    True ->
      State(
        ..state,
        active: list.filter(state.active, fn(id) { id != ordinal }),
        next_launch: case state.last_launch {
          Some(at) -> Some(at + 100)
          None -> state.next_launch
        },
      )
  }
}

/// A raced 0-RTT candidate needs authenticated reachability before selection;
/// a sole known destination retains the original early-data publication path.
pub fn requires_peer_confirmation(state: State(a)) -> Bool {
  state.pending != [] || state.queued != [] || state.launched > 1
}

/// Advance from an explicit monotonic instant; no polling or sleeping actors.
pub fn next(state: State(a), now: Int) -> Step(a) {
  case now >= state.total_deadline, state.pending != [] {
    True, _ -> TotalExpired
    False, True if now >= state.dns_deadline ->
      DnsExpired(State(..state, pending: []))
    False, _ -> next_candidate(state, now)
  }
}

fn next_candidate(state: State(a), now: Int) -> Step(a) {
  case state.queued, state.active, state.pending {
    [], [], [] -> Exhausted
    [], _, _ -> Wait(wait_bound(state), state)
    [candidate, ..rest], _, _ -> {
      let due = launch_time(state, now)
      case due > now {
        True -> Wait(int.min(due, wait_bound(state)), state)
        False -> {
          let ordinal = state.launched + 1
          let state =
            State(
              ..state,
              queued: rest,
              attempted: [candidate.value, ..state.attempted],
              active: [ordinal, ..state.active],
              launched: ordinal,
              last_family: Some(candidate.family),
              last_launch: Some(now),
              next_launch: Some(now + 250),
            )
          Launch(candidate.value, ordinal, state)
        }
      }
    }
  }
}

fn launch_time(state: State(a), now: Int) -> Int {
  case state.next_launch {
    Some(at) -> at
    None ->
      case list.contains(state.pending, Ipv6), state.ipv4_ready {
        True, Some(at) -> at
        _, _ -> now
      }
  }
}

fn wait_bound(state: State(a)) -> Int {
  case state.pending {
    [] -> state.total_deadline
    _ -> int.min(state.dns_deadline, state.total_deadline)
  }
}

fn interleave(
  candidates: List(Candidate(a)),
  previous: Option(Family),
) -> List(Candidate(a)) {
  case candidates {
    [] -> []
    [first, ..] -> {
      let family = case previous {
        Some(Ipv4) -> Ipv6
        Some(Ipv6) -> Ipv4
        None -> first.family
      }
      let #(preferred, other) =
        list.partition(candidates, fn(item) { item.family == family })
      alternate(preferred, other)
    }
  }
}

fn alternate(first: List(a), second: List(a)) -> List(a) {
  case first, second {
    [], _ -> second
    _, [] -> first
    [a, ..rest_a], [b, ..rest_b] -> [a, b, ..alternate(rest_a, rest_b)]
  }
}
