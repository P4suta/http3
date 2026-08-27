//// The listener's aggregate memory budget: pure quantum accounting.
////
//// PRE-004 gives the listener one byte budget for the whole endpoint. The
//// arithmetic behind it lives in `internal/runtime/budget` so that it can be
//// exercised directly, without a socket, a handshake, or an actor: a budget
//// is created from the configured `EndpointMemory` value, connections
//// reserve against it in whole quanta, release what they no longer hold, and
//// a reservation that does not fit is refused whole rather than partially
//// granted.
////
//// Four rules matter beyond simple arithmetic, and each has a test here.
//// A refusal must leave the budget exactly as it was, so a refused
//// connection cannot leak the bytes it was denied. Releasing one connection
//// twice must free its bytes once, because the listener learns of a released
//// connection twice -- once from the actor's own `Released` notice and once
//// from the monitor `Down` for the same actor. A release larger than the
//// connection holds must be rejected rather than credited, because a budget
//// that can be over-released is a budget that silently grows. And a request
//// the endpoint could not meet must be met out of memory a neighbour
//// releases, oldest first, with nothing of the connection's own to prompt it:
//// a refusal that only traffic can lift is a refusal that never lifts on the
//// steady connections it is most likely to catch.

import gleam/option.{None, Some}
import gleam_quic/config
import gleam_quic/failure
import gleam_quic/internal/runtime/budget

/// The accounting quantum: the step every reservation is rounded up to, and
/// the unit a connection actor asks the listener for room in.
const quantum_bytes = 16_384

/// The step a connection asks for room in and keeps ahead of what it holds.
const growth_step_bytes = 262_144

const growth_step_quanta = 16

/// A budget of ten quanta, small enough to fill inside one test.
const limit_bytes = 163_840

const first = <<1>>

const second = <<2>>

const third = <<3>>

/// How many generated reserve and release steps the convergence property
/// runs, and over how many distinct connection identifiers.
const property_cases = 256

const property_connections = 8

const generator_modulus = 2_147_483_647

const generator_seed = 982_451_653

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn an_empty_budget_holds_nothing_test() -> Nil {
  // The quantum is the module's own, so every other bound here is stated in
  // the unit the listener and its connection actors actually exchange.
  assert budget.quantum() == quantum_bytes
  assert budget.growth_step() == growth_step_bytes
  assert budget.used(budget.new(limit_bytes)) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn default_limits_admit_every_default_connection_test() -> Nil {
  // The two defaults have to agree with each other. `default_limits` pairs a
  // 64 MiB endpoint budget with a 1024-connection admission limit, so an
  // endpoint at its default connection limit must still be admitting
  // connections while every one of them is idle. At a 64 KiB quantum those two
  // defaults collided exactly: one quantum each was already the whole budget,
  // and the endpoint refused connections it had promised to accept.
  let limits = config.default_limits()
  let endpoint_memory = config.limit(limits, failure.EndpointMemory)
  let connections = config.limit(limits, failure.Connections)
  assert admit_every(budget.new(endpoint_memory), connections) == True
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn admission_funds_the_credit_a_server_advertises_test() -> Nil {
  // The admission charge is not a working set alone. A server promises the
  // peer connection-level receive credit in its own transport parameters,
  // before it has asked its endpoint for a byte of room, and that promise
  // cannot be retracted -- so the charge has to cover it, or the endpoint-wide
  // bound is short by that credit on every connection it ever admits.
  assert budget.admission_quanta() * budget.quantum()
    > budget.initial_receive_credit()

  // And the charge that covers it still has to fit the defaults.
  let limits = config.default_limits()
  assert config.limit(limits, failure.Connections)
    * budget.admission_quanta()
    * budget.quantum()
    <= config.limit(limits, failure.EndpointMemory)
}

/// Charge one admission for each of `connections` distinct connections,
/// reporting whether the last of them was still admitted.
fn admit_every(ledger: budget.Budget, connections: Int) -> Bool {
  case connections <= 0 {
    True -> True
    False ->
      case
        budget.reserve(
          ledger,
          <<connections:32>>,
          budget.admission_quanta() * budget.quantum(),
        )
      {
        // nolint: thrown_away_error -- a refused admission fails this outright.
        Error(_reason) -> False
        Ok(charged) -> admit_every(charged, connections - 1)
      }
  }
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_withheld_request_is_met_when_a_neighbour_releases_test() -> Nil {
  // Two connections between them hold eight of the endpoint's ten quanta.
  let assert Ok(ledger) =
    budget.reserve(budget.new(limit_bytes), first, 4 * quantum_bytes)
  let assert Ok(ledger) = budget.reserve(ledger, second, 4 * quantum_bytes)

  // A third asks for six and can only be given the two that are left. The
  // shortfall is what holds it where it is, and the endpoint ends up exactly
  // at its budget rather than one connection short of it.
  let #(ledger, answer) = budget.answer_request(ledger, third, 7, 6)
  assert answer == budget.Short(2)
  assert budget.used(ledger) == limit_bytes

  // It does not ask again -- it would only be refused again -- and while the
  // endpoint is full there is nothing to give it.
  let #(ledger, none_yet) = budget.retry_withheld(ledger)
  assert none_yet == []

  // A neighbour goes away. The room it returns is owed to the connection that
  // was held, and it is offered without that connection saying a word: the
  // sequence number the retry carries is the one from the request it could not
  // meet, so the answer lands on the request the connection is still waiting
  // on.
  let #(ledger, met) = budget.retry_withheld(budget.release_all(ledger, first))
  assert met == [budget.Retry(third, 7, 6)]
  assert budget.used(ledger) == limit_bytes

  // The request was met once. Nothing is left waiting, so nothing is granted
  // twice out of the next release.
  let #(_ledger, again) = budget.retry_withheld(ledger)
  assert again == []
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn withheld_requests_are_met_oldest_first_test() -> Nil {
  // One connection holds six of ten quanta.
  let assert Ok(ledger) =
    budget.reserve(budget.new(limit_bytes), first, 6 * quantum_bytes)

  // Two more ask, in order, for more than is left. Both are held.
  let #(ledger, second_answer) = budget.answer_request(ledger, second, 1, 6)
  let #(ledger, third_answer) = budget.answer_request(ledger, third, 1, 5)
  assert second_answer == budget.Short(4)
  assert third_answer == budget.Short(0)

  // Two quanta come back: enough for the older request and not the newer one.
  // The older one is met, and the walk stops there rather than stepping over
  // it -- funding the younger request instead would take the room from under
  // the connection that has been waiting longer.
  let assert Ok(ledger) = budget.release(ledger, first, 2 * quantum_bytes)
  let #(ledger, first_round) = budget.retry_withheld(ledger)
  assert first_round == [budget.Retry(second, 1, 6)]

  // Four more come back, and the request at the head still cannot be met
  // whole, so nothing is: a partial charge here would take memory from the
  // connection behind the head without unblocking the connection in front.
  let #(ledger, blocked) =
    budget.retry_withheld(budget.release_all(ledger, first))
  assert blocked == []

  // Room enough at last.
  let #(ledger, last) =
    budget.retry_withheld(budget.release_all(ledger, second))
  assert last == [budget.Retry(third, 1, 5)]
  assert budget.used(ledger) == 5 * quantum_bytes
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_connection_held_twice_keeps_its_place_in_the_queue_test() -> Nil {
  let assert Ok(ledger) =
    budget.reserve(budget.new(limit_bytes), first, 10 * quantum_bytes)

  // Two connections are held, oldest first, and then the older of them is
  // held a second time by a newer request of its own. Being refused again
  // must not send it to the back of the queue, or a connection under steady
  // pressure could be starved by connections that arrived after it.
  let #(ledger, _held) = budget.answer_request(ledger, second, 1, 3)
  let #(ledger, _also_held) = budget.answer_request(ledger, third, 1, 3)
  let #(ledger, _held_again) = budget.answer_request(ledger, second, 2, 4)
  assert budget.used(ledger) == limit_bytes

  // Four quanta come back: enough for exactly one of them, and it is the one
  // that was waiting first, answered against its newest request.
  let assert Ok(ledger) = budget.release(ledger, first, 4 * quantum_bytes)
  let #(_ledger, met) = budget.retry_withheld(ledger)
  assert met == [budget.Retry(second, 2, 4)]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_released_connection_is_owed_nothing_test() -> Nil {
  let assert Ok(ledger) =
    budget.reserve(budget.new(limit_bytes), first, 10 * quantum_bytes)
  let #(ledger, held) = budget.answer_request(ledger, second, 1, 3)
  assert held == budget.Short(0)

  // The held connection goes away before the room it wanted comes back. Its
  // request goes with it, so the endpoint never charges for a connection it no
  // longer has, and the queue cannot outlive the connections in it.
  let ledger = budget.release_all(ledger, second)
  let #(ledger, met) = budget.retry_withheld(budget.release_all(ledger, first))
  assert met == []
  assert budget.used(ledger) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn asking_for_less_than_it_holds_returns_the_difference_test() -> Nil {
  let assert Ok(ledger) =
    budget.reserve(budget.new(limit_bytes), first, 6 * quantum_bytes)
  let #(ledger, held) = budget.answer_request(ledger, second, 1, 6)
  assert held == budget.Short(4)

  // A connection that has shrunk asks for less than it holds. That is memory
  // coming back rather than memory being demanded, so it is met at once and
  // the difference is returned to the endpoint.
  let #(ledger, shrunk) = budget.answer_request(ledger, first, 2, 2)
  assert shrunk == budget.Met(2)
  assert budget.used(ledger) == 6 * quantum_bytes

  // And the room it returned is what the held connection was waiting for.
  let #(_ledger, met) = budget.retry_withheld(ledger)
  assert met == [budget.Retry(second, 1, 6)]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_connection_asks_for_room_before_it_grows_test() -> Nil {
  // A connection admitted with one working set holds nothing yet, and still
  // asks for a whole growth step: the room has to be granted before the peer
  // is invited to fill it, not measured and billed once it is already full.
  let grant = budget.new_grant(1)
  assert budget.granted_quanta(grant) == 1
  assert budget.granted_bytes(grant) == quantum_bytes
  let assert Some(#(grant, sequence, quanta)) = budget.request(grant, 0)
  assert sequence == 1
  assert quanta == growth_step_quanta

  // Nothing more is asked while an answer is outstanding, however much the
  // connection grows in the meantime.
  assert budget.request(grant, 8 * quantum_bytes) == None

  // Granted in full, the connection is not held, and it does not speak again
  // until what it holds comes within a step of the grant.
  let grant = budget.apply_grant(grant, sequence, quanta)
  assert budget.grant_refused(grant) == False
  assert budget.granted_bytes(grant) == growth_step_bytes
  assert budget.request(grant, 0) == None
  let assert Some(#(_grown, next_sequence, next_quanta)) =
    budget.request(grant, growth_step_bytes)
  assert next_sequence == 2
  assert next_quanta == 2 * growth_step_quanta
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn only_the_answer_to_the_newest_request_is_applied_test() -> Nil {
  // A connection holding ten quanta asks for a step of headroom above them.
  let assert Some(#(grant, first_sequence, wanted)) =
    budget.request(budget.new_grant(1), 10 * quantum_bytes)
  assert wanted == 10 + growth_step_quanta

  // The endpoint could only cover two quanta, which holds the connection
  // where it is. It does not ask again: it would only be refused again.
  let grant = budget.apply_refusal(grant, first_sequence, 2)
  assert budget.grant_refused(grant) == True
  assert budget.granted_quanta(grant) == 2
  assert budget.request(grant, 10 * quantum_bytes) == None

  // Having shrunk, it does speak up, because asking for less is memory going
  // back rather than memory being demanded.
  let assert Some(#(grant, second_sequence, second_wanted)) =
    budget.request(grant, 0)
  assert second_sequence == first_sequence + 1
  assert second_wanted == growth_step_quanta

  // The endpoint's answer to the first request now arrives late. Applying it
  // would install a grant sized for a footprint this connection has already
  // left behind, so it is ignored outright.
  let grant = budget.apply_grant(grant, first_sequence, wanted)
  assert budget.granted_quanta(grant) == 2
  assert budget.grant_refused(grant) == True

  // The answer to the newest request is the one that lands.
  let grant = budget.apply_grant(grant, second_sequence, second_wanted)
  assert budget.granted_quanta(grant) == growth_step_quanta
  assert budget.grant_refused(grant) == False
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_grant_never_undercounts_what_a_connection_holds_test() -> Nil {
  // The listener's ledger and one connection's grant driven together, over a
  // connection that keeps growing into whatever room it is given, until the
  // budget runs out under it. Two invariants hold at every step: the grant
  // always covers what the connection holds, because the connection only ever
  // grows into room granted in advance; and the ledger has always charged for
  // exactly what it granted, so it can never undercount what is held.
  let assert Ok(ledger) =
    budget.reserve(budget.new(limit_bytes), first, quantum_bytes)
  assert grow_together(ledger, budget.new_grant(1), 0, 12) == True
}

fn grow_together(
  ledger: budget.Budget,
  grant: budget.Grant,
  held: Int,
  remaining: Int,
) -> Bool {
  // The connection grows by one step, but never past the room it was granted.
  let held = smaller(held + growth_step_bytes, budget.granted_bytes(grant))
  case
    budget.granted_bytes(grant) >= held
    && budget.used(ledger) == budget.granted_quanta(grant) * quantum_bytes
  {
    False -> False
    True ->
      case remaining <= 0 {
        // The budget was never exceeded, and the connection ended up held by
        // it rather than growing through it.
        True ->
          budget.used(ledger) <= limit_bytes && budget.grant_refused(grant)
        False -> {
          let #(ledger, grant) = settle(ledger, grant, held)
          grow_together(ledger, grant, held, remaining - 1)
        }
      }
  }
}

/// One request-and-answer round between a connection and its listener, where
/// the listener fills what it can and names the shortfall as a refusal.
fn settle(
  ledger: budget.Budget,
  grant: budget.Grant,
  held: Int,
) -> #(budget.Budget, budget.Grant) {
  case budget.request(grant, held) {
    None -> #(ledger, grant)
    Some(#(asked, sequence, quanta)) -> {
      let charged = budget.granted_quanta(asked)
      case fill(ledger, quanta - charged, charged) {
        #(ledger, granted) if granted >= quanta -> #(
          ledger,
          budget.apply_grant(asked, sequence, granted),
        )
        #(ledger, granted) -> #(
          ledger,
          budget.apply_refusal(asked, sequence, granted),
        )
      }
    }
  }
}

/// Charge as many further quanta as the ledger can cover, one at a time.
fn fill(
  ledger: budget.Budget,
  remaining: Int,
  charged: Int,
) -> #(budget.Budget, Int) {
  case remaining <= 0 {
    True -> #(ledger, charged)
    False ->
      case budget.reserve(ledger, first, quantum_bytes) {
        // nolint: thrown_away_error -- a refused quantum stops the fill.
        Error(_reason) -> #(ledger, charged)
        Ok(next) -> fill(next, remaining - 1, charged + 1)
      }
  }
}

fn smaller(left: Int, right: Int) -> Int {
  case left < right {
    True -> left
    False -> right
  }
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_reservation_is_rounded_up_to_whole_quanta_test() -> Nil {
  // One byte costs one quantum: accounting error is bounded by the quantum,
  // and it is bounded upwards, never downwards.
  let assert Ok(ledger) = budget.reserve(budget.new(limit_bytes), first, 1)
  assert budget.used(ledger) == quantum_bytes

  // Growth is charged in whole quanta too, from what the connection already
  // holds rather than from zero.
  let assert Ok(grown) = budget.reserve(ledger, first, quantum_bytes + 1)
  assert budget.used(grown) == 3 * quantum_bytes
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_reservation_beyond_the_limit_is_refused_whole_test() -> Nil {
  let assert Ok(ledger) =
    budget.reserve(budget.new(limit_bytes), first, 6 * quantum_bytes)
  let assert Ok(full) = budget.reserve(ledger, second, 4 * quantum_bytes)
  assert budget.used(full) == limit_bytes

  // The refusal is the typed limit the public failure taxonomy already
  // carries, and it names the maximum that was exceeded.
  assert budget.reserve(full, second, 1)
    == Error(failure.Limit(failure.EndpointMemory, limit_bytes))

  // A refused reservation charges nothing: the budget is unchanged, and the
  // connection that was refused still holds exactly what it held.
  let assert Ok(released) = budget.release(full, second, 4 * quantum_bytes)
  assert budget.used(released) == 6 * quantum_bytes
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn releasing_more_than_a_connection_holds_is_rejected_test() -> Nil {
  let assert Ok(ledger) =
    budget.reserve(budget.new(limit_bytes), first, 2 * quantum_bytes)

  // Over-release is rejected rather than credited: a budget that can be
  // released below what its connections hold silently grows.
  assert budget.release(ledger, first, 3 * quantum_bytes) == Error(Nil)

  // And the rejected release left the budget exactly as it was.
  let assert Ok(released) = budget.release(ledger, first, 2 * quantum_bytes)
  assert budget.used(released) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn releasing_a_connection_twice_frees_its_bytes_once_test() -> Nil {
  let assert Ok(ledger) =
    budget.reserve(budget.new(limit_bytes), first, 2 * quantum_bytes)
  let assert Ok(ledger) = budget.reserve(ledger, second, quantum_bytes)

  // The listener learns of one released connection twice -- the actor's own
  // notice and the monitor `Down` for the same actor -- so the second
  // release has to be free, and it must not touch its neighbour.
  let released = budget.release_all(ledger, first)
  let again = budget.release_all(released, first)
  assert budget.used(released) == quantum_bytes
  assert budget.used(again) == quantum_bytes
  assert budget.used(budget.release_all(again, second)) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn interleaved_reserve_and_release_converge_to_zero_property_test() -> Nil {
  // Generated interleavings of reserve and release over several connection
  // identifiers. Every step holds the budget's two standing invariants, and
  // releasing every connection at the end returns the budget to empty: an
  // endpoint that has let go of every connection owes nothing.
  let exercised =
    exercise(budget.new(limit_bytes), generator_seed, property_cases)
  assert budget.used(release_every(exercised, property_connections)) == 0
}

fn exercise(ledger: budget.Budget, seed: Int, remaining: Int) -> budget.Budget {
  case remaining <= 0 {
    True -> ledger
    False -> {
      let seed = next_seed(seed)
      let index = seed % property_connections
      let connection = <<index>>
      let ledger = case seed % 3 {
        0 -> budget.release_all(ledger, connection)
        _ -> reserve_step(ledger, connection, seed % limit_bytes + 1)
      }
      // The budget never exceeds its limit, and it only ever holds whole
      // quanta, whatever order the steps arrive in.
      assert budget.used(ledger) <= limit_bytes
      assert budget.used(ledger) % quantum_bytes == 0
      exercise(ledger, seed, remaining - 1)
    }
  }
}

/// One generated reservation, where a refusal leaves the budget untouched.
fn reserve_step(
  ledger: budget.Budget,
  connection: BitArray,
  bytes: Int,
) -> budget.Budget {
  case budget.reserve(ledger, connection, bytes) {
    // nolint: thrown_away_error -- a refused step is the budget unchanged.
    Error(_reason) -> ledger
    Ok(grown) -> grown
  }
}

fn release_every(ledger: budget.Budget, remaining: Int) -> budget.Budget {
  case remaining <= 0 {
    True -> ledger
    False -> {
      let index = remaining - 1
      release_every(budget.release_all(ledger, <<index>>), index)
    }
  }
}

fn next_seed(seed: Int) -> Int {
  { seed * 48_271 + 1 } % generator_modulus
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn send_admission_is_funded_before_it_grows_test() -> Nil {
  // Four quanta granted, and a stream buffer far wider than them.
  let grant = budget.new_grant(4)
  let buffer_room = growth_step_bytes

  // The grant is what bounds an application's write, not the buffer ceiling:
  // a connection holding three quanta may take one more, and no more than one.
  assert admits(grant, 3 * quantum_bytes, buffer_room) == quantum_bytes
  assert admits(grant, 4 * quantum_bytes, buffer_room) == 0

  // Holding more than the grant is not a debt a further write may add to.
  assert admits(grant, 5 * quantum_bytes, buffer_room) == 0

  // The buffer ceiling still binds when it is the narrower of the two.
  assert admits(grant, 0, 1024) == 1024

  // And the bound does not wait for a refusal to land. A connection whose
  // request was met in full is admitted on exactly the same arithmetic as one
  // whose request fell short: a write held back by a met grant is held back by
  // endpoint memory just as surely as one held back by a refused grant, and a
  // refusal changes neither how much may be taken nor what the caller is told
  // when a parked write reaches its deadline.
  let #(met, short) = met_and_short_grants()
  assert budget.grant_refused(met) == False
  assert budget.grant_refused(short) == True
  assert admits(met, 3 * quantum_bytes, buffer_room)
    == admits(short, 3 * quantum_bytes, buffer_room)
  assert admits(met, 3 * quantum_bytes, buffer_room) == quantum_bytes
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_parked_send_names_the_bound_that_stopped_it_test() -> Nil {
  let grant = budget.new_grant(4)

  // Room under the ceiling and none under the grant is the grant holding the
  // write, and it is the grant whether or not a refusal has landed: this is
  // what a parked send reports to its caller as endpoint overload rather than
  // as a bare operation timeout, and a met grant reports it exactly as a
  // refused one does.
  let #(met, short) = met_and_short_grants()
  assert bound_by_grant(met, 4 * quantum_bytes, growth_step_bytes) == True
  assert bound_by_grant(short, 4 * quantum_bytes, growth_step_bytes) == True

  // Room under the grant and none under the ceiling is the application's own
  // choice holding the write, waiting on its peer rather than on the endpoint.
  assert bound_by_grant(grant, 0, 0) == False
  assert admits(grant, 0, 0) == 0

  // Neither has room: the endpoint funding more would not move this write
  // along, so the ceiling is what its caller is waiting on.
  assert bound_by_grant(grant, 4 * quantum_bytes, 0) == False

  // A grant narrower than the ceiling names the grant even with room to spare,
  // so the reason a send parks is decided by the same arithmetic that decided
  // how much it could take.
  assert bound_by_grant(grant, 3 * quantum_bytes, growth_step_bytes) == True
  assert bound_by_grant(grant, 0, 1024) == False
}

/// One request met in full and the same request fallen short, so a test can
/// hold the two side by side.
fn met_and_short_grants() -> #(budget.Grant, budget.Grant) {
  let assert Some(#(asked, sequence, _quanta)) =
    budget.request(budget.new_grant(4), 3 * quantum_bytes)
  #(
    budget.apply_grant(asked, sequence, 4),
    budget.apply_refusal(asked, sequence, 4),
  )
}

fn admits(grant: budget.Grant, held_bytes: Int, buffer_room: Int) -> Int {
  budget.admitted_bytes(budget.send_allowance(grant, held_bytes, buffer_room))
}

fn bound_by_grant(
  grant: budget.Grant,
  held_bytes: Int,
  buffer_room: Int,
) -> Bool {
  budget.grant_bound(budget.send_allowance(grant, held_bytes, buffer_room))
}
