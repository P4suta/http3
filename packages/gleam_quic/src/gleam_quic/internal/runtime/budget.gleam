//// The endpoint's aggregate memory ledger: pure quantum accounting.
////
//// PRE-004 gives an endpoint one byte budget for every connection it owns.
//// For a server that endpoint is the whole listener; the client role does not
//// enforce it yet, which `gleam_quic/config` states plainly. The arithmetic
//// behind it lives here, with no socket, actor, or transport state anywhere
//// near it, so it can be exercised directly and replaced without touching
//// either runtime.
////
//// A budget is created from the configured `EndpointMemory` value and charged
//// in whole quanta. Rounding is always upwards, so the ledger over-counts
//// rather than under-counts: the accounting error a connection can hide is
//// bounded by one quantum, and it is bounded on the safe side.
////
//// Four rules matter beyond the arithmetic.
////
////   * A reservation that does not fit is refused whole rather than partly
////     granted, and a refusal charges nothing, so a refused connection cannot
////     leak the bytes it was denied. Growth, which asks for a total rather
////     than a reservation, is instead filled as far as the budget reaches.
////   * A release larger than a connection holds is rejected rather than
////     credited: a budget that can be over-released is a budget that silently
////     grows.
////   * `release_all` is idempotent, because the listener learns of one
////     released connection twice -- from the actor's own notice and from the
////     monitor `Down` for the same actor -- and those bytes must come back
////     exactly once.
////   * A request the endpoint could not meet is kept, and every path that
////     returns memory retries the kept requests oldest first. Without that a
////     refusal would be lifted only by traffic, which is to say never, on the
////     steady connections it is most likely to catch.

import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam_quic/failure

/// The accounting quantum: the step every reservation is rounded up to, and
/// the unit in which a connection actor asks the listener for room.
///
/// It is a fixed constant rather than a configured limit. It is the resolution
/// of a denial-of-service bound, so an application must not be able to widen
/// it.
///
/// 16 KiB, and the choice is forced by the defaults. `config.default_limits`
/// pairs a 64 MiB `EndpointMemory` value with a 1024-connection admission
/// limit, and admission charges `admission_quanta` for every connection, so an
/// endpoint at its default connection limit must still be admitting
/// connections while every one of them is idle. At a 64 KiB quantum those two
/// defaults collide head on -- one quantum each would already be the whole
/// 64 MiB budget. A 16 KiB quantum leaves 4096 quanta for 1024 connections,
/// which is enough to fund each of them the 48 KiB admission charge below.
///
/// A fine quantum does not mean chatty accounting: connections ask for room in
/// `growth_step` units rather than a quantum at a time, so the ledger counts in
/// 16 KiB while a growing connection speaks to its endpoint once per 256 KiB.
const quantum_bytes = 16_384

/// The connection-level receive credit a server advertises in its transport
/// parameters, before it has asked its endpoint for any room at all.
///
/// This is the part of the admission charge that a peer can spend immediately.
/// A server's InitialMaxData is a promise made in the handshake, and it cannot
/// be retracted afterwards, so the budget has to fund it at admission or the
/// endpoint-wide bound is not a bound: an endpoint that admitted a connection
/// for the price of a working set and then promised it a megabyte of receive
/// credit would be over-committed by that megabyte, per connection, with
/// nothing in the ledger to show for it.
///
/// Two quanta. It is deliberately narrow -- one round trip's worth of first
/// data rather than a whole bandwidth-delay product -- because it is credit
/// spent before the connection has proved it wants any. A connection that does
/// want more asks for a `growth_step` on its first turn and advertises it as
/// soon as the answer lands, so what this value costs a busy connection is the
/// first round trip and nothing after it.
const initial_receive_credit_bytes = 32_768

/// The handshake working set: what one connection holds that is not receive
/// credit -- its keys, its transport state, its crypto reassembly, and the
/// Initial and Handshake packets it has sent and not yet had acknowledged.
const working_set_bytes = 16_384

/// The step a connection asks for room in, and the headroom it keeps ahead of
/// what it holds: sixteen quanta, 256 KiB.
///
/// Two things follow from it, and both want it wide. It is what keeps the
/// actor-to-endpoint traffic coarse: a connection asks for the next step once
/// what it holds comes within one step of its grant, so the endpoint hears from
/// it once per 256 KiB of growth however finely the ledger itself counts. And
/// it is the receive credit a connection has room to advertise beyond what it
/// already holds, so it is also the window a peer sending into a connection
/// whose owner is keeping up gets to use. A step of a quantum or two would make
/// every window update a round trip to the endpoint and throttle a healthy
/// connection to a fraction of its path.
///
/// 256 KiB is the byte half of the listener's own delivery window and the
/// default per-stream `Buffer`, so a connection whose owner keeps up is funded
/// for a window the rest of the stack is already sized for.
const growth_step_bytes = 262_144

/// One connection's side of the ledger: the room its endpoint has granted it,
/// and the request it is still waiting on.
///
/// This is the grant-before-growth rule in pure form. A connection may only
/// advertise receive credit, and only admit send-buffer growth, inside
/// `granted_quanta`; when what it holds comes within one `growth_step` of that
/// grant it asks for the next step, and it keeps holding what it already holds
/// until the answer arrives. Growth is therefore always funded before it
/// happens, rather than measured and billed afterwards.
///
/// Every request carries a sequence number, and only the answer to the newest
/// outstanding request is applied. Without it an answer racing a later request
/// would install a grant sized for a footprint the connection has already grown
/// past.
pub opaque type Grant {
  Grant(
    granted: Int,
    requested: Int,
    sequence: Int,
    awaiting: Bool,
    refused: Bool,
  )
}

/// A connection's opening grant: the quanta its endpoint charged to admit it.
pub fn new_grant(quanta: Int) -> Grant {
  let quanta = int.max(0, quanta)
  Grant(quanta, quanta, 0, False, False)
}

/// The whole quanta this connection may hold.
pub fn granted_quanta(grant: Grant) -> Int {
  grant.granted
}

/// The bytes this connection may hold.
pub fn granted_bytes(grant: Grant) -> Int {
  grant.granted * quantum_bytes
}

/// Whether the endpoint answered the last request with less than it asked for,
/// which is the endpoint at its budget and this connection held where it is.
///
/// A refusal is about the receive side and the connection's own queues: it is
/// what stops advertised credit growing and what makes a droppable Datagram
/// droppable. It is deliberately not consulted on the send side, where the
/// grant itself is the bound, met or not.
pub fn grant_refused(grant: Grant) -> Bool {
  grant.refused
}

/// The next request to send, if one is worth sending, as the updated grant, the
/// sequence number to carry, and the whole quanta being asked for.
///
/// Nothing is sent while an answer is outstanding, and nothing is sent while
/// the endpoint has already refused this connection more room -- a refused
/// connection waits to be granted rather than re-asking, so a busy endpoint
/// cannot be made to answer the same refusal over and over. A refused
/// connection that has since shrunk does speak up, because asking for less is
/// returning memory rather than demanding it.
pub fn request(grant: Grant, held_bytes: Int) -> Option(#(Grant, Int, Int)) {
  let wanted = wanted_quanta(held_bytes, grant.granted)
  case grant.awaiting, grant.refused {
    True, _ -> None
    False, True if wanted >= grant.requested -> None
    False, _ if wanted == grant.granted && !grant.refused -> None
    False, _ -> {
      let sequence = grant.sequence + 1
      Some(#(
        Grant(..grant, requested: wanted, sequence: sequence, awaiting: True),
        sequence,
        wanted,
      ))
    }
  }
}

/// What one write may take into a connection's send buffers now, and which of
/// the two bounds decided it.
///
/// It is opaque, and `send_allowance` is its only constructor, so a byte count
/// that reached a send buffer came through the grant arithmetic below. A
/// caller cannot hand itself an allowance the grant never funded, which is the
/// one mistake this decision has to be proof against: the send side has no
/// observable of its own that separates a write the grant bounded from a write
/// a refusal bounded, so an unfunded admission would go unnoticed.
pub opaque type Admission {
  Admission(bytes: Int, grant_bound: Bool)
}

/// The bytes a connection may take into its send buffers now.
///
/// This is grant-before-growth on the send side, and it is unconditional: an
/// application's write is memory this endpoint comes to hold until the peer
/// acknowledges it, so it is admitted only as far as the grant still reaches
/// past what the connection already holds, whether or not a refusal has landed.
/// A grant that was met in full and a grant that fell short admit exactly the
/// same bytes, and a write held back by either is held back by endpoint memory,
/// which is what its caller is told when its deadline passes. A refusal changes
/// nothing here at all.
///
/// `held_bytes` is what the connection holds, counted conservatively: the last
/// footprint it measured plus everything that could have grown since. Counting
/// the unmeasured remainder is what keeps a turn that advances several parked
/// streams from admitting a whole grant apiece, and it is what leaves the send
/// side with no measurement slack of its own.
///
/// `buffer_room` is the per-stream `Buffer` ceiling the application chose, and
/// the narrower of the two binds. Which one that was is carried out with the
/// count, because a write that ends up parked has to name what it is waiting
/// on: the endpoint, or its own peer.
pub fn send_allowance(
  grant: Grant,
  held_bytes: Int,
  buffer_room: Int,
) -> Admission {
  let funded = int.max(0, granted_bytes(grant) - held_bytes)
  case funded < buffer_room {
    True -> Admission(funded, True)
    False -> Admission(int.max(0, buffer_room), False)
  }
}

/// The bytes this admission allows into a send buffer.
pub fn admitted_bytes(admission: Admission) -> Int {
  admission.bytes
}

/// Whether it is the endpoint memory grant, rather than the application's own
/// `Buffer` ceiling, that holds a write this admission has no more room for.
///
/// The two are different answers to the caller. A write the `Buffer` ceiling
/// holds is waiting on its own peer to acknowledge what is already buffered; a
/// write the grant holds was never going to be funded until the endpoint has
/// room for it, whether or not a refusal has landed yet. A grant with no room
/// left and a ceiling with none are both exhausted, and then the ceiling is
/// what the caller is waiting on, because the endpoint funding more would not
/// move the write along.
pub fn grant_bound(admission: Admission) -> Bool {
  admission.grant_bound
}

/// Apply an endpoint's answer that met the request in full.
pub fn apply_grant(grant: Grant, sequence: Int, quanta: Int) -> Grant {
  settle(grant, sequence, quanta, False)
}

/// Apply an endpoint's answer that fell short of the request. The quanta named
/// are what the endpoint could actually cover, so a partial grant is still
/// installed; it is the shortfall that holds the connection where it is.
pub fn apply_refusal(grant: Grant, sequence: Int, quanta: Int) -> Grant {
  settle(grant, sequence, quanta, True)
}

/// Install an answer, but only the answer to the newest outstanding request.
fn settle(grant: Grant, sequence: Int, quanta: Int, refused: Bool) -> Grant {
  case sequence == grant.sequence {
    False -> grant
    True ->
      Grant(
        ..grant,
        granted: int.max(0, quanta),
        awaiting: False,
        refused: refused,
      )
  }
}

/// The grant a connection holding `held_bytes` wants, or the grant it already
/// has when it wants nothing.
///
/// A connection keeps one whole growth step of headroom above what it holds,
/// and never more than two, so neither growing nor shrinking by a byte can
/// start a conversation with its endpoint.
///
/// The headroom is asked for before it is needed rather than when it runs out,
/// because it is the room the connection advertises receive credit into: a
/// connection that waited until it was full to ask would have nothing to offer
/// a peer in the meantime, and every window update would be a round trip to
/// the endpoint.
fn wanted_quanta(held_bytes: Int, granted: Int) -> Int {
  let step = growth_step_bytes / quantum_bytes
  let held = whole_quanta(held_bytes) / quantum_bytes
  let target = held + step
  case granted < target, granted > held + 2 * step {
    True, _ -> target
    False, True -> target
    False, False -> granted
  }
}

/// One endpoint's byte budget: what each of its connections holds, and the
/// requests it could not meet.
///
/// `withheld` is the whole of the endpoint's retry bookkeeping, and it is
/// keyed by connection, so it is bounded by the connection set itself: one
/// connection waits on at most one request, a newer request from the same
/// connection replaces the older one, and a released connection takes its
/// entry with it. `arrivals` orders the retries first-in-first-out without a
/// queue that could outlive the connections in it.
pub opaque type Budget {
  Budget(
    limit: Int,
    used: Int,
    held: Dict(BitArray, Int),
    withheld: Dict(BitArray, Withheld),
    arrivals: Int,
  )
}

/// One request the endpoint could not meet, and its place in the queue.
type Withheld {
  Withheld(sequence: Int, quanta: Int, arrived: Int)
}

/// A request the endpoint could not meet when it was made and can meet now.
pub type Retry {
  Retry(connection: BitArray, sequence: Int, quanta: Int)
}

/// What an endpoint answered one connection's request with.
pub type Answer {
  /// The request was met in full: this connection may hold `quanta`.
  Met(quanta: Int)
  /// The endpoint is at its budget. `quanta` is what it could actually cover,
  /// which is installed, and the shortfall holds the connection where it is
  /// until `retry_withheld` finds room for the rest.
  Short(quanta: Int)
}

/// The accounting quantum in bytes.
pub fn quantum() -> Int {
  quantum_bytes
}

/// The step, in bytes, that a connection asks for room in and keeps ahead of
/// what it holds.
pub fn growth_step() -> Int {
  growth_step_bytes
}

/// The whole quanta an endpoint charges to admit one connection: its handshake
/// working set plus the connection-level receive credit it will advertise in
/// the handshake.
///
/// Charging for the advertised credit rather than for the working set alone is
/// what makes the endpoint bound a bound rather than an aspiration. Everything
/// a connection may hold beyond this is asked for first and granted second.
pub fn admission_quanta() -> Int {
  { working_set_bytes + initial_receive_credit_bytes } / quantum_bytes
}

/// The connection-level receive credit admission funds, in bytes, which is
/// what a server may advertise as its InitialMaxData.
pub fn initial_receive_credit() -> Int {
  initial_receive_credit_bytes
}

/// An empty budget for one endpoint, bounded by its configured maximum.
pub fn new(limit: Int) -> Budget {
  Budget(int.max(0, limit), 0, dict.new(), dict.new(), 0)
}

/// The bytes this endpoint's connections hold between them, in whole quanta.
pub fn used(ledger: Budget) -> Int {
  ledger.used
}

/// Charge one connection for `bytes` more, rounded up to whole quanta.
///
/// The charge is added to what the connection already holds, so growth is
/// priced from the connection's current footprint rather than from zero. A
/// charge that would take the endpoint past its limit is refused whole and
/// leaves the ledger exactly as it was.
pub fn reserve(
  ledger: Budget,
  connection: BitArray,
  bytes: Int,
) -> Result(Budget, failure.Failure) {
  let charge = whole_quanta(bytes)
  case ledger.used + charge > ledger.limit {
    True -> Error(failure.Limit(failure.EndpointMemory, ledger.limit))
    False ->
      Ok(
        Budget(
          ..ledger,
          used: ledger.used + charge,
          held: dict.insert(
            ledger.held,
            connection,
            holding(ledger, connection) + charge,
          ),
        ),
      )
  }
}

/// Return `bytes` of one connection's reservation, rounded up to whole quanta.
///
/// Releasing more than the connection holds is rejected rather than credited,
/// so no sequence of releases can push the endpoint's total below what its
/// connections actually hold.
pub fn release(
  ledger: Budget,
  connection: BitArray,
  bytes: Int,
) -> Result(Budget, Nil) {
  let credit = whole_quanta(bytes)
  let holds = holding(ledger, connection)
  case credit > holds {
    True -> Error(Nil)
    False -> Ok(with_holding(ledger, connection, holds - credit, credit))
  }
}

/// Return everything one connection holds, once.
///
/// Releasing a connection that holds nothing is free, which is what makes the
/// listener's two release paths -- the actor's `Released` notice and the
/// monitor `Down` for the same actor -- safe to run in either order.
pub fn release_all(ledger: Budget, connection: BitArray) -> Budget {
  let ledger = with_holding(ledger, connection, 0, holding(ledger, connection))
  forget_withheld(ledger, connection)
}

/// Answer one connection's request to hold `quanta` whole quanta in total.
///
/// This is the endpoint half of grant-before-growth, and the request is
/// deliberately a total rather than an increment: the ledger already knows what
/// this connection holds, so a request that crosses an answer in flight cannot
/// be charged twice, and a request for less than the connection holds is memory
/// coming back rather than memory being demanded.
///
/// Growth is filled as far as the budget reaches rather than refused whole, so
/// the endpoint ends up exactly at its budget instead of one connection short
/// of it. A request that could not be filled whole is answered `Short` and
/// kept; a request that was already waiting keeps its place in the queue, so a
/// connection refused over and over cannot be starved by newer arrivals.
pub fn answer_request(
  ledger: Budget,
  connection: BitArray,
  sequence: Int,
  quanta: Int,
) -> #(Budget, Answer) {
  let wanted = int.max(0, quanta)
  let holds = holding_quanta(ledger, connection)
  case wanted <= holds {
    True -> #(
      forget_withheld(shed(ledger, connection, holds - wanted), connection),
      Met(wanted),
    )
    False -> {
      let granted = holds + int.min(wanted - holds, spare_quanta(ledger))
      let ledger = charge(ledger, connection, granted - holds)
      case granted >= wanted {
        True -> #(forget_withheld(ledger, connection), Met(granted))
        False -> #(
          keep_withheld(ledger, connection, sequence, wanted),
          Short(granted),
        )
      }
    }
  }
}

/// Meet the requests this endpoint could not meet before, oldest first, out of
/// whatever room has since come back.
///
/// Every path that returns memory runs this, and it is the whole of what stops
/// a refusal being sticky: a refused connection does not ask again -- it would
/// only be refused again, and a busy endpoint would spend itself answering the
/// same refusals -- so the endpoint owes it the retry. A connection that never
/// sends another byte is still granted the room its neighbour released.
///
/// A retry is all or nothing, and the walk stops at the first request it cannot
/// meet whole. Funding part of the request at the head would take memory from
/// the connection behind it without unblocking the one in front, and stepping
/// over the head would let a run of small requests starve an older large one.
pub fn retry_withheld(ledger: Budget) -> #(Budget, List(Retry)) {
  ledger.withheld
  |> dict.to_list
  |> list.sort(fn(left, right) {
    int.compare({ left.1 }.arrived, { right.1 }.arrived)
  })
  |> meet_in_order(ledger, [])
}

fn meet_in_order(
  waiting: List(#(BitArray, Withheld)),
  ledger: Budget,
  met: List(Retry),
) -> #(Budget, List(Retry)) {
  case waiting {
    [] -> #(ledger, list.reverse(met))
    [#(connection, request), ..rest] -> {
      let owed = request.quanta - holding_quanta(ledger, connection)
      case owed <= spare_quanta(ledger) {
        False -> #(ledger, list.reverse(met))
        True ->
          meet_in_order(
            rest,
            forget_withheld(charge(ledger, connection, owed), connection),
            [Retry(connection, request.sequence, request.quanta), ..met],
          )
      }
    }
  }
}

/// The whole quanta this endpoint has left to give.
fn spare_quanta(ledger: Budget) -> Int {
  int.max(0, ledger.limit - ledger.used) / quantum_bytes
}

/// The whole quanta one connection holds.
fn holding_quanta(ledger: Budget, connection: BitArray) -> Int {
  holding(ledger, connection) / quantum_bytes
}

/// Charge one connection `quanta` further quanta, which the caller has already
/// established the endpoint has room for.
fn charge(ledger: Budget, connection: BitArray, quanta: Int) -> Budget {
  case quanta <= 0 {
    True -> ledger
    False ->
      case reserve(ledger, connection, quanta * quantum_bytes) {
        // nolint: thrown_away_error -- the room was checked before the charge.
        Error(_reason) -> ledger
        Ok(charged) -> charged
      }
  }
}

/// Return the `quanta` one connection no longer holds.
fn shed(ledger: Budget, connection: BitArray, quanta: Int) -> Budget {
  case quanta <= 0 {
    True -> ledger
    False ->
      case release(ledger, connection, quanta * quantum_bytes) {
        Error(Nil) -> ledger
        Ok(released) -> released
      }
  }
}

fn keep_withheld(
  ledger: Budget,
  connection: BitArray,
  sequence: Int,
  quanta: Int,
) -> Budget {
  let arrived = case dict.get(ledger.withheld, connection) {
    // Already waiting: the newer request replaces the older one and keeps the
    // older one's place in the queue.
    Ok(waiting) -> waiting.arrived
    Error(Nil) -> ledger.arrivals
  }
  Budget(
    ..ledger,
    arrivals: ledger.arrivals + 1,
    withheld: dict.insert(
      ledger.withheld,
      connection,
      Withheld(sequence, quanta, arrived),
    ),
  )
}

fn forget_withheld(ledger: Budget, connection: BitArray) -> Budget {
  Budget(..ledger, withheld: dict.delete(ledger.withheld, connection))
}

fn with_holding(
  ledger: Budget,
  connection: BitArray,
  remaining: Int,
  credit: Int,
) -> Budget {
  Budget(
    ..ledger,
    used: int.max(0, ledger.used - credit),
    held: case remaining {
      0 -> dict.delete(ledger.held, connection)
      _ -> dict.insert(ledger.held, connection, remaining)
    },
  )
}

fn holding(ledger: Budget, connection: BitArray) -> Int {
  case dict.get(ledger.held, connection) {
    Ok(bytes) -> bytes
    Error(Nil) -> 0
  }
}

/// Round a byte count up to whole quanta, never below zero.
fn whole_quanta(bytes: Int) -> Int {
  case bytes <= 0 {
    True -> 0
    False -> { bytes + quantum_bytes - 1 } / quantum_bytes * quantum_bytes
  }
}
