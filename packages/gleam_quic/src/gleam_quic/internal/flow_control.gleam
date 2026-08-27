//// Bounded QUIC connection and stream flow-control accounting.

import gleam/option.{type Option, None, Some}
import gleam_quic/varint

const maximum_stream_count = 1_152_921_504_606_846_975

/// Receive-side aggregate credit and consumption state.
///
/// `hold` is the endpoint memory budget's grip on this receiver: the credit it
/// may have outstanding -- advertised but not yet read off -- until its
/// endpoint grants it more room. `None` is no grip at all, and it is what
/// every receiver starts with and what every receiver on a path with no
/// endpoint memory grant behind it keeps: per-stream receivers, and every
/// receiver on the client side. A receiver with no hold behaves exactly as it
/// did before endpoint memory grants existed.
pub opaque type Receiver {
  Receiver(
    limit: Int,
    received: Int,
    consumed: Int,
    update_window: Int,
    maximum_limit: Int,
    consumed_since_update: Int,
    hold: Option(Int),
  )
}

/// Send-side aggregate credit.
pub opaque type Sender {
  Sender(limit: Int, sent: Int)
}

/// Peer stream-count accounting by monotonically increasing stream index.
pub opaque type StreamLimit {
  StreamLimit(limit: Int, opened: Int)
}

/// A credit, consumption, or peer stream-count failure.
pub type Error {
  InvalidInput
  FlowControlLimitExceeded
  FlowControlBlocked(Int)
  ConsumptionExceedsReceived
  StreamAlreadyOpened
  StreamLimitExceeded(Int)
}

/// Configure receive credit and the increment used for MAX_DATA updates.
pub fn new_receiver(
  initial_limit: Int,
  update_window: Int,
  maximum_limit: Int,
) -> Result(Receiver, Error) {
  case
    initial_limit >= 0
    && update_window > 0
    && maximum_limit >= initial_limit
    && maximum_limit <= varint.maximum
  {
    True ->
      Ok(Receiver(initial_limit, 0, 0, update_window, maximum_limit, 0, None))
    False -> Error(InvalidInput)
  }
}

/// Account only newly received bytes after stream overlap deduplication.
pub fn receive(receiver: Receiver, new_bytes: Int) -> Result(Receiver, Error) {
  case new_bytes < 0 {
    True -> Error(InvalidInput)
    False if receiver.received + new_bytes > receiver.limit ->
      Error(FlowControlLimitExceeded)
    False -> Ok(Receiver(..receiver, received: receiver.received + new_bytes))
  }
}

/// Mark delivered bytes and optionally emit a new monotonic receive limit.
pub fn consume(
  receiver: Receiver,
  bytes: Int,
) -> Result(#(Receiver, Option(Int)), Error) {
  case bytes < 0 {
    True -> Error(InvalidInput)
    False if receiver.consumed + bytes > receiver.received ->
      Error(ConsumptionExceedsReceived)
    False -> consume_valid(receiver, bytes)
  }
}

/// Return the currently advertised receive limit.
pub fn receiver_limit(receiver: Receiver) -> Int {
  receiver.limit
}

/// Return the bytes the application has already read off this receiver.
pub fn consumed_bytes(receiver: Receiver) -> Int {
  receiver.consumed
}

/// Hold this receiver to `allowance` bytes of outstanding credit until its
/// endpoint grants it more room.
///
/// The hold is stated as an allowance over what has already been read rather
/// than as an absolute limit, so it stays true as the application reads
/// without having to be restated on every read: what it bounds is the credit
/// the peer still has in hand, which is exactly the memory the peer can still
/// make this endpoint hold.
///
/// The hold only ever stops the limit rising; it never retracts credit already
/// advertised, because a MAX_DATA or MAX_STREAM_DATA value the peer has seen
/// is a promise, and a peer is never punished for using credit this endpoint
/// advertised. Consumption keeps accumulating while the hold binds, so the
/// first read after it widens advertises the window that was withheld rather
/// than waiting for another window to be consumed.
pub fn with_memory_hold(receiver: Receiver, allowance: Int) -> Receiver {
  Receiver(..receiver, hold: Some(maximum(0, allowance)))
}

/// Configure peer-advertised send credit.
pub fn new_sender(initial_limit: Int) -> Result(Sender, Error) {
  case initial_limit >= 0 && initial_limit <= varint.maximum {
    True -> Ok(Sender(initial_limit, 0))
    False -> Error(InvalidInput)
  }
}

/// Reserve newly sent stream bytes against peer MAX_DATA credit.
pub fn reserve(sender: Sender, new_bytes: Int) -> Result(Sender, Error) {
  case new_bytes < 0 {
    True -> Error(InvalidInput)
    False if sender.sent + new_bytes > sender.limit ->
      Error(FlowControlBlocked(sender.limit))
    False -> Ok(Sender(..sender, sent: sender.sent + new_bytes))
  }
}

/// Apply a monotonic MAX_DATA or MAX_STREAM_DATA value.
pub fn update_sender_limit(sender: Sender, advertised_limit: Int) -> Sender {
  case advertised_limit > sender.limit && advertised_limit <= varint.maximum {
    True -> Sender(..sender, limit: advertised_limit)
    False -> sender
  }
}

/// Return the blocking offset if no additional byte can be sent.
pub fn blocked_at(sender: Sender) -> Option(Int) {
  case sender.sent >= sender.limit {
    True -> Some(sender.limit)
    False -> None
  }
}

/// Return peer-advertised send credit.
pub fn sender_limit(sender: Sender) -> Int {
  sender.limit
}

/// Return aggregate newly sent bytes.
pub fn sent_bytes(sender: Sender) -> Int {
  sender.sent
}

/// Configure a peer's maximum stream count for one directionality class.
pub fn new_stream_limit(limit: Int) -> Result(StreamLimit, Error) {
  case valid_stream_limit(limit) {
    True -> Ok(StreamLimit(limit, 0))
    False -> Error(InvalidInput)
  }
}

/// Open a stream index, implicitly accounting for any lower skipped indices.
pub fn open_stream(
  stream_limit: StreamLimit,
  stream_index: Int,
) -> Result(StreamLimit, Error) {
  case stream_index < 0 {
    True -> Error(InvalidInput)
    False if stream_index < stream_limit.opened -> Error(StreamAlreadyOpened)
    False if stream_index >= stream_limit.limit ->
      Error(StreamLimitExceeded(stream_limit.limit))
    False -> Ok(StreamLimit(..stream_limit, opened: stream_index + 1))
  }
}

/// Apply a monotonic MAX_STREAMS value.
pub fn update_stream_limit(
  stream_limit: StreamLimit,
  advertised_limit: Int,
) -> StreamLimit {
  case
    advertised_limit > stream_limit.limit
    && valid_stream_limit(advertised_limit)
  {
    True -> StreamLimit(..stream_limit, limit: advertised_limit)
    False -> stream_limit
  }
}

/// Return the stream count consumed by peer stream IDs.
pub fn opened_streams(stream_limit: StreamLimit) -> Int {
  stream_limit.opened
}

/// Return the stream count currently advertised to the peer.
pub fn advertised_stream_limit(stream_limit: StreamLimit) -> Int {
  stream_limit.limit
}

/// Replenish one unit of peer stream concurrency after a stream closes.
pub fn replenish_stream_limit(
  stream_limit: StreamLimit,
) -> #(StreamLimit, Option(Int)) {
  case stream_limit.limit < maximum_stream_count {
    False -> #(stream_limit, None)
    True -> {
      let next = stream_limit.limit + 1
      #(StreamLimit(..stream_limit, limit: next), Some(next))
    }
  }
}

fn consume_valid(
  receiver: Receiver,
  bytes: Int,
) -> Result(#(Receiver, Option(Int)), Error) {
  Ok(raise_limit(
    Receiver(
      ..receiver,
      consumed: receiver.consumed + bytes,
      consumed_since_update: receiver.consumed_since_update + bytes,
    ),
  ))
}

/// Advertise the credit this receiver now has room for, without the
/// application having read anything.
///
/// A read is the ordinary reason a limit rises, and it is not the only one: an
/// endpoint memory hold that widens makes room the peer is owed just as a read
/// does. Nothing here is a read, so nothing is consumed; the same deadband and
/// the same floor decide whether an update is due, so a hold that widened by
/// nothing worth stating still says nothing.
///
/// Without it a connection whose hold had squeezed its limit down to what the
/// peer had already spent would stall for good: the peer has no credit, so
/// nothing arrives, so the application is never woken to read, so the limit
/// that only a read can raise is never raised.
pub fn advertise_pending(receiver: Receiver) -> #(Receiver, Option(Int)) {
  raise_limit(receiver)
}

/// Raise the advertised limit if an update is due and there is room above it,
/// reporting the new limit when one was stated.
fn raise_limit(receiver: Receiver) -> #(Receiver, Option(Int)) {
  let highest = highest_limit(receiver, receiver.consumed)
  case
    update_due(receiver, receiver.consumed_since_update, highest)
    && receiver.limit < highest
  {
    False -> #(receiver, None)
    True -> {
      let next_limit = minimum(receiver.limit + receiver.update_window, highest)
      #(
        Receiver(..receiver, limit: next_limit, consumed_since_update: 0),
        Some(next_limit),
      )
    }
  }
}

fn valid_stream_limit(limit: Int) -> Bool {
  limit >= 0 && limit <= maximum_stream_count
}

/// The highest limit this receiver may advertise: its configured maximum, and
/// no more than one endpoint memory allowance above what has been read.
fn highest_limit(receiver: Receiver, consumed: Int) -> Int {
  case receiver.hold {
    None -> receiver.maximum_limit
    Some(allowance) -> minimum(receiver.maximum_limit, consumed + allowance)
  }
}

/// Whether a MAX_DATA or MAX_STREAM_DATA update is due.
///
/// The deadband is half an update window consumed since the last update, which
/// is what it has always been.
///
/// A held receiver keeps that deadband and adds a floor beneath it, because
/// the deadband alone would deadlock a connection whose hold is narrower than
/// one update window: the peer runs out of credit, so the application has
/// nothing left to read, so half a window is never consumed and the credit is
/// never returned. The floor is the peer having spent every byte of credit it
/// holds -- then it is given whatever there is room for, however little,
/// because a blocked peer with room going spare is the one case where a small
/// update is worth more than a quiet link. Nothing is added for a receiver
/// with no hold, so no path without an endpoint memory grant behind it changes
/// at all.
fn update_due(
  receiver: Receiver,
  consumed_since_update: Int,
  highest: Int,
) -> Bool {
  let ordinary = consumed_since_update >= receiver.update_window / 2
  case receiver.hold {
    None -> ordinary
    Some(_allowance) ->
      ordinary
      || highest - receiver.limit >= receiver.update_window / 2
      || receiver.received >= receiver.limit
  }
}

fn minimum(left: Int, right: Int) -> Int {
  case left < right {
    True -> left
    False -> right
  }
}

fn maximum(left: Int, right: Int) -> Int {
  case left > right {
    True -> left
    False -> right
  }
}
