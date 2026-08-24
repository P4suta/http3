//// Bounded QUIC connection and stream flow-control accounting.

import gleam/option.{type Option, None, Some}
import gleam_quic/varint

const maximum_stream_count = 1_152_921_504_606_846_975

/// Receive-side aggregate credit and consumption state.
pub opaque type Receiver {
  Receiver(
    limit: Int,
    received: Int,
    consumed: Int,
    update_window: Int,
    maximum_limit: Int,
    consumed_since_update: Int,
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
    True -> Ok(Receiver(initial_limit, 0, 0, update_window, maximum_limit, 0))
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
  let consumed_since_update = receiver.consumed_since_update + bytes
  let consumed = receiver.consumed + bytes
  case
    consumed_since_update >= receiver.update_window / 2
    && receiver.limit < receiver.maximum_limit
  {
    False ->
      Ok(#(
        Receiver(
          ..receiver,
          consumed: consumed,
          consumed_since_update: consumed_since_update,
        ),
        None,
      ))
    True -> {
      let next_limit =
        minimum(receiver.limit + receiver.update_window, receiver.maximum_limit)
      Ok(#(
        Receiver(
          ..receiver,
          limit: next_limit,
          consumed: consumed,
          consumed_since_update: 0,
        ),
        Some(next_limit),
      ))
    }
  }
}

fn valid_stream_limit(limit: Int) -> Bool {
  limit >= 0 && limit <= maximum_stream_count
}

fn minimum(left: Int, right: Int) -> Int {
  case left < right {
    True -> left
    False -> right
  }
}
