//// Bounded QUIC STREAM send, receive, flow-control, and retransmission state.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam_quic/frame
import gleam_quic/internal/flow_control
import gleam_quic/internal/reassembler
import gleam_quic/stream_id
import gleam_quic/varint

type ReceiveStatus {
  ReceiveOpen
  ReceiveFin
  ReceiveResetPending(Int)
  ReceiveTerminal
}

type ByteRange {
  ByteRange(start: Int, end_exclusive: Int)
}

/// One pull from a stream receive buffer.
pub type ReadOutcome {
  ReadPending(State)
  ReadData(State, BitArray, finished: Bool, new_limit: Option(Int))
  ReadReset(
    State,
    application_error_code: Int,
    discarded_bytes: Int,
    new_limit: Option(Int),
  )
  ReadFinished(State)
}

/// One bounded transport poll from a stream send buffer.
pub type SendPoll {
  Emit(State, frame.Frame)
  SendBlocked(State, limit: Int)
  SendIdle(State)
}

/// Private state for one locally or remotely initiated QUIC stream.
pub opaque type State {
  State(
    identifier: Int,
    local_endpoint: stream_id.Initiator,
    receiver: flow_control.Receiver,
    sender: flow_control.Sender,
    reassembler: reassembler.Reassembler,
    highest_received: Int,
    delivered_bytes: Int,
    receive_status: ReceiveStatus,
    pending_send_data: BitArray,
    next_send_offset: Int,
    fin_requested: Bool,
    fin_emitted: Bool,
    fin_acknowledged: Bool,
    send_reset: Bool,
    retransmit: List(frame.Frame),
    acknowledged_ranges: List(ByteRange),
    unacknowledged_send_bytes: Int,
    maximum_buffered_send_bytes: Int,
  )
}

/// A stream direction, bound, final-size, or lifecycle violation.
pub type Error {
  InvalidInput
  NonByteAligned
  WrongDirection
  SendClosed
  SendBufferLimitExceeded(Int)
  ReceiveBufferLimitExceeded(Int)
  FlowControlFailure
  FinalSizeFailure
  ReassemblyFailure
  FrameMismatch
}

/// Create one stream with independent stream-level receive and send credit.
pub fn new(
  identifier: Int,
  local_endpoint: stream_id.Initiator,
  initial_receive_limit: Int,
  receive_update_window: Int,
  maximum_receive_limit: Int,
  initial_send_limit: Int,
  maximum_buffered_receive_bytes: Int,
  maximum_buffered_send_bytes: Int,
  maximum_final_size: Int,
) -> Result(State, Error) {
  use _ <- result.try(validate_configuration(
    identifier,
    maximum_buffered_send_bytes,
  ))
  use receiver <- result.try(create_receiver(
    initial_receive_limit,
    receive_update_window,
    maximum_receive_limit,
  ))
  use sender <- result.try(create_sender(initial_send_limit))
  use byte_stream <- result.try(create_reassembler(
    maximum_buffered_receive_bytes,
    maximum_final_size,
  ))
  Ok(State(
    identifier: identifier,
    local_endpoint: local_endpoint,
    receiver: receiver,
    sender: sender,
    reassembler: byte_stream,
    highest_received: 0,
    delivered_bytes: 0,
    receive_status: ReceiveOpen,
    pending_send_data: <<>>,
    next_send_offset: 0,
    fin_requested: False,
    fin_emitted: False,
    fin_acknowledged: False,
    send_reset: False,
    retransmit: [],
    acknowledged_ranges: [],
    unacknowledged_send_bytes: 0,
    maximum_buffered_send_bytes: maximum_buffered_send_bytes,
  ))
}

/// Insert STREAM bytes and return newly consumed flow-control offset space.
pub fn receive_data(
  state: State,
  offset: Int,
  data: BitArray,
  fin: Bool,
) -> Result(#(State, Int), Error) {
  case stream_id.can_receive(state.identifier, state.local_endpoint) {
    False -> Error(WrongDirection)
    True -> receive_permitted(state, offset, data, fin)
  }
}

/// Apply RESET_STREAM final size and release any buffered unread payload.
pub fn receive_reset(
  state: State,
  application_error_code: Int,
  final_size: Int,
) -> Result(#(State, Int), Error) {
  case
    stream_id.can_receive(state.identifier, state.local_endpoint)
    && application_error_code >= 0
    && application_error_code <= varint.maximum
    && final_size >= 0
    && final_size <= varint.maximum
  {
    False -> Error(InvalidInput)
    True -> receive_valid_reset(state, application_error_code, final_size)
  }
}

/// Pull at most a bounded amount of contiguous data or one terminal event.
pub fn read(state: State, maximum_bytes: Int) -> Result(ReadOutcome, Error) {
  case stream_id.can_receive(state.identifier, state.local_endpoint) {
    False -> Error(WrongDirection)
    True if maximum_bytes <= 0 -> Error(InvalidInput)
    True ->
      case state.receive_status {
        ReceiveResetPending(error_code) -> deliver_reset(state, error_code)
        ReceiveTerminal -> Ok(ReadFinished(state))
        ReceiveOpen | ReceiveFin -> read_contiguous(state, maximum_bytes)
      }
  }
}

/// Queue application bytes with an explicit per-stream memory bound.
pub fn queue_send(
  state: State,
  data: BitArray,
  fin: Bool,
) -> Result(State, Error) {
  case bit_array.bit_size(data) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> queue_aligned(state, data, fin)
  }
}

/// Prioritize retransmission, then emit new bytes within flow-control credit.
pub fn poll_send(
  state: State,
  maximum_data_bytes: Int,
) -> Result(SendPoll, Error) {
  case stream_id.can_send(state.identifier, state.local_endpoint) {
    False -> Error(WrongDirection)
    True if maximum_data_bytes <= 0 -> Error(InvalidInput)
    True if state.send_reset -> Ok(SendIdle(state))
    True -> poll_permitted_send(state, maximum_data_bytes)
  }
}

/// Apply a monotonic peer MAX_STREAM_DATA value.
pub fn update_send_limit(state: State, advertised_limit: Int) -> State {
  State(
    ..state,
    sender: flow_control.update_sender_limit(state.sender, advertised_limit),
  )
}

/// Deduplicate acknowledged STREAM byte ranges and release send-buffer credit.
pub fn on_frame_acked(
  state: State,
  sent_frame: frame.Frame,
) -> Result(State, Error) {
  case sent_frame {
    frame.Stream(identifier, offset, data, fin) ->
      acknowledge_stream_frame(state, identifier, offset, data, fin)
    _ -> Error(FrameMismatch)
  }
}

/// Requeue a lost STREAM frame unless another copy already acknowledged it.
pub fn on_frame_lost(
  state: State,
  sent_frame: frame.Frame,
) -> Result(State, Error) {
  case sent_frame {
    frame.Stream(identifier, offset, data, fin) ->
      lose_stream_frame(state, identifier, offset, data, fin, sent_frame)
    _ -> Error(FrameMismatch)
  }
}

/// Abort local sending and construct RESET_STREAM with the emitted final size.
pub fn reset_send(
  state: State,
  application_error_code: Int,
) -> Result(#(State, frame.Frame), Error) {
  case
    stream_id.can_send(state.identifier, state.local_endpoint)
    && application_error_code >= 0
    && application_error_code <= varint.maximum
  {
    False -> Error(InvalidInput)
    True if state.send_reset -> Error(SendClosed)
    True ->
      Ok(#(
        State(
          ..state,
          pending_send_data: <<>>,
          fin_requested: False,
          retransmit: [],
          unacknowledged_send_bytes: 0,
          send_reset: True,
        ),
        frame.ResetStream(
          state.identifier,
          application_error_code,
          state.next_send_offset,
        ),
      ))
  }
}

/// Return unread out-of-order receive bytes retained in memory.
pub fn buffered_receive_bytes(state: State) -> Int {
  reassembler.buffered_bytes(state.reassembler)
}

/// Return queued plus emitted unique bytes awaiting acknowledgment.
pub fn buffered_send_bytes(state: State) -> Int {
  bit_array.byte_size(state.pending_send_data) + state.unacknowledged_send_bytes
}

/// Highest unique STREAM offset reserved by this stream's sender.
pub fn next_send_offset(state: State) -> Int {
  state.next_send_offset
}

/// Return whether FIN was acknowledged or local sending was reset.
pub fn send_finished(state: State) -> Bool {
  state.fin_acknowledged || state.send_reset
}

/// Return whether every direction available to the local endpoint is closed.
pub fn is_terminal(state: State) -> Bool {
  let receive_finished =
    !stream_id.can_receive(state.identifier, state.local_endpoint)
    || state.receive_status == ReceiveTerminal
  let local_send_finished =
    !stream_id.can_send(state.identifier, state.local_endpoint)
    || send_finished(state)
  receive_finished && local_send_finished
}

fn validate_configuration(
  identifier: Int,
  maximum_buffered_send_bytes: Int,
) -> Result(Nil, Error) {
  case stream_id.decode(identifier), maximum_buffered_send_bytes >= 0 {
    Error(_), _ | _, False -> Error(InvalidInput)
    Ok(_), True -> Ok(Nil)
  }
}

fn create_receiver(
  initial_limit: Int,
  update_window: Int,
  maximum_limit: Int,
) -> Result(flow_control.Receiver, Error) {
  case flow_control.new_receiver(initial_limit, update_window, maximum_limit) {
    Ok(receiver) -> Ok(receiver)
    Error(_) -> Error(InvalidInput)
  }
}

fn create_sender(initial_limit: Int) -> Result(flow_control.Sender, Error) {
  case flow_control.new_sender(initial_limit) {
    Ok(sender) -> Ok(sender)
    Error(_) -> Error(InvalidInput)
  }
}

fn create_reassembler(
  maximum_buffered_bytes: Int,
  maximum_final_size: Int,
) -> Result(reassembler.Reassembler, Error) {
  case reassembler.new(maximum_buffered_bytes, maximum_final_size) {
    Ok(state) -> Ok(state)
    Error(_) -> Error(InvalidInput)
  }
}

fn receive_permitted(
  state: State,
  offset: Int,
  data: BitArray,
  fin: Bool,
) -> Result(#(State, Int), Error) {
  case bit_array.bit_size(data) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      let end = offset + bit_array.byte_size(data)
      case offset < 0 || end < offset || end > varint.maximum {
        True -> Error(InvalidInput)
        False -> insert_received_data(state, offset, end, data, fin)
      }
    }
  }
}

fn insert_received_data(
  state: State,
  offset: Int,
  end: Int,
  data: BitArray,
  fin: Bool,
) -> Result(#(State, Int), Error) {
  let newly_received = maximum(0, end - state.highest_received)
  use receiver <- result.try(receive_credit(state.receiver, newly_received))
  use byte_stream <- result.try(insert_reassembly(
    state.reassembler,
    offset,
    data,
    fin,
  ))
  let status = next_receive_status(state.receive_status, fin)
  Ok(#(
    State(
      ..state,
      receiver: receiver,
      reassembler: byte_stream,
      highest_received: maximum(state.highest_received, end),
      receive_status: status,
    ),
    newly_received,
  ))
}

fn next_receive_status(current: ReceiveStatus, fin: Bool) -> ReceiveStatus {
  case current, fin {
    ReceiveResetPending(_), _ | ReceiveTerminal, _ -> current
    _, True -> ReceiveFin
    _, False -> current
  }
}

fn receive_valid_reset(
  state: State,
  application_error_code: Int,
  final_size: Int,
) -> Result(#(State, Int), Error) {
  let newly_received = maximum(0, final_size - state.highest_received)
  use receiver <- result.try(receive_credit(state.receiver, newly_received))
  use with_final <- result.try(insert_reassembly(
    state.reassembler,
    final_size,
    <<>>,
    True,
  ))
  use discarded <- result.try(discard_reassembly(with_final))
  Ok(#(
    State(
      ..state,
      receiver: receiver,
      reassembler: discarded,
      highest_received: maximum(state.highest_received, final_size),
      receive_status: ReceiveResetPending(application_error_code),
    ),
    newly_received,
  ))
}

fn receive_credit(
  receiver: flow_control.Receiver,
  newly_received: Int,
) -> Result(flow_control.Receiver, Error) {
  case flow_control.receive(receiver, newly_received) {
    Ok(updated) -> Ok(updated)
    Error(_) -> Error(FlowControlFailure)
  }
}

fn insert_reassembly(
  byte_stream: reassembler.Reassembler,
  offset: Int,
  data: BitArray,
  fin: Bool,
) -> Result(reassembler.Reassembler, Error) {
  case reassembler.insert(byte_stream, offset, data, fin) {
    Ok(updated) -> Ok(updated)
    Error(reassembler.BufferLimitExceeded(bytes)) ->
      Error(ReceiveBufferLimitExceeded(bytes))
    Error(reassembler.FinalSizeChanged)
    | Error(reassembler.FinalSizeTooSmall)
    | Error(reassembler.BeyondFinalSize) -> Error(FinalSizeFailure)
    Error(_) -> Error(ReassemblyFailure)
  }
}

fn discard_reassembly(
  byte_stream: reassembler.Reassembler,
) -> Result(reassembler.Reassembler, Error) {
  case reassembler.discard_to_final(byte_stream) {
    Ok(updated) -> Ok(updated)
    Error(_) -> Error(FinalSizeFailure)
  }
}

fn deliver_reset(state: State, error_code: Int) -> Result(ReadOutcome, Error) {
  let discarded_bytes = state.highest_received - state.delivered_bytes
  use #(receiver, new_limit) <- result.try(consume_credit(
    state.receiver,
    discarded_bytes,
  ))
  Ok(ReadReset(
    State(
      ..state,
      receiver: receiver,
      delivered_bytes: state.highest_received,
      receive_status: ReceiveTerminal,
    ),
    error_code,
    discarded_bytes,
    new_limit,
  ))
}

fn read_contiguous(
  state: State,
  maximum_bytes: Int,
) -> Result(ReadOutcome, Error) {
  case reassembler.read(state.reassembler, maximum_bytes) {
    Error(_) -> Error(ReassemblyFailure)
    Ok(reassembler.Read(byte_stream, data, finished)) ->
      finish_read(state, byte_stream, data, finished)
  }
}

fn finish_read(
  state: State,
  byte_stream: reassembler.Reassembler,
  data: BitArray,
  finished: Bool,
) -> Result(ReadOutcome, Error) {
  let count = bit_array.byte_size(data)
  case count == 0 && !finished {
    True -> Ok(ReadPending(State(..state, reassembler: byte_stream)))
    False -> {
      use #(receiver, new_limit) <- result.try(consume_credit(
        state.receiver,
        count,
      ))
      let status = case finished {
        True -> ReceiveTerminal
        False -> state.receive_status
      }
      Ok(ReadData(
        State(
          ..state,
          receiver: receiver,
          reassembler: byte_stream,
          delivered_bytes: state.delivered_bytes + count,
          receive_status: status,
        ),
        data,
        finished,
        new_limit,
      ))
    }
  }
}

fn consume_credit(
  receiver: flow_control.Receiver,
  bytes: Int,
) -> Result(#(flow_control.Receiver, Option(Int)), Error) {
  case flow_control.consume(receiver, bytes) {
    Ok(updated) -> Ok(updated)
    Error(_) -> Error(FlowControlFailure)
  }
}

fn queue_aligned(
  state: State,
  data: BitArray,
  fin: Bool,
) -> Result(State, Error) {
  case stream_id.can_send(state.identifier, state.local_endpoint) {
    False -> Error(WrongDirection)
    True if state.send_reset || state.fin_requested -> Error(SendClosed)
    True -> queue_open_send(state, data, fin)
  }
}

fn queue_open_send(
  state: State,
  data: BitArray,
  fin: Bool,
) -> Result(State, Error) {
  let next_buffered = buffered_send_bytes(state) + bit_array.byte_size(data)
  case next_buffered > state.maximum_buffered_send_bytes {
    True -> Error(SendBufferLimitExceeded(next_buffered))
    False ->
      Ok(
        State(
          ..state,
          pending_send_data: <<state.pending_send_data:bits, data:bits>>,
          fin_requested: fin,
        ),
      )
  }
}

fn poll_permitted_send(
  state: State,
  maximum_data_bytes: Int,
) -> Result(SendPoll, Error) {
  case state.retransmit, state.pending_send_data {
    [next, ..rest], _ ->
      emit_retransmission(state, next, rest, maximum_data_bytes)
    [], <<>> if state.fin_requested && !state.fin_emitted ->
      emit_empty_fin(state)
    [], <<>> -> Ok(SendIdle(state))
    [], _ -> emit_new_data(state, maximum_data_bytes)
  }
}

fn emit_retransmission(
  state: State,
  retransmission: frame.Frame,
  rest: List(frame.Frame),
  maximum_data_bytes: Int,
) -> Result(SendPoll, Error) {
  case retransmission {
    frame.Stream(identifier, offset, data, fin) -> {
      let length = bit_array.byte_size(data)
      case length <= maximum_data_bytes {
        True -> Ok(Emit(State(..state, retransmit: rest), retransmission))
        False ->
          split_retransmission(
            state,
            rest,
            identifier,
            offset,
            data,
            fin,
            maximum_data_bytes,
          )
      }
    }
    _ -> Error(FrameMismatch)
  }
}

fn split_retransmission(
  state: State,
  rest: List(frame.Frame),
  identifier: Int,
  offset: Int,
  data: BitArray,
  fin: Bool,
  count: Int,
) -> Result(SendPoll, Error) {
  use #(prefix, suffix) <- result.try(split(data, count))
  let emitted = frame.Stream(identifier, offset, prefix, False)
  let remaining = frame.Stream(identifier, offset + count, suffix, fin)
  Ok(Emit(State(..state, retransmit: [remaining, ..rest]), emitted))
}

fn emit_new_data(
  state: State,
  maximum_data_bytes: Int,
) -> Result(SendPoll, Error) {
  let credit =
    flow_control.sender_limit(state.sender)
    - flow_control.sent_bytes(state.sender)
  case credit <= 0 {
    True -> Ok(SendBlocked(state, flow_control.sender_limit(state.sender)))
    False -> emit_with_credit(state, maximum_data_bytes, credit)
  }
}

fn emit_with_credit(
  state: State,
  maximum_data_bytes: Int,
  credit: Int,
) -> Result(SendPoll, Error) {
  let count =
    minimum(
      bit_array.byte_size(state.pending_send_data),
      minimum(maximum_data_bytes, credit),
    )
  use #(prefix, suffix) <- result.try(split(state.pending_send_data, count))
  use sender <- result.try(reserve_credit(state.sender, count))
  let fin = suffix == <<>> && state.fin_requested
  let emitted =
    frame.Stream(state.identifier, state.next_send_offset, prefix, fin)
  Ok(Emit(
    State(
      ..state,
      sender: sender,
      pending_send_data: suffix,
      next_send_offset: state.next_send_offset + count,
      fin_emitted: state.fin_emitted || fin,
      unacknowledged_send_bytes: state.unacknowledged_send_bytes + count,
    ),
    emitted,
  ))
}

fn reserve_credit(
  sender: flow_control.Sender,
  bytes: Int,
) -> Result(flow_control.Sender, Error) {
  case flow_control.reserve(sender, bytes) {
    Ok(updated) -> Ok(updated)
    Error(_) -> Error(FlowControlFailure)
  }
}

fn emit_empty_fin(state: State) -> Result(SendPoll, Error) {
  Ok(Emit(
    State(..state, fin_emitted: True),
    frame.Stream(state.identifier, state.next_send_offset, <<>>, True),
  ))
}

fn acknowledge_stream_frame(
  state: State,
  identifier: Int,
  offset: Int,
  data: BitArray,
  fin: Bool,
) -> Result(State, Error) {
  use end <- result.try(validate_sent_frame(state, identifier, offset, data))
  let before = total_range_bytes(state.acknowledged_ranges, 0)
  let ranges = case end > offset {
    True ->
      insert_byte_range(state.acknowledged_ranges, ByteRange(offset, end), [])
    False -> state.acknowledged_ranges
  }
  let newly_acknowledged = total_range_bytes(ranges, 0) - before
  let fin_acknowledged = state.fin_acknowledged || fin
  let provisional =
    State(
      ..state,
      acknowledged_ranges: ranges,
      fin_acknowledged: fin_acknowledged,
      unacknowledged_send_bytes: maximum(
        0,
        state.unacknowledged_send_bytes - newly_acknowledged,
      ),
    )
  Ok(
    State(
      ..provisional,
      retransmit: list.filter(provisional.retransmit, fn(candidate) {
        !frame_fully_acknowledged(provisional, candidate)
      }),
    ),
  )
}

fn lose_stream_frame(
  state: State,
  identifier: Int,
  offset: Int,
  data: BitArray,
  fin: Bool,
  lost_frame: frame.Frame,
) -> Result(State, Error) {
  use _ <- result.try(validate_sent_frame(state, identifier, offset, data))
  case
    state.send_reset
    || byte_range_acknowledged(state, offset, bit_array.byte_size(data))
    && { !fin || state.fin_acknowledged }
    || frame_is_queued(state.retransmit, lost_frame)
  {
    True -> Ok(state)
    False -> Ok(State(..state, retransmit: [lost_frame, ..state.retransmit]))
  }
}

fn validate_sent_frame(
  state: State,
  identifier: Int,
  offset: Int,
  data: BitArray,
) -> Result(Int, Error) {
  let end = offset + bit_array.byte_size(data)
  case
    bit_array.bit_size(data) % 8 == 0
    && identifier == state.identifier
    && offset >= 0
    && end >= offset
    && end <= state.next_send_offset
  {
    True -> Ok(end)
    False -> Error(FrameMismatch)
  }
}

fn frame_is_queued(frames: List(frame.Frame), candidate: frame.Frame) -> Bool {
  list.any(frames, fn(existing) { existing == candidate })
}

fn frame_fully_acknowledged(state: State, candidate: frame.Frame) -> Bool {
  case candidate {
    frame.Stream(identifier, offset, data, fin)
      if identifier == state.identifier
    ->
      byte_range_acknowledged(state, offset, bit_array.byte_size(data))
      && { !fin || state.fin_acknowledged }
    _ -> False
  }
}

fn byte_range_acknowledged(state: State, offset: Int, length: Int) -> Bool {
  case length {
    0 -> True
    _ ->
      list.any(state.acknowledged_ranges, fn(range) {
        range.start <= offset && range.end_exclusive >= offset + length
      })
  }
}

fn insert_byte_range(
  ranges: List(ByteRange),
  incoming: ByteRange,
  before_reversed: List(ByteRange),
) -> List(ByteRange) {
  case ranges {
    [] -> list.append(list.reverse(before_reversed), [incoming])
    [current, ..rest] if incoming.end_exclusive < current.start ->
      list.append(list.reverse(before_reversed), [incoming, current, ..rest])
    [current, ..rest] if current.end_exclusive < incoming.start ->
      insert_byte_range(rest, incoming, [current, ..before_reversed])
    [current, ..rest] ->
      insert_byte_range(
        rest,
        ByteRange(
          minimum(current.start, incoming.start),
          maximum(current.end_exclusive, incoming.end_exclusive),
        ),
        before_reversed,
      )
  }
}

fn total_range_bytes(ranges: List(ByteRange), total: Int) -> Int {
  case ranges {
    [] -> total
    [range, ..rest] ->
      total_range_bytes(rest, total + range.end_exclusive - range.start)
  }
}

fn split(bytes: BitArray, count: Int) -> Result(#(BitArray, BitArray), Error) {
  case count < 0 || count > bit_array.byte_size(bytes) {
    True -> Error(InvalidInput)
    False -> {
      let prefix_bits = count * 8
      case bytes {
        <<prefix:bits-size(prefix_bits), suffix:bits>> -> Ok(#(prefix, suffix))
        _ -> Error(InvalidInput)
      }
    }
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
