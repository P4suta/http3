//// Finite HTTP/2 stream identifier, lifecycle, and flow-control registry.

import gleam/dict.{type Dict}
import gleam/option.{type Option, None, Some}
import gleam/result
import http/internal/http2/flow_control
import http/internal/http2/stream_state as lifecycle

const maximum_stream_id = 0x7fff_ffff

/// The local endpoint role, which determines stream identifier parity.
pub type Role {
  Client
  Server
}

/// A locally opened stream and its allocated identifier.
pub type Opened {
  Opened(state: State, stream_id: Int)
}

/// A transition on one known or newly accepted stream.
pub type Updated {
  Updated(state: State, stream_state: lifecycle.State)
}

/// Stream identifier, lifecycle, flow-control, or admission failure.
pub type Error {
  InvalidLimit
  InvalidStreamIdentifier
  StreamIdentifierExhausted
  WrongInitiator(stream_id: Int)
  UnreservedPeerStream(stream_id: Int)
  NonMonotonicPeerStream(previous: Int, received: Int)
  TooManyActiveStreams(maximum: Int)
  UnknownStream(stream_id: Int)
  StreamFailure(lifecycle.Error)
  FlowControlFailure(flow_control.Error)
}

type Stream {
  Stream(
    lifecycle: lifecycle.State,
    send_window: flow_control.Window,
    receive_window: flow_control.Window,
  )
}

/// Opaque registry retaining only active or reserved streams.
pub opaque type State {
  State(
    role: Role,
    maximum_active_streams: Int,
    streams: Dict(Int, Stream),
    next_local_stream_id: Int,
    highest_peer_stream_id: Option(Int),
    initial_send_window: flow_control.Window,
    initial_receive_window: flow_control.Window,
  )
}

/// Construct an empty registry with a strict aggregate active-stream limit.
pub fn new(role: Role, maximum_active_streams: Int) -> Result(State, Error) {
  case maximum_active_streams > 0 {
    False -> Error(InvalidLimit)
    True -> {
      use initial_send_window <- result.try(new_window(65_535))
      use initial_receive_window <- result.try(new_window(65_535))
      Ok(State(
        role:,
        maximum_active_streams:,
        streams: dict.new(),
        next_local_stream_id: case role {
          Client -> 1
          Server -> 2
        },
        highest_peer_stream_id: None,
        initial_send_window:,
        initial_receive_window:,
      ))
    }
  }
}

/// Allocate and open the next locally initiated stream.
pub fn open_local(state: State, end_stream: Bool) -> Result(Opened, Error) {
  use _ <- result.try(require_capacity(state))
  let stream_id = state.next_local_stream_id
  case stream_id > maximum_stream_id {
    True -> Error(StreamIdentifierExhausted)
    False -> {
      use next <- result.try(
        map_lifecycle(lifecycle.send_headers(lifecycle.Idle, end_stream)),
      )
      let state = State(..state, next_local_stream_id: stream_id + 2)
      Ok(Opened(store_new(state, stream_id, next), stream_id))
    }
  }
}

/// Reserve a monotonically increasing peer stream promised to a client.
pub fn reserve_remote(state: State, stream_id: Int) -> Result(State, Error) {
  use _ <- result.try(require_valid_stream_id(stream_id))
  use _ <- result.try(require_peer_initiated(state, stream_id))
  case state.role {
    Server -> Error(UnreservedPeerStream(stream_id: stream_id))
    Client -> {
      use _ <- result.try(require_new_peer_id(state, stream_id))
      use _ <- result.try(require_capacity(state))
      use reserved <- result.try(
        map_lifecycle(lifecycle.reserve_remote(lifecycle.Idle)),
      )
      let state = State(..state, highest_peer_stream_id: Some(stream_id))
      Ok(store_new(state, stream_id, reserved))
    }
  }
}

/// Receive HEADERS, opening a legal peer stream or advancing an existing one.
pub fn receive_headers(
  state: State,
  stream_id: Int,
  end_stream: Bool,
) -> Result(Updated, Error) {
  use _ <- result.try(require_valid_stream_id(stream_id))
  case dict.get(state.streams, stream_id) {
    Ok(stream) ->
      update_existing(
        state,
        stream_id,
        stream,
        lifecycle.receive_headers(stream.lifecycle, end_stream),
      )
    Error(Nil) -> receive_new_peer_headers(state, stream_id, end_stream)
  }
}

/// Send another header section on an existing stream.
pub fn send_headers(
  state: State,
  stream_id: Int,
  end_stream: Bool,
) -> Result(Updated, Error) {
  update_known(state, stream_id, fn(current) {
    lifecycle.send_headers(current, end_stream)
  })
}

/// Receive DATA without changing flow credit. Prefer consume_receive_data.
pub fn receive_data(
  state: State,
  stream_id: Int,
  end_stream: Bool,
) -> Result(Updated, Error) {
  update_known(state, stream_id, fn(current) {
    lifecycle.receive_data(current, end_stream)
  })
}

/// Send DATA without changing flow credit. Prefer consume_send_data.
pub fn send_data(
  state: State,
  stream_id: Int,
  end_stream: Bool,
) -> Result(Updated, Error) {
  update_known(state, stream_id, fn(current) {
    lifecycle.send_data(current, end_stream)
  })
}

/// Observe a peer RST_STREAM and release active admission immediately.
/// A duplicate reset for an already closed identifier is harmless.
pub fn receive_reset(state: State, stream_id: Int) -> Result(Updated, Error) {
  use _ <- result.try(require_valid_stream_id(stream_id))
  case dict.get(state.streams, stream_id) {
    Ok(stream) ->
      update_existing(
        state,
        stream_id,
        stream,
        lifecycle.receive_reset(stream.lifecycle),
      )
    Error(Nil) -> {
      use next <- result.try(
        map_lifecycle(lifecycle.receive_reset(derived_state(state, stream_id))),
      )
      Ok(Updated(state, next))
    }
  }
}

/// Send RST_STREAM for one known stream and release its active admission.
pub fn send_reset(state: State, stream_id: Int) -> Result(Updated, Error) {
  update_known(state, stream_id, fn(current) { lifecycle.send_reset(current) })
}

/// Consume outbound stream credit and advance lifecycle atomically.
pub fn consume_send_data(
  state: State,
  stream_id: Int,
  flow_controlled_octets: Int,
  end_stream: Bool,
) -> Result(Updated, Error) {
  use stream <- result.try(known_stream(state, stream_id))
  use window <- result.try(
    flow_control.consume(stream.send_window, flow_controlled_octets)
    |> map_flow,
  )
  use next <- result.try(
    map_lifecycle(lifecycle.send_data(stream.lifecycle, end_stream)),
  )
  let stream = Stream(..stream, lifecycle: next, send_window: window)
  Ok(Updated(store(state, stream_id, stream), next))
}

/// Consume inbound stream credit and advance lifecycle atomically.
pub fn consume_receive_data(
  state: State,
  stream_id: Int,
  flow_controlled_octets: Int,
  end_stream: Bool,
) -> Result(Updated, Error) {
  use stream <- result.try(known_stream(state, stream_id))
  use window <- result.try(
    flow_control.consume(stream.receive_window, flow_controlled_octets)
    |> map_flow,
  )
  use next <- result.try(
    map_lifecycle(lifecycle.receive_data(stream.lifecycle, end_stream)),
  )
  let stream = Stream(..stream, lifecycle: next, receive_window: window)
  Ok(Updated(store(state, stream_id, stream), next))
}

/// Apply a peer WINDOW_UPDATE to one active stream.
pub fn increase_send_window(
  state: State,
  stream_id: Int,
  increment: Int,
) -> Result(State, Error) {
  use stream <- result.try(known_stream(state, stream_id))
  use window <- result.try(
    flow_control.increase(stream.send_window, increment)
    |> map_flow,
  )
  Ok(store(state, stream_id, Stream(..stream, send_window: window)))
}

/// Restore locally granted inbound credit for one active stream.
pub fn restore_receive_window(
  state: State,
  stream_id: Int,
  increment: Int,
) -> Result(State, Error) {
  use stream <- result.try(known_stream(state, stream_id))
  use window <- result.try(
    flow_control.increase(stream.receive_window, increment)
    |> map_flow,
  )
  Ok(store(state, stream_id, Stream(..stream, receive_window: window)))
}

/// Apply SETTINGS_INITIAL_WINDOW_SIZE to all active outbound windows.
/// The transition is transactional if any stream would overflow.
pub fn apply_peer_initial_window_size(
  state: State,
  replacement: Int,
) -> Result(State, Error) {
  let previous = flow_control.available(state.initial_send_window)
  use initial <- result.try(new_window(replacement))
  use streams <- result.try(apply_initial_window_to_streams(
    dict.to_list(state.streams),
    dict.new(),
    previous,
    replacement,
  ))
  Ok(State(..state, streams: streams, initial_send_window: initial))
}

/// Current outbound credit for one active stream.
pub fn send_window(state: State, stream_id: Int) -> Result(Int, Error) {
  use stream <- result.try(known_stream(state, stream_id))
  Ok(flow_control.available(stream.send_window))
}

/// Current inbound credit for one active stream.
pub fn receive_window(state: State, stream_id: Int) -> Result(Int, Error) {
  use stream <- result.try(known_stream(state, stream_id))
  Ok(flow_control.available(stream.receive_window))
}

/// Return a known state, or derive Idle/Closed from monotonic identifiers.
pub fn stream_state(state: State, stream_id: Int) -> lifecycle.State {
  case dict.get(state.streams, stream_id) {
    Ok(stream) -> stream.lifecycle
    Error(Nil) -> derived_state(state, stream_id)
  }
}

/// Number of retained active and reserved streams.
pub fn active_count(state: State) -> Int {
  dict.size(state.streams)
}

/// Number of active streams initiated by this endpoint.
pub fn local_active_count(state: State) -> Int {
  count_local(state, dict.to_list(state.streams), 0)
}

/// Number of active streams initiated by the peer.
pub fn peer_active_count(state: State) -> Int {
  active_count(state) - local_active_count(state)
}

/// Highest accepted peer-initiated stream identifier.
pub fn highest_peer_stream_id(state: State) -> Option(Int) {
  state.highest_peer_stream_id
}

fn receive_new_peer_headers(
  state: State,
  stream_id: Int,
  end_stream: Bool,
) -> Result(Updated, Error) {
  use _ <- result.try(require_peer_initiated(state, stream_id))
  use _ <- result.try(require_new_peer_id(state, stream_id))
  case state.role {
    Client -> Error(UnreservedPeerStream(stream_id: stream_id))
    Server -> {
      use _ <- result.try(require_capacity(state))
      use next <- result.try(
        map_lifecycle(lifecycle.receive_headers(lifecycle.Idle, end_stream)),
      )
      let state = State(..state, highest_peer_stream_id: Some(stream_id))
      Ok(Updated(store_new(state, stream_id, next), next))
    }
  }
}

fn update_known(
  state: State,
  stream_id: Int,
  transition: fn(lifecycle.State) -> Result(lifecycle.State, lifecycle.Error),
) -> Result(Updated, Error) {
  use _ <- result.try(require_valid_stream_id(stream_id))
  case dict.get(state.streams, stream_id) {
    Ok(stream) ->
      update_existing(state, stream_id, stream, transition(stream.lifecycle))
    Error(Nil) -> {
      use _ <- result.try(
        map_lifecycle(transition(derived_state(state, stream_id))),
      )
      Error(UnknownStream(stream_id: stream_id))
    }
  }
}

fn update_existing(
  state: State,
  stream_id: Int,
  stream: Stream,
  transition: Result(lifecycle.State, lifecycle.Error),
) -> Result(Updated, Error) {
  use next <- result.try(map_lifecycle(transition))
  let stream = Stream(..stream, lifecycle: next)
  Ok(Updated(store(state, stream_id, stream), next))
}

fn store_new(
  state: State,
  stream_id: Int,
  lifecycle: lifecycle.State,
) -> State {
  store(
    state,
    stream_id,
    Stream(
      lifecycle:,
      send_window: state.initial_send_window,
      receive_window: state.initial_receive_window,
    ),
  )
}

fn store(state: State, stream_id: Int, stream: Stream) -> State {
  let streams = case stream.lifecycle {
    lifecycle.Closed -> dict.delete(state.streams, stream_id)
    _ -> dict.insert(state.streams, stream_id, stream)
  }
  State(..state, streams: streams)
}

fn known_stream(state: State, stream_id: Int) -> Result(Stream, Error) {
  use _ <- result.try(require_valid_stream_id(stream_id))
  case dict.get(state.streams, stream_id) {
    Ok(stream) -> Ok(stream)
    Error(Nil) -> Error(UnknownStream(stream_id: stream_id))
  }
}

fn apply_initial_window_to_streams(
  entries: List(#(Int, Stream)),
  updated: Dict(Int, Stream),
  previous: Int,
  replacement: Int,
) -> Result(Dict(Int, Stream), Error) {
  case entries {
    [] -> Ok(updated)
    [#(stream_id, stream), ..rest] -> {
      use send_window <- result.try(
        flow_control.apply_initial_window_size(
          stream.send_window,
          previous,
          replacement,
        )
        |> map_flow,
      )
      apply_initial_window_to_streams(
        rest,
        dict.insert(
          updated,
          stream_id,
          Stream(..stream, send_window: send_window),
        ),
        previous,
        replacement,
      )
    }
  }
}

fn derived_state(state: State, stream_id: Int) -> lifecycle.State {
  case valid_stream_id(stream_id) {
    False -> lifecycle.Idle
    True ->
      case locally_initiated(state, stream_id), state.highest_peer_stream_id {
        True, _ if stream_id < state.next_local_stream_id -> lifecycle.Closed
        False, Some(highest) if stream_id <= highest -> lifecycle.Closed
        _, _ -> lifecycle.Idle
      }
  }
}

fn count_local(state: State, entries: List(#(Int, Stream)), count: Int) -> Int {
  case entries {
    [] -> count
    [#(stream_id, _), ..rest] ->
      count_local(state, rest, case locally_initiated(state, stream_id) {
        True -> count + 1
        False -> count
      })
  }
}

fn require_capacity(state: State) -> Result(Nil, Error) {
  case dict.size(state.streams) < state.maximum_active_streams {
    True -> Ok(Nil)
    False -> Error(TooManyActiveStreams(maximum: state.maximum_active_streams))
  }
}

fn require_new_peer_id(state: State, stream_id: Int) -> Result(Nil, Error) {
  case state.highest_peer_stream_id {
    Some(previous) if stream_id <= previous ->
      Error(NonMonotonicPeerStream(previous:, received: stream_id))
    _ -> Ok(Nil)
  }
}

fn require_peer_initiated(state: State, stream_id: Int) -> Result(Nil, Error) {
  case locally_initiated(state, stream_id) {
    True -> Error(WrongInitiator(stream_id: stream_id))
    False -> Ok(Nil)
  }
}

fn require_valid_stream_id(stream_id: Int) -> Result(Nil, Error) {
  case valid_stream_id(stream_id) {
    True -> Ok(Nil)
    False -> Error(InvalidStreamIdentifier)
  }
}

fn valid_stream_id(stream_id: Int) -> Bool {
  stream_id > 0 && stream_id <= maximum_stream_id
}

fn locally_initiated(state: State, stream_id: Int) -> Bool {
  case state.role {
    Client -> stream_id % 2 == 1
    Server -> stream_id % 2 == 0
  }
}

fn new_window(initial: Int) -> Result(flow_control.Window, Error) {
  flow_control.new(initial)
  |> map_flow
}

fn map_flow(value: Result(value, flow_control.Error)) -> Result(value, Error) {
  result.map_error(value, FlowControlFailure)
}

fn map_lifecycle(
  value: Result(value, lifecycle.Error),
) -> Result(value, Error) {
  result.map_error(value, StreamFailure)
}
