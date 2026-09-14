//// Pure RFC 9113 stream lifecycle transitions.

/// The seven HTTP/2 stream states.
pub type State {
  Idle
  ReservedLocal
  ReservedRemote
  Open
  HalfClosedLocal
  HalfClosedRemote
  Closed
}

/// A frame is invalid for the current stream direction or reservation.
pub type Error {
  FrameOnIdle
  LocalSideClosed
  RemoteSideClosed
  StreamClosed
  WrongReservation
}

/// Reserve an idle promised stream for locally initiated server push.
pub fn reserve_local(state: State) -> Result(State, Error) {
  case state {
    Idle -> Ok(ReservedLocal)
    Closed -> Error(StreamClosed)
    _ -> Error(WrongReservation)
  }
}

/// Observe an idle promised stream reserved by the peer.
pub fn reserve_remote(state: State) -> Result(State, Error) {
  case state {
    Idle -> Ok(ReservedRemote)
    Closed -> Error(StreamClosed)
    _ -> Error(WrongReservation)
  }
}

/// Send a header section, opening an idle/local-reserved stream when needed.
pub fn send_headers(state: State, end_stream: Bool) -> Result(State, Error) {
  case state {
    Idle -> Ok(open_local(end_stream))
    ReservedLocal -> Ok(close_local(HalfClosedRemote, end_stream))
    Open | HalfClosedRemote -> Ok(close_local(state, end_stream))
    ReservedRemote -> Error(WrongReservation)
    HalfClosedLocal -> Error(LocalSideClosed)
    Closed -> Error(StreamClosed)
  }
}

/// Receive a header section, opening an idle/remote-reserved stream as needed.
pub fn receive_headers(state: State, end_stream: Bool) -> Result(State, Error) {
  case state {
    Idle -> Ok(open_remote(end_stream))
    ReservedRemote -> Ok(close_remote(HalfClosedLocal, end_stream))
    Open | HalfClosedLocal -> Ok(close_remote(state, end_stream))
    ReservedLocal -> Error(WrongReservation)
    HalfClosedRemote -> Error(RemoteSideClosed)
    Closed -> Error(StreamClosed)
  }
}

/// Send DATA in a locally open direction.
pub fn send_data(state: State, end_stream: Bool) -> Result(State, Error) {
  case state {
    Idle -> Error(FrameOnIdle)
    Open | HalfClosedRemote -> Ok(close_local(state, end_stream))
    HalfClosedLocal -> Error(LocalSideClosed)
    Closed -> Error(StreamClosed)
    ReservedLocal | ReservedRemote -> Error(WrongReservation)
  }
}

/// Receive DATA in a remotely open direction.
pub fn receive_data(state: State, end_stream: Bool) -> Result(State, Error) {
  case state {
    Idle -> Error(FrameOnIdle)
    Open | HalfClosedLocal -> Ok(close_remote(state, end_stream))
    HalfClosedRemote -> Error(RemoteSideClosed)
    Closed -> Error(StreamClosed)
    ReservedLocal | ReservedRemote -> Error(WrongReservation)
  }
}

/// Locally reset a non-idle stream.
pub fn send_reset(state: State) -> Result(State, Error) {
  reset(state)
}

/// Observe a peer reset; duplicate resets on a closed stream are harmless.
pub fn receive_reset(state: State) -> Result(State, Error) {
  reset(state)
}

fn reset(state: State) -> Result(State, Error) {
  case state {
    Idle -> Error(FrameOnIdle)
    Closed -> Ok(Closed)
    _ -> Ok(Closed)
  }
}

fn open_local(end_stream: Bool) -> State {
  case end_stream {
    True -> HalfClosedLocal
    False -> Open
  }
}

fn open_remote(end_stream: Bool) -> State {
  case end_stream {
    True -> HalfClosedRemote
    False -> Open
  }
}

fn close_local(state: State, end_stream: Bool) -> State {
  case state, end_stream {
    _, False -> state
    Open, True -> HalfClosedLocal
    HalfClosedRemote, True -> Closed
    _, True -> state
  }
}

fn close_remote(state: State, end_stream: Bool) -> State {
  case state, end_stream {
    _, False -> state
    Open, True -> HalfClosedRemote
    HalfClosedLocal, True -> Closed
    _, True -> state
  }
}
