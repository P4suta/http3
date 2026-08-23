import gleam_quic/internal/http3/stream_registry

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn parses_and_registers_each_unidirectional_stream_type_test() -> Nil {
  assert stream_registry.decode_preface(<<0, "control">>)
    == Ok(stream_registry.Preface(stream_registry.Control, <<"control">>))
  assert stream_registry.decode_preface(<<1, 5, "push">>)
    == Ok(stream_registry.Preface(stream_registry.Push(5), <<"push">>))
  assert stream_registry.decode_preface(<<2>>)
    == Ok(stream_registry.Preface(stream_registry.QpackEncoder, <<>>))
  assert stream_registry.decode_preface(<<3>>)
    == Ok(stream_registry.Preface(stream_registry.QpackDecoder, <<>>))
  assert stream_registry.decode_preface(<<0x40>>)
    == Error(stream_registry.TruncatedPreface)

  let assert Ok(state) = stream_registry.new(stream_registry.Server, 2)
  let assert Ok(state) = stream_registry.open(state, 3, stream_registry.Control)
  let assert Ok(state) =
    stream_registry.open(state, 7, stream_registry.QpackEncoder)
  let assert Ok(state) =
    stream_registry.open(state, 11, stream_registry.QpackDecoder)
  assert stream_registry.open(state, 15, stream_registry.Control)
    == Error(stream_registry.DuplicateControlStream)
  assert stream_registry.close(state, 7)
    == Error(stream_registry.ClosedCriticalStream(7))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_push_direction_id_and_resource_limits_test() -> Nil {
  let assert Ok(client) = stream_registry.new(stream_registry.Client, 1)
  assert stream_registry.open(client, 2, stream_registry.Push(0))
    == Error(stream_registry.PushStreamFromClient)
  assert stream_registry.open(client, 3, stream_registry.Control)
    == Error(stream_registry.InvalidStreamId(3))

  let assert Ok(server) = stream_registry.new(stream_registry.Server, 1)
  assert stream_registry.open(server, 3, stream_registry.Push(0))
    == Error(stream_registry.PushIdNotAllowed(0))
  let assert Ok(server) = stream_registry.permit_pushes_through(server, 2)
  let assert Ok(server) =
    stream_registry.open(server, 3, stream_registry.Push(0))
  assert stream_registry.active_push_streams(server) == 1
  assert stream_registry.open(server, 7, stream_registry.Push(0))
    == Error(stream_registry.DuplicatePushId(0))
  assert stream_registry.open(server, 7, stream_registry.Push(1))
    == Error(stream_registry.PushStreamLimitExceeded(1))
  let assert Ok(server) = stream_registry.close(server, 3)
  assert stream_registry.active_push_streams(server) == 0
  let assert Ok(server) =
    stream_registry.open(server, 7, stream_registry.Push(1))
  assert stream_registry.active_push_streams(server) == 1
  assert stream_registry.permit_pushes_through(server, 1)
    == Error(stream_registry.PushIdNotAllowed(1))
}
