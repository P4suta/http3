import gleam_quic/internal/reassembler
import gleam_quic/stream_id

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn maps_all_stream_id_classes_and_permissions_test() -> Nil {
  assert stream_id.encode(0, stream_id.Client, stream_id.Bidirectional) == Ok(0)
  assert stream_id.encode(0, stream_id.Server, stream_id.Bidirectional) == Ok(1)
  assert stream_id.encode(0, stream_id.Client, stream_id.Unidirectional)
    == Ok(2)
  assert stream_id.encode(0, stream_id.Server, stream_id.Unidirectional)
    == Ok(3)
  assert stream_id.decode(10)
    == Ok(stream_id.StreamId(2, stream_id.Client, stream_id.Unidirectional))
  assert stream_id.can_send(10, stream_id.Client)
  assert !stream_id.can_send(10, stream_id.Server)
  assert stream_id.can_receive(10, stream_id.Server)
  assert !stream_id.can_receive(10, stream_id.Client)
  assert stream_id.can_send(1, stream_id.Client)
  assert stream_id.can_send(1, stream_id.Server)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn reassembles_out_of_order_and_reads_bounded_chunks_test() -> Nil {
  let assert Ok(state) = reassembler.new(10, 100)
  let assert Ok(state) = reassembler.insert(state, 5, <<"world">>, False)
  let assert Ok(reassembler.Read(state, <<>>, False)) =
    reassembler.read(state, 10)
  let assert Ok(state) = reassembler.insert(state, 0, <<"hello">>, False)
  let assert Ok(reassembler.Read(state, <<"hellowo">>, False)) =
    reassembler.read(state, 7)
  let assert Ok(reassembler.Read(state, <<"rld">>, False)) =
    reassembler.read(state, 10)
  let assert Ok(state) = reassembler.insert(state, 10, <<>>, True)
  let assert Ok(reassembler.Read(_state, <<>>, True)) =
    reassembler.read(state, 10)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_conflicting_overlap_final_size_and_buffer_exhaustion_test() -> Nil {
  let assert Ok(state) = reassembler.new(3, 100)
  let assert Ok(state) = reassembler.insert(state, 0, <<"abc">>, False)
  let assert Ok(same) = reassembler.insert(state, 1, <<"bc">>, False)
  assert reassembler.buffered_bytes(same) == 3
  assert reassembler.insert(state, 1, <<"bx">>, False)
    == Error(reassembler.ConflictingOverlap)
  assert reassembler.insert(state, 3, <<"d">>, False)
    == Error(reassembler.BufferLimitExceeded(4))

  let assert Ok(final) = reassembler.insert(state, 3, <<>>, True)
  assert reassembler.insert(final, 2, <<>>, True)
    == Error(reassembler.FinalSizeChanged)
  assert reassembler.insert(final, 3, <<"x">>, False)
    == Error(reassembler.BeyondFinalSize)
}
