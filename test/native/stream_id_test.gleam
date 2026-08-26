import http3/internal/stream_id

const largest_index = 1_152_921_504_606_846_975

const largest_identifier = 4_611_686_018_427_387_903

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rfc_9000_section_2_1_low_bits_classify_streams_test() -> Nil {
  assert stream_id.decode(0)
    == Ok(stream_id.StreamId(0, stream_id.Client, stream_id.Bidirectional))
  assert stream_id.decode(1)
    == Ok(stream_id.StreamId(0, stream_id.Server, stream_id.Bidirectional))
  assert stream_id.decode(2)
    == Ok(stream_id.StreamId(0, stream_id.Client, stream_id.Unidirectional))
  assert stream_id.decode(3)
    == Ok(stream_id.StreamId(0, stream_id.Server, stream_id.Unidirectional))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn encode_round_trips_every_stream_class_test() -> Nil {
  let index = 1_234_567_890_123

  assert stream_id.encode(index, stream_id.Client, stream_id.Bidirectional)
    == Ok(index * 4)
  assert stream_id.encode(index, stream_id.Server, stream_id.Bidirectional)
    == Ok(index * 4 + 1)
  assert stream_id.encode(index, stream_id.Client, stream_id.Unidirectional)
    == Ok(index * 4 + 2)
  assert stream_id.encode(index, stream_id.Server, stream_id.Unidirectional)
    == Ok(index * 4 + 3)

  assert stream_id.decode(index * 4)
    == Ok(stream_id.StreamId(index, stream_id.Client, stream_id.Bidirectional))
  assert stream_id.decode(index * 4 + 1)
    == Ok(stream_id.StreamId(index, stream_id.Server, stream_id.Bidirectional))
  assert stream_id.decode(index * 4 + 2)
    == Ok(stream_id.StreamId(index, stream_id.Client, stream_id.Unidirectional))
  assert stream_id.decode(index * 4 + 3)
    == Ok(stream_id.StreamId(index, stream_id.Server, stream_id.Unidirectional))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn identifiers_outside_the_62_bit_range_are_typed_test() -> Nil {
  assert stream_id.decode(-1) == Error(stream_id.OutOfRange)
  assert stream_id.decode(largest_identifier + 1) == Error(stream_id.OutOfRange)
  assert stream_id.decode(largest_identifier)
    == Ok(stream_id.StreamId(
      largest_index,
      stream_id.Server,
      stream_id.Unidirectional,
    ))

  assert stream_id.encode(-1, stream_id.Client, stream_id.Bidirectional)
    == Error(stream_id.OutOfRange)
  assert stream_id.encode(
      largest_index + 1,
      stream_id.Client,
      stream_id.Bidirectional,
    )
    == Error(stream_id.OutOfRange)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_send_and_receive_permissions_test() -> Nil {
  assert stream_id.can_send(0, stream_id.Client) == True
  assert stream_id.can_send(1, stream_id.Client) == True
  assert stream_id.can_send(2, stream_id.Client) == True
  assert stream_id.can_send(3, stream_id.Client) == False

  assert stream_id.can_receive(0, stream_id.Client) == True
  assert stream_id.can_receive(1, stream_id.Client) == True
  assert stream_id.can_receive(2, stream_id.Client) == False
  assert stream_id.can_receive(3, stream_id.Client) == True
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_send_and_receive_permissions_test() -> Nil {
  assert stream_id.can_send(0, stream_id.Server) == True
  assert stream_id.can_send(1, stream_id.Server) == True
  assert stream_id.can_send(2, stream_id.Server) == False
  assert stream_id.can_send(3, stream_id.Server) == True

  assert stream_id.can_receive(0, stream_id.Server) == True
  assert stream_id.can_receive(1, stream_id.Server) == True
  assert stream_id.can_receive(2, stream_id.Server) == True
  assert stream_id.can_receive(3, stream_id.Server) == False
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn out_of_range_identifiers_permit_nothing_test() -> Nil {
  assert stream_id.can_send(-1, stream_id.Client) == False
  assert stream_id.can_receive(-1, stream_id.Client) == False
  assert stream_id.can_send(largest_identifier + 1, stream_id.Server) == False
  assert stream_id.can_receive(largest_identifier + 1, stream_id.Server)
    == False
}
