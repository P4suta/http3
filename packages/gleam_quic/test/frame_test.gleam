import gleam/option.{None, Some}
import gleam_quic/frame

const reset_token = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_every_standard_frame_shape_test() -> Nil {
  let frames = [
    frame.Padding(3),
    frame.Ping,
    frame.Ack(frame.Acknowledgement(
      delay: 7,
      ranges: [frame.AckRange(20, 25), frame.AckRange(10, 15)],
      ecn: Some(frame.EcnCounts(4, 5, 6)),
    )),
    frame.ResetStream(4, 42, 100),
    frame.StopSending(4, 42),
    frame.Crypto(12, <<1, 2, 3>>),
    frame.NewToken(<<9, 8, 7>>),
    frame.Stream(8, 2, <<"body":utf8>>, True),
    frame.MaxData(10_000),
    frame.MaxStreamData(8, 2000),
    frame.MaxStreams(frame.Bidirectional, 20),
    frame.MaxStreams(frame.Unidirectional, 10),
    frame.DataBlocked(10_000),
    frame.StreamDataBlocked(8, 2000),
    frame.StreamsBlocked(frame.Bidirectional, 20),
    frame.StreamsBlocked(frame.Unidirectional, 10),
    frame.NewConnectionId(3, 1, <<1, 2, 3, 4>>, reset_token),
    frame.RetireConnectionId(2),
    frame.PathChallenge(<<1, 2, 3, 4, 5, 6, 7, 8>>),
    frame.PathResponse(<<8, 7, 6, 5, 4, 3, 2, 1>>),
    frame.ConnectionCloseTransport(7, 6, "bad frame"),
    frame.ConnectionCloseApplication(0x100, "finished"),
    frame.HandshakeDone,
    frame.Datagram(<<5, 4, 3>>),
  ]

  let assert Ok(encoded) = frame.encode_all(frames)
  assert frame.decode_all(encoded, frame.default_limits()) == Ok(frames)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn accepts_stream_and_datagram_frames_without_length_test() -> Nil {
  assert frame.decode_all(<<0x08, 4, "rest":utf8>>, frame.default_limits())
    == Ok([frame.Stream(4, 0, <<"rest":utf8>>, False)])
  assert frame.decode_all(<<0x30, "rest":utf8>>, frame.default_limits())
    == Ok([frame.Datagram(<<"rest":utf8>>)])
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_malformed_or_truncated_frames_test() -> Nil {
  let limits = frame.default_limits()
  assert frame.decode_all(<<0x06, 0, 4, 1, 2>>, limits)
    == Error(frame.Truncated)
  assert frame.decode_all(<<0x1a, 1, 2, 3>>, limits) == Error(frame.Truncated)
  assert frame.decode_all(<<0x1c, 0, 0, 1, 0xff>>, limits)
    == Error(frame.InvalidUtf8)
  assert frame.decode_all(<<0x18, 1, 2, 1, 0xaa, reset_token:bits>>, limits)
    == Error(frame.InvalidFrame)
  assert frame.decode_all(<<0x18, 1, 0, 0, reset_token:bits>>, limits)
    == Error(frame.InvalidFrame)
  assert frame.decode_all(<<0x21>>, limits)
    == Error(frame.UnknownFrameType(0x21))
  assert frame.decode_all(<<0x02, 2, 0, 0, 3>>, limits)
    == Error(frame.InvalidFrame)
  assert frame.decode_all(<<1:size(1)>>, limits) == Error(frame.NonByteAligned)
  assert frame.encode(frame.Padding(0)) == Error(frame.InvalidFrame)
  assert frame.encode(frame.NewToken(<<>>)) == Error(frame.InvalidFrame)
  assert frame.encode(frame.Ack(frame.Acknowledgement(0, [], None)))
    == Error(frame.InvalidFrame)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_non_byte_aligned_frame_fields_without_vm_exception_test() -> Nil {
  let bits = <<1:size(1)>>
  assert frame.encode(frame.Crypto(0, bits)) == Error(frame.NonByteAligned)
  assert frame.encode(frame.NewToken(bits)) == Error(frame.NonByteAligned)
  assert frame.encode(frame.Stream(0, 0, bits, False))
    == Error(frame.NonByteAligned)
  assert frame.encode(frame.NewConnectionId(0, 0, bits, reset_token))
    == Error(frame.NonByteAligned)
  assert frame.encode(frame.PathChallenge(bits)) == Error(frame.NonByteAligned)
  assert frame.encode(frame.PathResponse(bits)) == Error(frame.NonByteAligned)
  assert frame.encode(frame.Datagram(bits)) == Error(frame.NonByteAligned)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_decode_resource_limits_test() -> Nil {
  let payload_limits = frame.Limits(100, 10, 3, 3, 3)
  assert frame.decode_all(<<0x0a, 0, 4, 1, 2, 3, 4>>, payload_limits)
    == Error(frame.DataLimitExceeded(3))
  assert frame.decode_all(<<0x07, 4, 1, 2, 3, 4>>, payload_limits)
    == Error(frame.TokenLimitExceeded(3))
  assert frame.decode_all(<<0x1d, 0, 4, "four":utf8>>, payload_limits)
    == Error(frame.ReasonLimitExceeded(3))

  let ack_limits = frame.Limits(100, 0, 100, 100, 100)
  assert frame.decode_all(<<0x02, 1, 0, 1, 0, 0, 0>>, ack_limits)
    == Error(frame.AckRangeLimitExceeded(0))

  let frame_limits = frame.Limits(2, 10, 100, 100, 100)
  assert frame.decode_all(<<0, 0, 0>>, frame_limits)
    == Error(frame.FrameLimitExceeded(2))
  assert frame.decode_all(<<1>>, frame.Limits(0, 1, 1, 1, 1))
    == Error(frame.InvalidLimits)
}
