import gleam_quic/internal/tls/handshake

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn incrementally_decodes_tls_handshake_envelopes_test() -> Nil {
  let message = handshake.Message(handshake.ClientHello, <<1, 2, 3, 4>>)
  let assert Ok(encoded) = handshake.encode(message, 1024)
  assert encoded == <<1, 0, 0, 4, 1, 2, 3, 4>>
  assert handshake.decode_next(<<>>, handshake.default_limits())
    == Ok(handshake.NeedMore)
  assert handshake.decode_next(<<1, 0, 0>>, handshake.default_limits())
    == Ok(handshake.NeedMore)
  assert handshake.decode_next(<<1, 0, 0, 4, 1, 2>>, handshake.default_limits())
    == Ok(handshake.NeedMore)
  assert handshake.decode_next(
      <<encoded:bits, 8, 0, 0, 0>>,
      handshake.default_limits(),
    )
    == Ok(handshake.Complete(message, <<8, 0, 0, 0>>))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn preserves_unknown_handshake_types_test() -> Nil {
  assert handshake.decode_next(<<200, 0, 0, 1, 9>>, handshake.default_limits())
    == Ok(
      handshake.Complete(handshake.Message(handshake.Unknown(200), <<9>>), <<>>),
    )
  assert handshake.encode(handshake.Message(handshake.Unknown(255), <<>>), 10)
    == Ok(<<255, 0, 0, 0>>)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_tls_handshake_resource_limits_test() -> Nil {
  assert handshake.decode_next(<<1:size(1)>>, handshake.default_limits())
    == Error(handshake.NonByteAligned)
  assert handshake.decode_next(<<>>, handshake.Limits(-1, 1))
    == Error(handshake.InvalidLimits)
  assert handshake.decode_next(<<1, 0, 0, 5>>, handshake.Limits(4, 100))
    == Error(handshake.MessageTooLarge(5))
  assert handshake.decode_next(<<0:88>>, handshake.Limits(100, 10))
    == Error(handshake.BufferTooLarge(11))
  assert handshake.encode(handshake.Message(handshake.ClientHello, <<0:40>>), 4)
    == Error(handshake.MessageTooLarge(5))
  assert handshake.encode(handshake.Message(handshake.Unknown(256), <<>>), 4)
    == Error(handshake.InvalidMessageType(256))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn identifies_messages_forbidden_by_quic_test() -> Nil {
  assert handshake.forbidden_in_quic(handshake.EndOfEarlyData)
  assert handshake.forbidden_in_quic(handshake.KeyUpdate)
  assert !handshake.forbidden_in_quic(handshake.ClientHello)
  assert !handshake.forbidden_in_quic(handshake.Unknown(200))
}
