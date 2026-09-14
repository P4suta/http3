import gleeunit
import http/internal/http2/frame

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn frame_is_decoded_incrementally_with_bounded_payload_test() -> Nil {
  let assert Ok(decoder) = frame.decoder(16_384)
  let assert Ok(frame.NeedMore(decoder)) =
    frame.feed(decoder, <<0, 0, 3, 0, 1>>)
  let assert Ok(frame.FrameReady(header, <<"abc":utf8>>, <<>>)) =
    frame.feed(decoder, <<0, 0, 0, 1, "abc":utf8>>)

  assert header
    == frame.Header(length: 3, frame_type: frame.Data, flags: 1, stream_id: 1)
}

pub fn bytes_after_one_frame_are_returned_untouched_test() -> Nil {
  let assert Ok(decoder) = frame.decoder(16_384)
  let following = <<0, 0, 0, 4, 0, 0, 0, 0, 1>>
  let assert Ok(frame.FrameReady(_, <<>>, remaining)) =
    frame.feed(decoder, <<0, 0, 0, 4, 0, 0, 0, 0, 0, following:bits>>)

  assert remaining == following
}

pub fn oversized_frame_is_rejected_from_its_header_test() -> Nil {
  let assert Ok(decoder) = frame.decoder(2)
  let assert Error(failure) = frame.feed(decoder, <<0, 0, 3, 0, 0, 0, 0, 0, 1>>)

  assert failure == frame.FrameTooLarge(2)
}

pub fn stream_identifier_rules_are_enforced_test() -> Nil {
  let assert Ok(data_decoder) = frame.decoder(16_384)
  let assert Error(data_failure) =
    frame.feed(data_decoder, <<0, 0, 0, 0, 0, 0, 0, 0, 0>>)
  assert data_failure == frame.InvalidStreamIdentifier

  let assert Ok(settings_decoder) = frame.decoder(16_384)
  let assert Error(settings_failure) =
    frame.feed(settings_decoder, <<0, 0, 0, 4, 0, 0, 0, 0, 1>>)
  assert settings_failure == frame.InvalidStreamIdentifier
}

pub fn fixed_lengths_and_settings_ack_are_enforced_test() -> Nil {
  let assert Ok(ping_decoder) = frame.decoder(16_384)
  let assert Error(ping_failure) =
    frame.feed(ping_decoder, <<0, 0, 7, 6, 0, 0, 0, 0, 0>>)
  assert ping_failure == frame.InvalidPayloadLength

  let assert Ok(settings_decoder) = frame.decoder(16_384)
  let assert Error(settings_failure) =
    frame.feed(settings_decoder, <<0, 0, 6, 4, 1, 0, 0, 0, 0>>)
  assert settings_failure == frame.InvalidPayloadLength
}

pub fn unknown_type_is_preserved_and_reserved_stream_bit_is_ignored_test() -> Nil {
  let assert Ok(decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(header, <<>>, <<>>)) =
    frame.feed(decoder, <<0, 0, 0, 250, 165, 128, 0, 0, 7>>)

  assert header
    == frame.Header(
      length: 0,
      frame_type: frame.Unknown(250),
      flags: 165,
      stream_id: 7,
    )
}

pub fn invalid_limits_and_non_byte_aligned_input_are_typed_test() -> Nil {
  assert frame.decoder(0) == Error(frame.InvalidLimit)
  let assert Ok(decoder) = frame.decoder(16_384)
  assert frame.feed(decoder, <<1:size(1)>>) == Error(frame.NonByteAligned)
}

pub fn encoded_frame_round_trips_through_the_same_validation_test() -> Nil {
  let payload = <<0, 1, 0, 0, 16, 0>>
  let assert Ok(encoded) = frame.encode(frame.Settings, 0, 0, payload, 16_384)
  assert encoded == <<0, 0, 6, 4, 0, 0, 0, 0, 0, payload:bits>>

  let assert Ok(decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(header, decoded, <<>>)) =
    frame.feed(decoder, encoded)
  assert header == frame.Header(6, frame.Settings, 0, 0)
  assert decoded == payload
}

pub fn registered_origin_frame_type_is_preserved_test() -> Nil {
  let assert Ok(encoded) = frame.encode(frame.Origin, 0, 0, <<>>, 16_384)
  assert encoded == <<0, 0, 0, 0x0c, 0, 0, 0, 0, 0>>
  let assert Ok(decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(header, <<>>, <<>>)) =
    frame.feed(decoder, encoded)
  assert header == frame.Header(0, frame.Origin, 0, 0)
}

pub fn registered_priority_update_frame_type_is_preserved_test() -> Nil {
  let assert Ok(encoded) =
    frame.encode(frame.PriorityUpdate, 0, 0, <<0:size(32)>>, 16_384)
  assert encoded == <<0, 0, 4, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
  let assert Ok(decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(header, <<0:size(32)>>, <<>>)) =
    frame.feed(decoder, encoded)
  assert header == frame.Header(4, frame.PriorityUpdate, 0, 0)
}

pub fn encoder_rejects_values_that_do_not_fit_the_wire_test() -> Nil {
  assert frame.encode(frame.Unknown(256), 0, 1, <<>>, 16_384)
    == Error(frame.InvalidFrameType)
  assert frame.encode(frame.Data, 256, 1, <<>>, 16_384)
    == Error(frame.InvalidFlags)
  assert frame.encode(frame.Data, 0, 2_147_483_648, <<>>, 16_384)
    == Error(frame.InvalidStreamIdentifier)
  assert frame.encode(frame.Data, 0, 1, <<1:size(1)>>, 16_384)
    == Error(frame.NonByteAligned)
}
