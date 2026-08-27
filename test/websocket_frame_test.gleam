import gleam/bit_array
import gleam/option.{Some}
import gleam/string
import http3/internal/websocket_frame as frame

fn decoder(role: frame.Role) -> frame.Decoder {
  let assert Ok(decoder) = frame.decoder(role, 1_048_576, 1_048_590)
  decoder
}

pub fn masked_client_text_frame_decodes_incrementally_test() -> Nil {
  let encoded =
    frame.encode_with_mask(
      frame.Frame(True, frame.Text, <<"hello":utf8>>),
      Some(<<1, 2, 3, 4>>),
    )
  let assert Ok(encoded) = encoded
  let assert Ok(first) = bit_array.slice(encoded, at: 0, take: 3)
  let assert Ok(second) =
    bit_array.slice(encoded, at: 3, take: bit_array.byte_size(encoded) - 3)

  let assert Ok(pending) = frame.push(decoder(frame.Server), first)
  assert frame.next(pending) == Ok(frame.NeedMore(pending))
  let assert Ok(complete) = frame.push(pending, second)
  let assert Ok(frame.Ready(next, decoded)) = frame.next(complete)
  assert decoded == frame.Frame(True, frame.Text, <<"hello":utf8>>)
  assert frame.buffered_bytes(next) == 0
}

pub fn server_frames_are_unmasked_and_support_extended_lengths_test() -> Nil {
  let payload = repeated(130, <<>>)
  let assert Ok(encoded) =
    frame.encode(frame.Server, frame.Frame(True, frame.Binary, payload))
  let assert Ok(buffered) = frame.push(decoder(frame.Client), encoded)
  let assert Ok(frame.Ready(_, decoded)) = frame.next(buffered)
  assert decoded == frame.Frame(True, frame.Binary, payload)
}

pub fn masking_and_control_rules_are_enforced_test() -> Nil {
  let assert Ok(unmasked) =
    frame.encode(frame.Server, frame.Frame(True, frame.Text, <<>>))
  let assert Ok(server_decoder) = frame.push(decoder(frame.Server), unmasked)
  assert frame.next(server_decoder) == Error(frame.MaskRequired)

  let assert Ok(masked) =
    frame.encode_with_mask(
      frame.Frame(True, frame.Text, <<>>),
      Some(<<0, 0, 0, 0>>),
    )
  let assert Ok(client_decoder) = frame.push(decoder(frame.Client), masked)
  assert frame.next(client_decoder) == Error(frame.MaskForbidden)

  assert frame.encode(
      frame.Server,
      frame.Frame(False, frame.Ping, <<"x":utf8>>),
    )
    == Error(frame.FragmentedControl)
  assert frame.encode(
      frame.Server,
      frame.Frame(True, frame.Close, repeated(126, <<>>)),
    )
    == Error(frame.ControlPayloadTooLarge)
}

pub fn reserved_bits_opcode_and_nonminimal_lengths_are_rejected_test() -> Nil {
  let cases = [
    <<192, 0>>,
    <<131, 0>>,
    <<129, 126, 0, 125>>,
    <<130, 127, 0:1, 125:size(63)>>,
  ]
  let errors = [
    frame.ReservedBits,
    frame.ReservedOpcode(3),
    frame.InvalidLength,
    frame.InvalidLength,
  ]
  assert decode_errors(cases, errors)
}

pub fn decoder_bounds_payload_and_retained_buffer_test() -> Nil {
  let assert Ok(small) = frame.decoder(frame.Client, 4, 8)
  let assert Ok(too_large) = frame.push(small, <<130, 5, 1, 2, 3, 4, 5>>)
  assert frame.next(too_large) == Error(frame.PayloadLimitExceeded(4))
  assert frame.push(small, <<0, 1, 2, 3, 4, 5, 6, 7, 8>>)
    == Error(frame.BufferLimitExceeded(8))
}

pub fn decoder_rejects_invalid_limits_and_non_byte_aligned_chunks_test() -> Nil {
  assert frame.decoder(frame.Client, 0, 14) == Error(frame.InvalidLimit)
  assert frame.decoder(frame.Client, 15, 14) == Error(frame.InvalidLimit)
  assert frame.push(decoder(frame.Client), <<1:1>>)
    == Error(frame.NonByteAligned)
}

pub fn incomplete_extended_lengths_are_retained_without_consumption_test() -> Nil {
  let assert Ok(buffered) = frame.push(decoder(frame.Client), <<130, 126, 0>>)
  assert frame.next(buffered) == Ok(frame.NeedMore(buffered))
  assert frame.buffered_bytes(buffered) == 3
}

pub fn fragmented_and_oversized_control_frames_are_rejected_on_decode_test() -> Nil {
  let assert Ok(fragmented) = frame.push(decoder(frame.Client), <<9, 0>>)
  assert frame.next(fragmented) == Error(frame.FragmentedControl)
  let assert Ok(oversized) =
    frame.push(decoder(frame.Client), <<136, 126, 0, 126>>)
  assert frame.next(oversized) == Error(frame.ControlPayloadTooLarge)
}

pub fn sixty_four_bit_lengths_reject_the_reserved_high_bit_test() -> Nil {
  let assert Ok(buffered) =
    frame.push(decoder(frame.Client), <<130, 127, 1:1, 65_536:63>>)
  assert frame.next(buffered) == Error(frame.InvalidLength)
}

pub fn masked_sixty_four_bit_length_round_trips_test() -> Nil {
  let payload = string.repeat("x", times: 65_536) |> bit_array.from_string
  let assert Ok(encoded) =
    frame.encode_with_mask(
      frame.Frame(True, frame.Binary, payload),
      Some(<<4, 3, 2, 1>>),
    )
  let assert Ok(buffered) = frame.push(decoder(frame.Server), encoded)
  let assert Ok(frame.Ready(next, decoded)) = frame.next(buffered)
  assert decoded == frame.Frame(True, frame.Binary, payload)
  assert frame.buffered_bytes(next) == 0
}

pub fn concatenated_frames_are_pulled_one_at_a_time_test() -> Nil {
  let assert Ok(first) =
    frame.encode(frame.Server, frame.Frame(True, frame.Text, <<"one":utf8>>))
  let assert Ok(second) =
    frame.encode(frame.Server, frame.Frame(True, frame.Ping, <<"two":utf8>>))
  let assert Ok(buffered) =
    frame.push(decoder(frame.Client), <<first:bits, second:bits>>)
  let assert Ok(frame.Ready(after_first, first_frame)) = frame.next(buffered)
  assert first_frame == frame.Frame(True, frame.Text, <<"one":utf8>>)
  let assert Ok(frame.Ready(after_second, second_frame)) =
    frame.next(after_first)
  assert second_frame == frame.Frame(True, frame.Ping, <<"two":utf8>>)
  assert frame.buffered_bytes(after_second) == 0
}

pub fn explicit_masks_must_be_exactly_four_bytes_test() -> Nil {
  assert frame.encode_with_mask(
      frame.Frame(True, frame.Binary, <<1, 2, 3>>),
      Some(<<1, 2, 3>>),
    )
    == Error(frame.InvalidMask)
}

fn decode_errors(cases: List(BitArray), errors: List(frame.Error)) -> Bool {
  case cases, errors {
    [], [] -> True
    [bytes, ..rest], [expected, ..remaining] -> {
      let assert Ok(buffered) = frame.push(decoder(frame.Client), bytes)
      frame.next(buffered) == Error(expected) && decode_errors(rest, remaining)
    }
    _, _ -> False
  }
}

fn repeated(remaining: Int, bytes: BitArray) -> BitArray {
  case remaining {
    0 -> bytes
    _ -> repeated(remaining - 1, <<bytes:bits, 42>>)
  }
}
