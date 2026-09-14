//// Finite incremental HTTP/1.1 message-body decoding.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http/internal/http1

/// Finite body, metadata-buffer, and trailer policy.
pub type Limits {
  Limits(
    maximum_body_bytes: Int,
    maximum_buffered_bytes: Int,
    maximum_trailer_bytes: Int,
    maximum_trailer_count: Int,
    maximum_line_bytes: Int,
  )
}

type State {
  Empty
  Fixed(remaining: Int)
  CloseDelimited(received: Int)
  Chunked(state: ChunkState, declared_body_bytes: Int)
}

type ChunkState {
  ChunkSize(buffered: BitArray)
  ChunkData(remaining: Int)
  ChunkEnding(buffered: BitArray)
  ChunkTrailers(buffered: BitArray)
}

/// A decoder for one already validated HTTP/1.1 body framing decision.
pub opaque type Decoder {
  Decoder(limits: Limits, state: State)
}

/// Data, completion, or finite incremental progress from one transport read.
pub type Outcome {
  BodyNeedMore(Decoder)
  BodyData(BitArray, Decoder)
  BodyComplete(
    data: BitArray,
    trailers: List(http1.Header),
    remaining: BitArray,
  )
}

/// Invalid framing, chunk syntax, EOF, or finite-resource use.
pub type Error {
  InvalidLimit
  InvalidFraming
  NonByteAligned
  BodyTooLarge(maximum: Int)
  BufferLimitExceeded(maximum: Int)
  LineTooLong(maximum: Int)
  TrailerTooLarge(maximum: Int)
  InvalidChunkSize
  InvalidChunkExtension
  InvalidChunkTerminator
  InvalidTrailer(http1.Error)
  ForbiddenTrailer
  UnexpectedEndOfBody
  InvalidBodyData
}

/// Construct a decoder from the framing selected by a validated message head.
pub fn decoder(
  framing: http1.Framing,
  limits: Limits,
) -> Result(Decoder, Error) {
  use <- require(valid_limits(limits), InvalidLimit)
  case framing {
    http1.NoBody -> Ok(Decoder(limits, Empty))
    http1.ContentLength(length) if length >= 0 -> {
      use <- require(
        length <= limits.maximum_body_bytes,
        BodyTooLarge(limits.maximum_body_bytes),
      )
      Ok(Decoder(limits, Fixed(length)))
    }
    http1.ContentLength(_) -> Error(InvalidFraming)
    http1.Chunked -> Ok(Decoder(limits, Chunked(ChunkSize(<<>>), 0)))
    http1.CloseDelimited -> Ok(Decoder(limits, CloseDelimited(0)))
    http1.Tunnel -> Error(InvalidFraming)
  }
}

/// Consume one byte-aligned transport chunk.
pub fn feed(decoder: Decoder, bytes: BitArray) -> Result(Outcome, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case decoder.state {
        Empty -> Ok(BodyComplete(<<>>, [], bytes))
        Fixed(remaining) -> feed_fixed(decoder.limits, remaining, bytes)
        CloseDelimited(received) ->
          feed_close_delimited(decoder.limits, received, bytes)
        Chunked(state, declared) ->
          decode_chunked(decoder.limits, state, declared, bytes, [])
      }
  }
}

/// Finish a body after the transport reports a clean EOF.
pub fn finish(decoder: Decoder) -> Result(Outcome, Error) {
  case decoder.state {
    Empty | Fixed(0) | CloseDelimited(_) -> Ok(BodyComplete(<<>>, [], <<>>))
    Fixed(_) | Chunked(_, _) -> Error(UnexpectedEndOfBody)
  }
}

fn valid_limits(limits: Limits) -> Bool {
  limits.maximum_body_bytes > 0
  && limits.maximum_buffered_bytes > 0
  && limits.maximum_trailer_bytes > 0
  && limits.maximum_trailer_count > 0
  && limits.maximum_line_bytes > 0
  && limits.maximum_line_bytes <= limits.maximum_buffered_bytes
  && limits.maximum_trailer_bytes <= limits.maximum_buffered_bytes
}

fn feed_fixed(
  limits: Limits,
  remaining: Int,
  bytes: BitArray,
) -> Result(Outcome, Error) {
  case remaining, bit_array.byte_size(bytes) {
    0, _ -> Ok(BodyComplete(<<>>, [], bytes))
    _, 0 -> Ok(BodyNeedMore(Decoder(limits, Fixed(remaining))))
    _, available if available < remaining ->
      Ok(BodyData(bytes, Decoder(limits, Fixed(remaining - available))))
    _, _ -> {
      use #(data, following) <- result.try(take_bytes(bytes, remaining))
      Ok(BodyComplete(data, [], following))
    }
  }
}

fn feed_close_delimited(
  limits: Limits,
  received: Int,
  bytes: BitArray,
) -> Result(Outcome, Error) {
  let total = received + bit_array.byte_size(bytes)
  use <- require(
    total <= limits.maximum_body_bytes,
    BodyTooLarge(limits.maximum_body_bytes),
  )
  case bytes {
    <<>> -> Ok(BodyNeedMore(Decoder(limits, CloseDelimited(received))))
    _ -> Ok(BodyData(bytes, Decoder(limits, CloseDelimited(total))))
  }
}

fn decode_chunked(
  limits: Limits,
  state: ChunkState,
  declared: Int,
  bytes: BitArray,
  reversed_data: List(BitArray),
) -> Result(Outcome, Error) {
  case state {
    ChunkSize(buffered) ->
      decode_chunk_size(limits, buffered, declared, bytes, reversed_data)
    ChunkData(remaining) ->
      decode_chunk_data(limits, remaining, declared, bytes, reversed_data)
    ChunkEnding(buffered) ->
      decode_chunk_ending(limits, buffered, declared, bytes, reversed_data)
    ChunkTrailers(buffered) ->
      decode_chunk_trailers(limits, buffered, declared, bytes, reversed_data)
  }
}

fn decode_chunk_size(
  limits: Limits,
  buffered: BitArray,
  declared: Int,
  bytes: BitArray,
  reversed_data: List(BitArray),
) -> Result(Outcome, Error) {
  let combined = bit_array.append(buffered, bytes)
  case find_crlf(combined, 0) {
    None -> retain_chunk_size(limits, combined, declared, reversed_data)
    Some(length) -> {
      use <- require(
        length <= limits.maximum_line_bytes,
        LineTooLong(limits.maximum_line_bytes),
      )
      use #(line, rest_with_crlf) <- result.try(take_bytes(combined, length))
      use #(_, rest) <- result.try(take_bytes(rest_with_crlf, 2))
      use size <- result.try(parse_chunk_size(line, limits, declared))
      case size {
        0 ->
          decode_chunked(
            limits,
            ChunkTrailers(<<>>),
            declared,
            rest,
            reversed_data,
          )
        _ ->
          decode_chunked(
            limits,
            ChunkData(size),
            declared + size,
            rest,
            reversed_data,
          )
      }
    }
  }
}

fn retain_chunk_size(
  limits: Limits,
  combined: BitArray,
  declared: Int,
  reversed_data: List(BitArray),
) -> Result(Outcome, Error) {
  use <- require(valid_line_endings(combined), InvalidChunkSize)
  use <- require(
    partial_line_within_limit(combined, limits.maximum_line_bytes, 0),
    LineTooLong(limits.maximum_line_bytes),
  )
  use <- require(
    bit_array.byte_size(combined) < limits.maximum_buffered_bytes,
    BufferLimitExceeded(limits.maximum_buffered_bytes),
  )
  pending_or_data(limits, ChunkSize(combined), declared, reversed_data)
}

fn decode_chunk_data(
  limits: Limits,
  remaining: Int,
  declared: Int,
  bytes: BitArray,
  reversed_data: List(BitArray),
) -> Result(Outcome, Error) {
  case bit_array.byte_size(bytes) {
    0 -> pending_or_data(limits, ChunkData(remaining), declared, reversed_data)
    available if available < remaining ->
      pending_or_data(limits, ChunkData(remaining - available), declared, [
        bytes,
        ..reversed_data
      ])
    _ -> {
      use #(data, rest) <- result.try(take_bytes(bytes, remaining))
      decode_chunked(limits, ChunkEnding(<<>>), declared, rest, [
        data,
        ..reversed_data
      ])
    }
  }
}

fn decode_chunk_ending(
  limits: Limits,
  buffered: BitArray,
  declared: Int,
  bytes: BitArray,
  reversed_data: List(BitArray),
) -> Result(Outcome, Error) {
  case buffered, bytes {
    <<>>, <<0x0d, 0x0a, rest:bytes>> ->
      decode_chunked(limits, ChunkSize(<<>>), declared, rest, reversed_data)
    <<>>, <<0x0d>> ->
      pending_or_data(limits, ChunkEnding(<<0x0d>>), declared, reversed_data)
    <<>>, <<>> ->
      pending_or_data(limits, ChunkEnding(<<>>), declared, reversed_data)
    <<0x0d>>, <<0x0a, rest:bytes>> ->
      decode_chunked(limits, ChunkSize(<<>>), declared, rest, reversed_data)
    <<0x0d>>, <<>> ->
      pending_or_data(limits, ChunkEnding(<<0x0d>>), declared, reversed_data)
    _, _ -> Error(InvalidChunkTerminator)
  }
}

fn decode_chunk_trailers(
  limits: Limits,
  buffered: BitArray,
  declared: Int,
  bytes: BitArray,
  reversed_data: List(BitArray),
) -> Result(Outcome, Error) {
  let combined = bit_array.append(buffered, bytes)
  case find_trailer_end(combined) {
    None -> retain_trailers(limits, combined, declared, reversed_data)
    Some(trailer_end) -> {
      use <- require(
        trailer_end <= limits.maximum_trailer_bytes,
        TrailerTooLarge(limits.maximum_trailer_bytes),
      )
      use trailer_lines <- result.try(
        bit_array.slice(combined, at: 0, take: trailer_end - 2)
        |> result.replace_error(InvalidBodyData),
      )
      use trailers <- result.try(
        http1.parse_trailer_block(
          trailer_lines,
          limits.maximum_trailer_count,
          limits.maximum_line_bytes,
        )
        |> result.map_error(InvalidTrailer),
      )
      use <- require(valid_trailers(trailers), ForbiddenTrailer)
      use remaining <- result.try(
        bit_array.slice(
          combined,
          at: trailer_end,
          take: bit_array.byte_size(combined) - trailer_end,
        )
        |> result.replace_error(InvalidBodyData),
      )
      Ok(BodyComplete(decoded_data(reversed_data), trailers, remaining))
    }
  }
}

fn retain_trailers(
  limits: Limits,
  combined: BitArray,
  declared: Int,
  reversed_data: List(BitArray),
) -> Result(Outcome, Error) {
  use <- require(
    valid_line_endings(combined),
    InvalidTrailer(http1.InvalidLineEnding),
  )
  use <- require(
    partial_line_within_limit(combined, limits.maximum_line_bytes, 0),
    LineTooLong(limits.maximum_line_bytes),
  )
  use <- require(
    bit_array.byte_size(combined) < limits.maximum_trailer_bytes,
    TrailerTooLarge(limits.maximum_trailer_bytes),
  )
  use <- require(
    bit_array.byte_size(combined) < limits.maximum_buffered_bytes,
    BufferLimitExceeded(limits.maximum_buffered_bytes),
  )
  pending_or_data(limits, ChunkTrailers(combined), declared, reversed_data)
}

fn pending_or_data(
  limits: Limits,
  state: ChunkState,
  declared: Int,
  reversed_data: List(BitArray),
) -> Result(Outcome, Error) {
  let decoder = Decoder(limits, Chunked(state, declared))
  case reversed_data {
    [] -> Ok(BodyNeedMore(decoder))
    _ -> Ok(BodyData(decoded_data(reversed_data), decoder))
  }
}

fn decoded_data(reversed_data: List(BitArray)) -> BitArray {
  reversed_data |> list.reverse |> bit_array.concat
}

fn parse_chunk_size(
  line: BitArray,
  limits: Limits,
  declared: Int,
) -> Result(Int, Error) {
  case find_byte(line, 0x3b, 0) {
    None -> parse_hexadecimal(line, 0, limits, declared)
    Some(separator) -> {
      use #(digits, extension_with_separator) <- result.try(take_bytes(
        line,
        separator,
      ))
      use #(_, extension) <- result.try(take_bytes(extension_with_separator, 1))
      use <- require(valid_chunk_extension(extension), InvalidChunkExtension)
      parse_hexadecimal(trim_trailing_bws(digits), 0, limits, declared)
    }
  }
}

fn parse_hexadecimal(
  bytes: BitArray,
  accumulated: Int,
  limits: Limits,
  declared: Int,
) -> Result(Int, Error) {
  case bytes {
    <<>> -> Error(InvalidChunkSize)
    _ -> parse_hexadecimal_loop(bytes, accumulated, limits, declared)
  }
}

fn parse_hexadecimal_loop(
  bytes: BitArray,
  accumulated: Int,
  limits: Limits,
  declared: Int,
) -> Result(Int, Error) {
  case bytes {
    <<>> -> Ok(accumulated)
    <<byte, rest:bytes>> -> {
      use digit <- result.try(hexadecimal_digit(byte))
      let next = accumulated * 16 + digit
      use <- require(
        declared + next <= limits.maximum_body_bytes,
        BodyTooLarge(limits.maximum_body_bytes),
      )
      parse_hexadecimal_loop(rest, next, limits, declared)
    }
    _ -> Error(InvalidChunkSize)
  }
}

fn hexadecimal_digit(byte: Int) -> Result(Int, Error) {
  case byte {
    byte if byte >= 0x30 && byte <= 0x39 -> Ok(byte - 0x30)
    byte if byte >= 0x41 && byte <= 0x46 -> Ok(byte - 0x41 + 10)
    byte if byte >= 0x61 && byte <= 0x66 -> Ok(byte - 0x61 + 10)
    _ -> Error(InvalidChunkSize)
  }
}

fn valid_chunk_extension(bytes: BitArray) -> Bool {
  let bytes = trim_leading_bws(bytes)
  case skip_token(bytes, False) {
    None -> False
    Some(rest) -> finish_chunk_extension(rest)
  }
}

fn finish_chunk_extension(bytes: BitArray) -> Bool {
  let bytes = trim_leading_bws(bytes)
  case bytes {
    <<>> -> True
    <<0x3b, rest:bytes>> -> valid_chunk_extension(rest)
    <<0x3d, rest:bytes>> ->
      case skip_chunk_extension_value(trim_leading_bws(rest)) {
        None -> False
        Some(rest) -> finish_chunk_extension_value(rest)
      }
    _ -> False
  }
}

fn finish_chunk_extension_value(bytes: BitArray) -> Bool {
  case trim_leading_bws(bytes) {
    <<>> -> True
    <<0x3b, rest:bytes>> -> valid_chunk_extension(rest)
    _ -> False
  }
}

fn skip_chunk_extension_value(bytes: BitArray) -> Option(BitArray) {
  case bytes {
    <<0x22, rest:bytes>> -> skip_quoted_string(rest)
    _ -> skip_token(bytes, False)
  }
}

fn skip_quoted_string(bytes: BitArray) -> Option(BitArray) {
  case bytes {
    <<0x22, rest:bytes>> -> Some(rest)
    <<0x5c, byte, rest:bytes>> ->
      case valid_quoted_pair_byte(byte) {
        True -> skip_quoted_string(rest)
        False -> None
      }
    <<byte, rest:bytes>> ->
      case valid_quoted_text_byte(byte) {
        True -> skip_quoted_string(rest)
        False -> None
      }
    _ -> None
  }
}

fn skip_token(bytes: BitArray, consumed: Bool) -> Option(BitArray) {
  case bytes {
    <<byte, rest:bytes>> ->
      case is_token_byte(byte) {
        True -> skip_token(rest, True)
        False ->
          case consumed {
            True -> Some(bytes)
            False -> None
          }
      }
    <<>> ->
      case consumed {
        True -> Some(<<>>)
        False -> None
      }
    _ -> None
  }
}

fn trim_leading_bws(bytes: BitArray) -> BitArray {
  case bytes {
    <<byte, rest:bytes>> if byte == 0x20 || byte == 0x09 ->
      trim_leading_bws(rest)
    _ -> bytes
  }
}

fn trim_trailing_bws(bytes: BitArray) -> BitArray {
  let retained = last_non_bws_end(bytes, 0, 0)
  bit_array.slice(bytes, at: 0, take: retained)
  |> result.unwrap(<<>>)
}

fn last_non_bws_end(bytes: BitArray, offset: Int, retained: Int) -> Int {
  case bytes {
    <<>> -> retained
    <<byte, rest:bytes>> if byte == 0x20 || byte == 0x09 ->
      last_non_bws_end(rest, offset + 1, retained)
    <<_, rest:bytes>> -> last_non_bws_end(rest, offset + 1, offset + 1)
    _ -> retained
  }
}

fn is_token_byte(byte: Int) -> Bool {
  byte >= 0x30
  && byte <= 0x39
  || byte >= 0x41
  && byte <= 0x5a
  || byte >= 0x61
  && byte <= 0x7a
  || byte == 0x21
  || byte == 0x23
  || byte == 0x24
  || byte == 0x25
  || byte == 0x26
  || byte == 0x27
  || byte == 0x2a
  || byte == 0x2b
  || byte == 0x2d
  || byte == 0x2e
  || byte == 0x5e
  || byte == 0x5f
  || byte == 0x60
  || byte == 0x7c
  || byte == 0x7e
}

fn valid_quoted_text_byte(byte: Int) -> Bool {
  byte == 0x09
  || byte == 0x20
  || byte == 0x21
  || byte >= 0x23
  && byte <= 0x5b
  || byte >= 0x5d
  && byte <= 0x7e
  || byte >= 0x80
}

fn valid_quoted_pair_byte(byte: Int) -> Bool {
  byte == 0x09 || byte == 0x20 || byte >= 0x21 && byte <= 0x7e || byte >= 0x80
}

fn valid_trailers(trailers: List(http1.Header)) -> Bool {
  case trailers {
    [] -> True
    [header, ..rest] -> !forbidden_trailer(header) && valid_trailers(rest)
  }
}

fn forbidden_trailer(header: http1.Header) -> Bool {
  http1.header_name_equals(header, <<"authorization":utf8>>)
  || http1.header_name_equals(header, <<"connection":utf8>>)
  || http1.header_name_equals(header, <<"content-encoding":utf8>>)
  || http1.header_name_equals(header, <<"content-length":utf8>>)
  || http1.header_name_equals(header, <<"content-range":utf8>>)
  || http1.header_name_equals(header, <<"content-type":utf8>>)
  || http1.header_name_equals(header, <<"host":utf8>>)
  || http1.header_name_equals(header, <<"keep-alive":utf8>>)
  || http1.header_name_equals(header, <<"proxy-authenticate":utf8>>)
  || http1.header_name_equals(header, <<"proxy-authorization":utf8>>)
  || http1.header_name_equals(header, <<"proxy-connection":utf8>>)
  || http1.header_name_equals(header, <<"te":utf8>>)
  || http1.header_name_equals(header, <<"trailer":utf8>>)
  || http1.header_name_equals(header, <<"transfer-encoding":utf8>>)
  || http1.header_name_equals(header, <<"upgrade":utf8>>)
}

fn find_trailer_end(bytes: BitArray) -> Option(Int) {
  case bytes {
    <<0x0d, 0x0a, _:bytes>> -> Some(2)
    _ -> find_head_end(bytes, 0)
  }
}

fn find_head_end(bytes: BitArray, offset: Int) -> Option(Int) {
  case bytes {
    <<0x0d, 0x0a, 0x0d, 0x0a, _:bytes>> -> Some(offset + 4)
    <<_, rest:bytes>> -> find_head_end(rest, offset + 1)
    _ -> None
  }
}

fn find_crlf(bytes: BitArray, offset: Int) -> Option(Int) {
  case bytes {
    <<0x0d, 0x0a, _:bytes>> -> Some(offset)
    <<_, rest:bytes>> -> find_crlf(rest, offset + 1)
    _ -> None
  }
}

fn find_byte(bytes: BitArray, wanted: Int, offset: Int) -> Option(Int) {
  case bytes {
    <<byte, _rest:bytes>> if byte == wanted -> Some(offset)
    <<_, rest:bytes>> -> find_byte(rest, wanted, offset + 1)
    _ -> None
  }
}

fn valid_line_endings(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<0x0d>> -> True
    <<0x0d, 0x0a, rest:bytes>> -> valid_line_endings(rest)
    <<0x0d, _, _:bytes>> -> False
    <<0x0a, _:bytes>> -> False
    <<_, rest:bytes>> -> valid_line_endings(rest)
    _ -> False
  }
}

fn partial_line_within_limit(
  bytes: BitArray,
  maximum: Int,
  current: Int,
) -> Bool {
  case bytes {
    <<>> -> current <= maximum
    <<0x0d>> -> current <= maximum
    <<0x0d, 0x0a, rest:bytes>> ->
      current <= maximum && partial_line_within_limit(rest, maximum, 0)
    <<_, rest:bytes>> ->
      current < maximum && partial_line_within_limit(rest, maximum, current + 1)
    _ -> False
  }
}

fn take_bytes(
  bytes: BitArray,
  count: Int,
) -> Result(#(BitArray, BitArray), Error) {
  use taken <- result.try(
    bit_array.slice(bytes, at: 0, take: count)
    |> result.replace_error(InvalidBodyData),
  )
  use remaining <- result.try(
    bit_array.slice(bytes, at: count, take: bit_array.byte_size(bytes) - count)
    |> result.replace_error(InvalidBodyData),
  )
  Ok(#(taken, remaining))
}

fn require(
  condition: Bool,
  failure: error,
  next: fn() -> Result(value, error),
) -> Result(value, error) {
  case condition {
    True -> next()
    False -> Error(failure)
  }
}
