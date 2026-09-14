//// Strict bounded HTTP/1.1 head and chunk serialization.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import http/internal/http1

/// Invalid outgoing syntax, framing ownership, or finite output use.
pub type Error {
  InvalidLimit
  NonByteAligned
  InvalidMethod
  InvalidTarget
  InvalidStatus
  InvalidReason
  InvalidHeaderName
  InvalidHeaderValue
  MissingHost
  DuplicateHost
  ReservedFramingHeader
  InvalidFraming
  HeadTooLarge(maximum: Int)
  LineTooLong(maximum: Int)
  TooManyHeaders(maximum: Int)
  EmptyChunk
  ForbiddenTrailer
  InvalidEncoding
}

/// Serialize one HTTP/1.1 request head.
pub fn request(
  method: BitArray,
  target: BitArray,
  headers: List(http1.Header),
  framing: http1.Framing,
  limits: http1.Limits,
) -> Result(BitArray, Error) {
  use <- require(valid_limits(limits), InvalidLimit)
  use <- require(valid_token(method), InvalidMethod)
  use <- require(valid_target(target), InvalidTarget)
  use _ <- result.try(validate_user_headers(headers))
  use _ <- result.try(require_one_host(headers))
  use headers <- result.try(add_framing_header(headers, framing))
  let start_line = <<method:bits, 0x20, target:bits, " HTTP/1.1":utf8>>
  encode_head(start_line, headers, limits)
}

/// Serialize one HTTP/1.1 response head.
pub fn response(
  status: Int,
  reason: BitArray,
  headers: List(http1.Header),
  framing: http1.Framing,
  limits: http1.Limits,
) -> Result(BitArray, Error) {
  use <- require(valid_limits(limits), InvalidLimit)
  use <- require(status >= 100 && status <= 999, InvalidStatus)
  use <- require(valid_field_value(reason), InvalidReason)
  use _ <- result.try(validate_user_headers(headers))
  use headers <- result.try(add_framing_header(headers, framing))
  let status = status |> int.to_string |> bit_array.from_string
  let start_line = <<"HTTP/1.1 ":utf8, status:bits, 0x20, reason:bits>>
  encode_head(start_line, headers, limits)
}

/// Serialize one non-empty HTTP/1.1 chunk.
pub fn chunk(bytes: BitArray) -> Result(BitArray, Error) {
  case bit_array.bit_size(bytes) % 8, bit_array.byte_size(bytes) {
    remainder, _ if remainder != 0 -> Error(NonByteAligned)
    _, 0 -> Error(EmptyChunk)
    _, length -> {
      let hexadecimal = length |> int.to_base16 |> bit_array.from_string
      Ok(<<hexadecimal:bits, "\r\n":utf8, bytes:bits, "\r\n":utf8>>)
    }
  }
}

/// Serialize the final zero chunk and a bounded trailer block.
pub fn final_chunk(
  trailers: List(http1.Header),
  limits: http1.Limits,
) -> Result(BitArray, Error) {
  use <- require(valid_limits(limits), InvalidLimit)
  use <- require(
    list.length(trailers) <= limits.maximum_header_count,
    TooManyHeaders(limits.maximum_header_count),
  )
  use _ <- result.try(validate_trailers(trailers))
  use encoded <- result.try(encode_header_lines(trailers, limits, []))
  let bytes = <<"0\r\n":utf8, encoded:bits, "\r\n":utf8>>
  use <- require(
    bit_array.byte_size(bytes) <= limits.maximum_head_bytes,
    HeadTooLarge(limits.maximum_head_bytes),
  )
  Ok(bytes)
}

fn encode_head(
  start_line: BitArray,
  headers: List(http1.Header),
  limits: http1.Limits,
) -> Result(BitArray, Error) {
  use <- require(
    bit_array.byte_size(start_line) <= limits.maximum_line_bytes,
    LineTooLong(limits.maximum_line_bytes),
  )
  use <- require(
    list.length(headers) <= limits.maximum_header_count,
    TooManyHeaders(limits.maximum_header_count),
  )
  use encoded_headers <- result.try(encode_header_lines(headers, limits, []))
  let bytes = <<
    start_line:bits,
    "\r\n":utf8,
    encoded_headers:bits,
    "\r\n":utf8,
  >>
  use <- require(
    bit_array.byte_size(bytes) <= limits.maximum_head_bytes,
    HeadTooLarge(limits.maximum_head_bytes),
  )
  Ok(bytes)
}

fn encode_header_lines(
  headers: List(http1.Header),
  limits: http1.Limits,
  reversed: List(BitArray),
) -> Result(BitArray, Error) {
  case headers {
    [] -> Ok(reversed |> list.reverse |> bit_array.concat)
    [http1.Header(name, value), ..rest] -> {
      use <- require(valid_token(name), InvalidHeaderName)
      use <- require(valid_field_value(value), InvalidHeaderValue)
      let line = <<name:bits, ": ":utf8, value:bits>>
      use <- require(
        bit_array.byte_size(line) <= limits.maximum_line_bytes,
        LineTooLong(limits.maximum_line_bytes),
      )
      encode_header_lines(rest, limits, [<<line:bits, "\r\n":utf8>>, ..reversed])
    }
  }
}

fn validate_user_headers(headers: List(http1.Header)) -> Result(Nil, Error) {
  case headers {
    [] -> Ok(Nil)
    [header, ..rest] -> {
      use <- require(!reserved_framing_header(header), ReservedFramingHeader)
      validate_user_headers(rest)
    }
  }
}

fn require_one_host(headers: List(http1.Header)) -> Result(Nil, Error) {
  case count_header(headers, <<"host":utf8>>, 0) {
    0 -> Error(MissingHost)
    1 -> Ok(Nil)
    _ -> Error(DuplicateHost)
  }
}

fn count_header(
  headers: List(http1.Header),
  name: BitArray,
  count: Int,
) -> Int {
  case headers {
    [] -> count
    [header, ..rest] -> {
      let next = case http1.header_name_equals(header, name) {
        True -> count + 1
        False -> count
      }
      count_header(rest, name, next)
    }
  }
}

fn add_framing_header(
  headers: List(http1.Header),
  framing: http1.Framing,
) -> Result(List(http1.Header), Error) {
  case framing {
    http1.NoBody -> Ok(headers)
    http1.ContentLength(length) if length >= 0 -> {
      let value = length |> int.to_string |> bit_array.from_string
      Ok(
        list.append(headers, [
          http1.Header(<<"Content-Length":utf8>>, value),
        ]),
      )
    }
    http1.Chunked ->
      Ok(
        list.append(headers, [
          http1.Header(<<"Transfer-Encoding":utf8>>, <<"chunked":utf8>>),
        ]),
      )
    http1.ContentLength(_) | http1.CloseDelimited | http1.Tunnel ->
      Error(InvalidFraming)
  }
}

fn validate_trailers(trailers: List(http1.Header)) -> Result(Nil, Error) {
  case trailers {
    [] -> Ok(Nil)
    [header, ..rest] -> {
      use <- require(!forbidden_trailer(header), ForbiddenTrailer)
      validate_trailers(rest)
    }
  }
}

fn reserved_framing_header(header: http1.Header) -> Bool {
  http1.header_name_equals(header, <<"content-length":utf8>>)
  || http1.header_name_equals(header, <<"transfer-encoding":utf8>>)
}

fn forbidden_trailer(header: http1.Header) -> Bool {
  reserved_framing_header(header)
  || http1.header_name_equals(header, <<"host":utf8>>)
  || http1.header_name_equals(header, <<"trailer":utf8>>)
}

fn valid_limits(limits: http1.Limits) -> Bool {
  limits.maximum_head_bytes > 0
  && limits.maximum_header_count > 0
  && limits.maximum_line_bytes > 0
  && limits.maximum_line_bytes <= limits.maximum_head_bytes
}

fn valid_token(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> False
    _ -> valid_token_bytes(bytes)
  }
}

fn valid_token_bytes(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, rest:bytes>> -> is_token_byte(byte) && valid_token_bytes(rest)
    _ -> False
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

fn valid_target(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> False
    _ -> valid_target_bytes(bytes)
  }
}

fn valid_target_bytes(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, rest:bytes>> ->
      byte >= 0x21 && byte <= 0x7e && byte != 0x23 && valid_target_bytes(rest)
    _ -> False
  }
}

fn valid_field_value(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, rest:bytes>> ->
      { byte == 0x09 || byte >= 0x20 && byte != 0x7f }
      && valid_field_value(rest)
    _ -> False
  }
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
