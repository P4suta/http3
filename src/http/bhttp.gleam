//// Bounded Binary HTTP Messages codec for RFC 9292.
////
//// The codec accepts the two standard request and response framing modes,
//// preserves indeterminate-length content chunks, and applies independent
//// limits before retaining or slicing peer-controlled data.

import gleam/bit_array
import gleam/list
import gleam/result

const maximum_integer = 4_611_686_018_427_387_903

/// One HTTP field line. Names are lower-case HTTP tokens and values are raw,
/// byte-aligned field values without NUL, CR, LF, or boundary SP/HTAB.
pub type Field {
  Field(name: String, value: BitArray)
}

/// One informational response preceding a final response.
pub type Informational {
  Informational(status: Int, headers: List(Field))
}

/// A complete binary HTTP request or response.
///
/// Content is represented as chunks. Known-length decoding necessarily
/// returns at most one chunk because that framing does not carry boundaries.
pub type Message {
  Request(
    method: String,
    scheme: String,
    authority: String,
    path: String,
    headers: List(Field),
    content: List(BitArray),
    trailers: List(Field),
    padding: Int,
  )
  Response(
    informational: List(Informational),
    status: Int,
    headers: List(Field),
    content: List(BitArray),
    trailers: List(Field),
    padding: Int,
  )
}

/// RFC 9292 framing indicator family.
pub type Mode {
  KnownLength
  IndeterminateLength
}

/// Independent finite bounds for one message.
pub type Limits {
  Limits(
    maximum_bytes: Int,
    maximum_fields: Int,
    maximum_field_section_bytes: Int,
    maximum_content_bytes: Int,
    maximum_chunks: Int,
    maximum_padding_bytes: Int,
  )
}

/// A finite decoder retaining incomplete fragments until the caller marks the
/// input complete.
pub opaque type Decoder {
  Decoder(buffered: BitArray, limits: Limits)
}

/// Incremental decode progress.
pub type Progress {
  Awaiting(Decoder)
  Decoded(Message)
}

/// Invalid configuration, wire syntax, message semantics, or resource use.
pub type Error {
  InvalidLimits
  InvalidFraming
  InvalidMessage
  InvalidField
  InvalidPadding
  NonByteAligned
  Truncated
  LimitExceeded
}

/// Conservative finite defaults for a single binary HTTP message.
pub fn defaults() -> Limits {
  Limits(
    maximum_bytes: 16_777_216,
    maximum_fields: 4096,
    maximum_field_section_bytes: 1_048_576,
    maximum_content_bytes: 16_777_216,
    maximum_chunks: 4096,
    maximum_padding_bytes: 1_048_576,
  )
}

/// Create a bounded incremental decoder.
pub fn decoder(limits: Limits) -> Result(Decoder, Error) {
  use _ <- result.try(validate_limits(limits))
  Ok(Decoder(<<>>, limits))
}

/// Append a fragment. Parsing occurs only when `finished` is true, preventing
/// RFC 9292's legal trailing-section omission from being mistaken for a
/// complete message before stream end.
pub fn push(
  decoder decoder: Decoder,
  fragment fragment: BitArray,
  finished finished: Bool,
) -> Result(Progress, Error) {
  use _ <- result.try(require_aligned(fragment))
  let retained =
    bit_array.byte_size(decoder.buffered) + bit_array.byte_size(fragment)
  use _ <- result.try(require(retained <= decoder.limits.maximum_bytes))
  let buffered = bit_array.append(decoder.buffered, fragment)
  case finished {
    False -> Ok(Awaiting(Decoder(buffered, decoder.limits)))
    True -> decode(buffered, decoder.limits) |> result.map(Decoded)
  }
}

/// Encode one complete request or response using the selected RFC framing.
pub fn encode(
  message message: Message,
  mode mode: Mode,
  limits limits: Limits,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(validate_message(message, limits))
  use wire <- result.try(case message {
    Request(
      method,
      scheme,
      authority,
      path,
      headers,
      content,
      trailers,
      padding,
    ) ->
      encode_request(
        method,
        scheme,
        authority,
        path,
        headers,
        content,
        trailers,
        padding,
        mode,
        limits,
      )
    Response(informational, status, headers, content, trailers, padding) ->
      encode_response(
        informational,
        status,
        headers,
        content,
        trailers,
        padding,
        mode,
        limits,
      )
  })
  use _ <- result.try(require(bit_array.byte_size(wire) <= limits.maximum_bytes))
  Ok(wire)
}

/// Decode exactly one complete RFC 9292 message.
pub fn decode(bytes: BitArray, limits: Limits) -> Result(Message, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(require_aligned(bytes))
  use _ <- result.try(require(
    bit_array.byte_size(bytes) <= limits.maximum_bytes,
  ))
  use #(framing, rest) <- result.try(decode_integer(bytes))
  use message <- result.try(case framing {
    0 -> decode_request(rest, KnownLength, limits)
    1 -> decode_response(rest, KnownLength, limits)
    2 -> decode_request(rest, IndeterminateLength, limits)
    3 -> decode_response(rest, IndeterminateLength, limits)
    _ -> Error(InvalidFraming)
  })
  use _ <- result.try(validate_message(message, limits))
  Ok(message)
}

fn encode_request(
  method: String,
  scheme: String,
  authority: String,
  path: String,
  headers: List(Field),
  content: List(BitArray),
  trailers: List(Field),
  padding: Int,
  mode: Mode,
  limits: Limits,
) -> Result(BitArray, Error) {
  use framing <- result.try(
    encode_integer(case mode {
      KnownLength -> 0
      IndeterminateLength -> 2
    }),
  )
  use controls <- result.try(encode_controls(method, scheme, authority, path))
  use headers <- result.try(encode_fields(headers, mode, limits))
  use content <- result.try(encode_content(content, mode, limits))
  use trailers <- result.try(encode_fields(trailers, mode, limits))
  use padding <- result.try(encode_padding(padding))
  Ok(<<
    framing:bits,
    controls:bits,
    headers:bits,
    content:bits,
    trailers:bits,
    padding:bits,
  >>)
}

fn encode_response(
  informational: List(Informational),
  status: Int,
  headers: List(Field),
  content: List(BitArray),
  trailers: List(Field),
  padding: Int,
  mode: Mode,
  limits: Limits,
) -> Result(BitArray, Error) {
  use framing <- result.try(
    encode_integer(case mode {
      KnownLength -> 1
      IndeterminateLength -> 3
    }),
  )
  use informational <- result.try(
    encode_informational(informational, mode, limits, []),
  )
  use status <- result.try(encode_integer(status))
  use headers <- result.try(encode_fields(headers, mode, limits))
  use content <- result.try(encode_content(content, mode, limits))
  use trailers <- result.try(encode_fields(trailers, mode, limits))
  use padding <- result.try(encode_padding(padding))
  Ok(
    bit_array.concat([
      framing,
      ..list.append(informational, [status, headers, content, trailers, padding])
    ]),
  )
}

fn encode_informational(
  values: List(Informational),
  mode: Mode,
  limits: Limits,
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case values {
    [] -> Ok(list.reverse(reversed))
    [Informational(status, headers), ..rest] -> {
      use encoded_status <- result.try(encode_integer(status))
      use encoded_headers <- result.try(encode_fields(headers, mode, limits))
      encode_informational(rest, mode, limits, [
        encoded_headers,
        encoded_status,
        ..reversed
      ])
    }
  }
}

fn encode_controls(
  method: String,
  scheme: String,
  authority: String,
  path: String,
) -> Result(BitArray, Error) {
  use method <- result.try(encode_string(method))
  use scheme <- result.try(encode_string(scheme))
  use authority <- result.try(encode_string(authority))
  use path <- result.try(encode_string(path))
  Ok(<<method:bits, scheme:bits, authority:bits, path:bits>>)
}

fn encode_string(value: String) -> Result(BitArray, Error) {
  let bytes = bit_array.from_string(value)
  use length <- result.try(encode_integer(bit_array.byte_size(bytes)))
  Ok(<<length:bits, bytes:bits>>)
}

fn encode_fields(
  fields: List(Field),
  mode: Mode,
  limits: Limits,
) -> Result(BitArray, Error) {
  use lines <- result.try(encode_field_lines(fields, []))
  let section = bit_array.concat(lines)
  use _ <- result.try(require(
    bit_array.byte_size(section) <= limits.maximum_field_section_bytes,
  ))
  case mode {
    KnownLength -> {
      use length <- result.try(encode_integer(bit_array.byte_size(section)))
      Ok(<<length:bits, section:bits>>)
    }
    IndeterminateLength -> Ok(<<section:bits, 0>>)
  }
}

fn encode_field_lines(
  fields: List(Field),
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case fields {
    [] -> Ok(list.reverse(reversed))
    [Field(name, value), ..rest] -> {
      let name = bit_array.from_string(name)
      use name_length <- result.try(encode_integer(bit_array.byte_size(name)))
      use value_length <- result.try(encode_integer(bit_array.byte_size(value)))
      encode_field_lines(rest, [
        <<name_length:bits, name:bits, value_length:bits, value:bits>>,
        ..reversed
      ])
    }
  }
}

fn encode_content(
  chunks: List(BitArray),
  mode: Mode,
  limits: Limits,
) -> Result(BitArray, Error) {
  case mode {
    KnownLength -> {
      let content = bit_array.concat(chunks)
      use _ <- result.try(require(
        bit_array.byte_size(content) <= limits.maximum_content_bytes,
      ))
      use length <- result.try(encode_integer(bit_array.byte_size(content)))
      Ok(<<length:bits, content:bits>>)
    }
    IndeterminateLength -> {
      use chunks <- result.try(encode_chunks(chunks, []))
      Ok(<<bit_array.concat(chunks):bits, 0>>)
    }
  }
}

fn encode_chunks(
  chunks: List(BitArray),
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case chunks {
    [] -> Ok(list.reverse(reversed))
    [chunk, ..rest] -> {
      use _ <- result.try(require(bit_array.byte_size(chunk) > 0))
      use length <- result.try(encode_integer(bit_array.byte_size(chunk)))
      encode_chunks(rest, [<<length:bits, chunk:bits>>, ..reversed])
    }
  }
}

fn encode_padding(count: Int) -> Result(BitArray, Error) {
  case count >= 0 {
    True -> Ok(<<0:size(count * 8)>>)
    False -> Error(InvalidPadding)
  }
}

fn decode_request(
  bytes: BitArray,
  mode: Mode,
  limits: Limits,
) -> Result(Message, Error) {
  use #(method, rest) <- result.try(decode_string(bytes))
  use #(scheme, rest) <- result.try(decode_string(rest))
  use #(authority, rest) <- result.try(decode_string(rest))
  use #(path, rest) <- result.try(decode_string(rest))
  case rest {
    <<>> -> Ok(Request(method, scheme, authority, path, [], [], [], 0))
    _ -> {
      use #(headers, rest) <- result.try(decode_fields(rest, mode, limits))
      use #(content, trailers, padding) <- result.try(decode_body(
        rest,
        mode,
        limits,
      ))
      Ok(Request(
        method,
        scheme,
        authority,
        path,
        headers,
        content,
        trailers,
        padding,
      ))
    }
  }
}

fn decode_response(
  bytes: BitArray,
  mode: Mode,
  limits: Limits,
) -> Result(Message, Error) {
  use #(informational, status, rest) <- result.try(
    decode_statuses(bytes, mode, limits, []),
  )
  case rest {
    <<>> -> Ok(Response(informational, status, [], [], [], 0))
    _ -> {
      use #(headers, rest) <- result.try(decode_fields(rest, mode, limits))
      use #(content, trailers, padding) <- result.try(decode_body(
        rest,
        mode,
        limits,
      ))
      Ok(Response(informational, status, headers, content, trailers, padding))
    }
  }
}

fn decode_statuses(
  bytes: BitArray,
  mode: Mode,
  limits: Limits,
  reversed: List(Informational),
) -> Result(#(List(Informational), Int, BitArray), Error) {
  use #(status, rest) <- result.try(decode_integer(bytes))
  case status {
    status if status >= 100 && status <= 199 -> {
      use #(headers, rest) <- result.try(decode_fields(rest, mode, limits))
      decode_statuses(rest, mode, limits, [
        Informational(status, headers),
        ..reversed
      ])
    }
    status if status >= 200 && status <= 599 ->
      Ok(#(list.reverse(reversed), status, rest))
    _ -> Error(InvalidMessage)
  }
}

fn decode_string(bytes: BitArray) -> Result(#(String, BitArray), Error) {
  use #(length, rest) <- result.try(decode_integer(bytes))
  use #(value, rest) <- result.try(take(rest, length))
  case bit_array.to_string(value) {
    Ok(value) -> Ok(#(value, rest))
    Error(_) -> Error(InvalidMessage)
  }
}

fn decode_fields(
  bytes: BitArray,
  mode: Mode,
  limits: Limits,
) -> Result(#(List(Field), BitArray), Error) {
  case mode {
    KnownLength -> {
      use #(length, rest) <- result.try(decode_integer(bytes))
      use _ <- result.try(require(length <= limits.maximum_field_section_bytes))
      use #(section, rest) <- result.try(take(rest, length))
      use fields <- result.try(decode_known_field_lines(section, limits, []))
      Ok(#(fields, rest))
    }
    IndeterminateLength ->
      decode_indeterminate_field_lines(bytes, limits, [], 0)
  }
}

fn decode_known_field_lines(
  bytes: BitArray,
  limits: Limits,
  reversed: List(Field),
) -> Result(List(Field), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    _ -> {
      use #(field, rest) <- result.try(decode_field_line(bytes))
      use _ <- result.try(require(list.length(reversed) < limits.maximum_fields))
      decode_known_field_lines(rest, limits, [field, ..reversed])
    }
  }
}

fn decode_indeterminate_field_lines(
  bytes: BitArray,
  limits: Limits,
  reversed: List(Field),
  used: Int,
) -> Result(#(List(Field), BitArray), Error) {
  use #(name_length, after_length) <- result.try(decode_integer(bytes))
  case name_length {
    0 -> Ok(#(list.reverse(reversed), after_length))
    _ -> {
      use _ <- result.try(require(list.length(reversed) < limits.maximum_fields))
      use #(name_bytes, rest) <- result.try(take(after_length, name_length))
      use #(value_length, rest) <- result.try(decode_integer(rest))
      use #(value, rest) <- result.try(take(rest, value_length))
      let consumed = bit_array.byte_size(bytes) - bit_array.byte_size(rest)
      use _ <- result.try(require(
        used + consumed <= limits.maximum_field_section_bytes,
      ))
      use field <- result.try(make_field(name_bytes, value))
      decode_indeterminate_field_lines(
        rest,
        limits,
        [field, ..reversed],
        used + consumed,
      )
    }
  }
}

fn decode_field_line(bytes: BitArray) -> Result(#(Field, BitArray), Error) {
  use #(name_length, rest) <- result.try(decode_integer(bytes))
  case name_length {
    0 -> Error(InvalidField)
    _ -> {
      use #(name, rest) <- result.try(take(rest, name_length))
      use #(value_length, rest) <- result.try(decode_integer(rest))
      use #(value, rest) <- result.try(take(rest, value_length))
      use field <- result.try(make_field(name, value))
      Ok(#(field, rest))
    }
  }
}

fn make_field(name: BitArray, value: BitArray) -> Result(Field, Error) {
  case bit_array.to_string(name) {
    Error(_) -> Error(InvalidField)
    Ok(name) -> {
      use _ <- result.try(validate_field(Field(name, value)))
      Ok(Field(name, value))
    }
  }
}

fn decode_body(
  bytes: BitArray,
  mode: Mode,
  limits: Limits,
) -> Result(#(List(BitArray), List(Field), Int), Error) {
  case bytes {
    <<>> -> Ok(#([], [], 0))
    _ -> {
      use #(content, rest) <- result.try(decode_content(bytes, mode, limits))
      case rest {
        <<>> -> Ok(#(content, [], 0))
        _ -> {
          use #(trailers, rest) <- result.try(decode_fields(rest, mode, limits))
          use padding <- result.try(decode_padding(rest, limits))
          Ok(#(content, trailers, padding))
        }
      }
    }
  }
}

fn decode_content(
  bytes: BitArray,
  mode: Mode,
  limits: Limits,
) -> Result(#(List(BitArray), BitArray), Error) {
  case mode {
    KnownLength -> {
      use #(length, rest) <- result.try(decode_integer(bytes))
      use _ <- result.try(require(length <= limits.maximum_content_bytes))
      use #(content, rest) <- result.try(take(rest, length))
      case content {
        <<>> -> Ok(#([], rest))
        _ -> Ok(#([content], rest))
      }
    }
    IndeterminateLength -> decode_chunks(bytes, limits, [], 0)
  }
}

fn decode_chunks(
  bytes: BitArray,
  limits: Limits,
  reversed: List(BitArray),
  used: Int,
) -> Result(#(List(BitArray), BitArray), Error) {
  use #(length, rest) <- result.try(decode_integer(bytes))
  case length {
    0 -> Ok(#(list.reverse(reversed), rest))
    _ -> {
      use _ <- result.try(require(list.length(reversed) < limits.maximum_chunks))
      use _ <- result.try(require(used + length <= limits.maximum_content_bytes))
      use #(chunk, rest) <- result.try(take(rest, length))
      decode_chunks(rest, limits, [chunk, ..reversed], used + length)
    }
  }
}

fn decode_padding(bytes: BitArray, limits: Limits) -> Result(Int, Error) {
  let count = bit_array.byte_size(bytes)
  use _ <- result.try(require(count <= limits.maximum_padding_bytes))
  case all_zero(bytes) {
    True -> Ok(count)
    False -> Error(InvalidPadding)
  }
}

fn all_zero(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<0, rest:bits>> -> all_zero(rest)
    _ -> False
  }
}

fn validate_limits(limits: Limits) -> Result(Nil, Error) {
  case
    limits.maximum_bytes > 0
    && limits.maximum_fields > 0
    && limits.maximum_field_section_bytes >= 0
    && limits.maximum_field_section_bytes <= limits.maximum_bytes
    && limits.maximum_content_bytes >= 0
    && limits.maximum_content_bytes <= limits.maximum_bytes
    && limits.maximum_chunks > 0
    && limits.maximum_padding_bytes >= 0
    && limits.maximum_padding_bytes <= limits.maximum_bytes
  {
    True -> Ok(Nil)
    False -> Error(InvalidLimits)
  }
}

fn validate_message(message: Message, limits: Limits) -> Result(Nil, Error) {
  case message {
    Request(
      method,
      scheme,
      authority,
      path,
      headers,
      content,
      trailers,
      padding,
    ) -> {
      use _ <- result.try(validate_controls(method, scheme, authority, path))
      validate_parts([], headers, content, trailers, padding, limits)
    }
    Response(informational, status, headers, content, trailers, padding) -> {
      use _ <- result.try(require_status(status, 200, 599))
      use _ <- result.try(validate_informational(informational))
      validate_parts(informational, headers, content, trailers, padding, limits)
    }
  }
}

fn validate_controls(
  method: String,
  scheme: String,
  authority: String,
  path: String,
) -> Result(Nil, Error) {
  case
    method != ""
    && path != ""
    && valid_control(method)
    && valid_control(scheme)
    && valid_control(authority)
    && valid_control(path)
  {
    True -> Ok(Nil)
    False -> Error(InvalidMessage)
  }
}

fn valid_control(value: String) -> Bool {
  valid_control_bytes(bit_array.from_string(value))
}

fn valid_control_bytes(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, rest:bits>> if byte != 0 && byte != 10 && byte != 13 ->
      valid_control_bytes(rest)
    _ -> False
  }
}

fn validate_informational(values: List(Informational)) -> Result(Nil, Error) {
  case values {
    [] -> Ok(Nil)
    [Informational(status, _), ..rest] -> {
      use _ <- result.try(require_status(status, 100, 199))
      validate_informational(rest)
    }
  }
}

fn validate_parts(
  informational: List(Informational),
  headers: List(Field),
  content: List(BitArray),
  trailers: List(Field),
  padding: Int,
  limits: Limits,
) -> Result(Nil, Error) {
  let field_count =
    list.length(headers)
    + list.length(trailers)
    + informational_field_count(informational, 0)
  use _ <- result.try(require(field_count <= limits.maximum_fields))
  use _ <- result.try(validate_fields(headers))
  use _ <- result.try(validate_fields(trailers))
  use _ <- result.try(validate_informational_fields(informational))
  use _ <- result.try(require(list.length(content) <= limits.maximum_chunks))
  use content_bytes <- result.try(validate_chunks(content, 0))
  use _ <- result.try(require(content_bytes <= limits.maximum_content_bytes))
  case padding >= 0 && padding <= limits.maximum_padding_bytes {
    True -> Ok(Nil)
    False -> Error(LimitExceeded)
  }
}

fn informational_field_count(values: List(Informational), count: Int) -> Int {
  case values {
    [] -> count
    [Informational(_, headers), ..rest] ->
      informational_field_count(rest, count + list.length(headers))
  }
}

fn validate_informational_fields(
  values: List(Informational),
) -> Result(Nil, Error) {
  case values {
    [] -> Ok(Nil)
    [Informational(_, headers), ..rest] -> {
      use _ <- result.try(validate_fields(headers))
      validate_informational_fields(rest)
    }
  }
}

fn validate_fields(fields: List(Field)) -> Result(Nil, Error) {
  case fields {
    [] -> Ok(Nil)
    [field, ..rest] -> {
      use _ <- result.try(validate_field(field))
      validate_fields(rest)
    }
  }
}

fn validate_field(field: Field) -> Result(Nil, Error) {
  case
    field.name != ""
    && valid_field_name(bit_array.from_string(field.name))
    && bit_array.bit_size(field.value) % 8 == 0
    && valid_field_value(field.value)
  {
    True -> Ok(Nil)
    False -> Error(InvalidField)
  }
}

fn valid_field_name(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, rest:bits>> ->
      case is_lower_token_byte(byte) {
        True -> valid_field_name(rest)
        False -> False
      }
    _ -> False
  }
}

fn is_lower_token_byte(byte: Int) -> Bool {
  byte >= 97
  && byte <= 122
  || byte >= 48
  && byte <= 57
  || byte == 33
  || byte == 35
  || byte == 36
  || byte == 37
  || byte == 38
  || byte == 39
  || byte == 42
  || byte == 43
  || byte == 45
  || byte == 46
  || byte == 94
  || byte == 95
  || byte == 96
  || byte == 124
  || byte == 126
}

fn valid_field_value(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, _rest:bits>> if byte == 9 || byte == 32 -> False
    _ -> valid_field_value_tail(bytes, False)
  }
}

fn valid_field_value_tail(bytes: BitArray, trailing_whitespace: Bool) -> Bool {
  case bytes {
    <<>> -> !trailing_whitespace
    <<byte, _rest:bits>> if byte == 0 || byte == 10 || byte == 13 -> False
    <<byte, rest:bits>> -> valid_field_value_tail(rest, byte == 9 || byte == 32)
    _ -> False
  }
}

fn validate_chunks(chunks: List(BitArray), total: Int) -> Result(Int, Error) {
  case chunks {
    [] -> Ok(total)
    [chunk, ..rest] ->
      case bit_array.bit_size(chunk) % 8, bit_array.byte_size(chunk) {
        remainder, _ if remainder != 0 -> Error(NonByteAligned)
        _, 0 -> Error(InvalidMessage)
        _, size -> validate_chunks(rest, total + size)
      }
  }
}

fn require_status(
  status: Int,
  minimum: Int,
  maximum: Int,
) -> Result(Nil, Error) {
  case status >= minimum && status <= maximum {
    True -> Ok(Nil)
    False -> Error(InvalidMessage)
  }
}

fn require_aligned(bytes: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(bytes) % 8 {
    0 -> Ok(Nil)
    _ -> Error(NonByteAligned)
  }
}

fn require(condition: Bool) -> Result(Nil, Error) {
  case condition {
    True -> Ok(Nil)
    False -> Error(LimitExceeded)
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Error) {
  case length < 0 || length > bit_array.byte_size(bytes) {
    True -> Error(Truncated)
    False -> {
      let bits = length * 8
      case bytes {
        <<value:bits-size(bits), rest:bits>> -> Ok(#(value, rest))
        _ -> Error(Truncated)
      }
    }
  }
}

fn decode_integer(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case bytes {
    <<0:size(2), value:size(6), rest:bits>> -> Ok(#(value, rest))
    <<1:size(2), value:size(14), rest:bits>> -> Ok(#(value, rest))
    <<2:size(2), value:size(30), rest:bits>> -> Ok(#(value, rest))
    <<3:size(2), value:size(62), rest:bits>> -> Ok(#(value, rest))
    _ -> Error(Truncated)
  }
}

fn encode_integer(value: Int) -> Result(BitArray, Error) {
  case value {
    value if value < 0 -> Error(InvalidMessage)
    value if value <= 63 -> Ok(<<0:size(2), value:size(6)>>)
    value if value <= 16_383 -> Ok(<<1:size(2), value:size(14)>>)
    value if value <= 1_073_741_823 -> Ok(<<2:size(2), value:size(30)>>)
    value if value <= maximum_integer -> Ok(<<3:size(2), value:size(62)>>)
    _ -> Error(LimitExceeded)
  }
}
