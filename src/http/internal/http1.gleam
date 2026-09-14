//// Strict, finite HTTP/1.1 request-head parsing.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result

const maximum_content_length = 9_223_372_036_854_775_807

/// Finite request-head parsing policy.
pub type Limits {
  Limits(
    maximum_head_bytes: Int,
    maximum_header_count: Int,
    maximum_line_bytes: Int,
  )
}

/// One wire header with its original field-name spelling and semantic value.
pub type Header {
  Header(name: BitArray, value: BitArray)
}

/// Body framing selected only after all message-length fields are validated.
pub type Framing {
  NoBody
  ContentLength(Int)
  Chunked
  CloseDelimited
  Tunnel
}

/// A validated HTTP/1.1 request head.
pub type RequestHead {
  RequestHead(
    method: BitArray,
    target: BitArray,
    headers: List(Header),
    framing: Framing,
  )
}

/// A finite parser retaining only an incomplete request head.
pub opaque type RequestParser {
  RequestParser(limits: Limits, buffered: BitArray)
}

/// A validated HTTP/1.1 response head.
pub type ResponseHead {
  ResponseHead(
    status: Int,
    reason: BitArray,
    headers: List(Header),
    framing: Framing,
  )
}

/// A finite response parser bound to the request method it answers.
pub opaque type ResponseParser {
  ResponseParser(limits: Limits, request_method: BitArray, buffered: BitArray)
}

/// Incremental request parsing progress.
pub type RequestOutcome {
  NeedMore(RequestParser)
  RequestReady(RequestHead, remaining: BitArray)
}

/// Incremental response parsing progress.
pub type ResponseOutcome {
  ResponseNeedMore(ResponseParser)
  ResponseReady(ResponseHead, remaining: BitArray)
}

type MessageFields {
  MessageFields(
    content_length: Option(Int),
    transfer_encoding: Bool,
    host_count: Int,
  )
}

/// A syntax, framing, or finite-resource failure.
pub type Error {
  InvalidLimit
  NonByteAligned
  HeadTooLarge(maximum: Int)
  LineTooLong(maximum: Int)
  TooManyHeaders(maximum: Int)
  InvalidLineEnding
  InvalidRequestLine
  InvalidStatusLine
  InvalidMethod
  InvalidTarget
  UnsupportedVersion
  InvalidHeaderName
  InvalidHeaderValue
  ObsoleteLineFolding
  WhitespaceBeforeColon
  DuplicateContentLength
  InvalidContentLength
  InvalidTransferEncoding
  ConflictingMessageLength
  MissingHost
  DuplicateHost
  InvalidHost
}

/// Construct an empty request parser with explicit finite bounds.
pub fn request_parser(limits: Limits) -> Result(RequestParser, Error) {
  case limits {
    Limits(maximum_head_bytes, maximum_header_count, maximum_line_bytes)
      if maximum_head_bytes > 0
      && maximum_header_count > 0
      && maximum_line_bytes > 0
      && maximum_line_bytes <= maximum_head_bytes
    -> Ok(RequestParser(limits, <<>>))
    _ -> Error(InvalidLimit)
  }
}

/// Construct an empty response parser for one request method.
pub fn response_parser(
  limits: Limits,
  request_method: BitArray,
) -> Result(ResponseParser, Error) {
  use _ <- result.try(request_parser(limits))
  case bit_array.bit_size(request_method) % 8, valid_token(request_method) {
    0, True -> Ok(ResponseParser(limits, request_method, <<>>))
    _, _ -> Error(InvalidMethod)
  }
}

/// Return the request method bound to an internal response parser. This keeps
/// informational-response chaining independent of backend terms.
pub fn response_request_method(parser: ResponseParser) -> BitArray {
  parser.request_method
}

/// Append one transport chunk and parse at most one request head.
///
/// Bytes following the header terminator are returned untouched and are not
/// charged to the request-head limit.
pub fn feed_request(
  parser: RequestParser,
  bytes: BitArray,
) -> Result(RequestOutcome, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      let combined = <<parser.buffered:bits, bytes:bits>>
      case find_head_end(combined, 0) {
        Some(head_end) ->
          parse_complete_request(parser.limits, combined, head_end)
        None -> retain_incomplete_request(parser.limits, combined)
      }
    }
  }
}

/// Append one transport chunk and parse at most one response head.
pub fn feed_response(
  parser: ResponseParser,
  bytes: BitArray,
) -> Result(ResponseOutcome, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      let combined = <<parser.buffered:bits, bytes:bits>>
      case find_head_end(combined, 0) {
        Some(head_end) ->
          parse_complete_response(
            parser.limits,
            parser.request_method,
            combined,
            head_end,
          )
        None -> retain_incomplete_response(parser, combined)
      }
    }
  }
}

fn parse_complete_request(
  limits: Limits,
  combined: BitArray,
  head_end: Int,
) -> Result(RequestOutcome, Error) {
  use <- require(
    head_end <= limits.maximum_head_bytes,
    HeadTooLarge(limits.maximum_head_bytes),
  )
  use head_lines <- result.try(
    bit_array.slice(combined, at: 0, take: head_end - 2)
    |> result.replace_error(InvalidLineEnding),
  )
  use <- require(valid_line_endings(head_lines), InvalidLineEnding)
  use lines <- result.try(
    split_lines(head_lines, limits.maximum_line_bytes, []),
  )
  use head <- result.try(parse_request_lines(lines, limits.maximum_header_count))
  use remaining <- result.try(
    bit_array.slice(
      combined,
      at: head_end,
      take: bit_array.byte_size(combined) - head_end,
    )
    |> result.replace_error(InvalidLineEnding),
  )
  Ok(RequestReady(head, remaining))
}

fn retain_incomplete_request(
  limits: Limits,
  combined: BitArray,
) -> Result(RequestOutcome, Error) {
  use <- require(valid_line_endings(combined), InvalidLineEnding)
  use <- require(
    partial_lines_within_limit(combined, limits.maximum_line_bytes, 0),
    LineTooLong(limits.maximum_line_bytes),
  )
  use <- require(
    bit_array.byte_size(combined) < limits.maximum_head_bytes,
    HeadTooLarge(limits.maximum_head_bytes),
  )
  Ok(NeedMore(RequestParser(limits, combined)))
}

fn parse_complete_response(
  limits: Limits,
  request_method: BitArray,
  combined: BitArray,
  head_end: Int,
) -> Result(ResponseOutcome, Error) {
  use <- require(
    head_end <= limits.maximum_head_bytes,
    HeadTooLarge(limits.maximum_head_bytes),
  )
  use head_lines <- result.try(
    bit_array.slice(combined, at: 0, take: head_end - 2)
    |> result.replace_error(InvalidLineEnding),
  )
  use <- require(valid_line_endings(head_lines), InvalidLineEnding)
  use lines <- result.try(
    split_lines(head_lines, limits.maximum_line_bytes, []),
  )
  use head <- result.try(parse_response_lines(
    lines,
    limits.maximum_header_count,
    request_method,
  ))
  use remaining <- result.try(
    bit_array.slice(
      combined,
      at: head_end,
      take: bit_array.byte_size(combined) - head_end,
    )
    |> result.replace_error(InvalidLineEnding),
  )
  Ok(ResponseReady(head, remaining))
}

fn retain_incomplete_response(
  parser: ResponseParser,
  combined: BitArray,
) -> Result(ResponseOutcome, Error) {
  use <- require(valid_line_endings(combined), InvalidLineEnding)
  use <- require(
    partial_lines_within_limit(combined, parser.limits.maximum_line_bytes, 0),
    LineTooLong(parser.limits.maximum_line_bytes),
  )
  use <- require(
    bit_array.byte_size(combined) < parser.limits.maximum_head_bytes,
    HeadTooLarge(parser.limits.maximum_head_bytes),
  )
  Ok(ResponseNeedMore(ResponseParser(..parser, buffered: combined)))
}

fn parse_request_lines(
  lines: List(BitArray),
  maximum_header_count: Int,
) -> Result(RequestHead, Error) {
  case lines {
    [request_line, ..header_lines] -> {
      use #(method, target) <- result.try(parse_request_line(request_line))
      use headers <- result.try(
        parse_headers(header_lines, maximum_header_count, 0, []),
      )
      use fields <- result.try(analyse_message_fields(
        headers,
        MessageFields(None, False, 0),
      ))
      use framing <- result.try(finish_request_framing(fields))
      Ok(RequestHead(method, target, headers, framing))
    }
    _ -> Error(InvalidRequestLine)
  }
}

fn parse_response_lines(
  lines: List(BitArray),
  maximum_header_count: Int,
  request_method: BitArray,
) -> Result(ResponseHead, Error) {
  case lines {
    [status_line, ..header_lines] -> {
      use #(status, reason) <- result.try(parse_status_line(status_line))
      use headers <- result.try(
        parse_headers(header_lines, maximum_header_count, 0, []),
      )
      use fields <- result.try(analyse_message_fields(
        headers,
        MessageFields(None, False, 0),
      ))
      use framing <- result.try(finish_response_framing(
        fields,
        status,
        request_method,
      ))
      Ok(ResponseHead(status, reason, headers, framing))
    }
    _ -> Error(InvalidStatusLine)
  }
}

fn parse_request_line(line: BitArray) -> Result(#(BitArray, BitArray), Error) {
  case split_on_byte(line, 0x20, [], <<>>) {
    [method, target, <<"HTTP/1.1":utf8>>] -> {
      use <- require(valid_token(method), InvalidMethod)
      use <- require(valid_target(target), InvalidTarget)
      Ok(#(method, target))
    }
    [method, target, _version] -> {
      use <- require(valid_token(method), InvalidMethod)
      use <- require(valid_target(target), InvalidTarget)
      Error(UnsupportedVersion)
    }
    _ -> Error(InvalidRequestLine)
  }
}

fn parse_status_line(line: BitArray) -> Result(#(Int, BitArray), Error) {
  case line {
    <<"HTTP/1.1 ":utf8, hundreds, tens, units, 0x20, reason:bytes>>
      if hundreds >= 0x31
      && hundreds <= 0x39
      && tens >= 0x30
      && tens <= 0x39
      && units >= 0x30
      && units <= 0x39
    -> {
      use <- require(valid_field_value(reason), InvalidStatusLine)
      Ok(#(
        { hundreds - 0x30 } * 100 + { tens - 0x30 } * 10 + units - 0x30,
        reason,
      ))
    }
    _ -> Error(InvalidStatusLine)
  }
}

fn parse_headers(
  lines: List(BitArray),
  maximum: Int,
  count: Int,
  reversed: List(Header),
) -> Result(List(Header), Error) {
  case lines {
    [] -> Ok(list.reverse(reversed))
    [line, ..rest] -> {
      use <- require(count < maximum, TooManyHeaders(maximum))
      use header <- result.try(parse_header(line))
      parse_headers(rest, maximum, count + 1, [header, ..reversed])
    }
  }
}

/// Parse a CRLF-terminated trailer field block for the body decoder.
pub fn parse_trailer_block(
  bytes: BitArray,
  maximum_header_count: Int,
  maximum_line_bytes: Int,
) -> Result(List(Header), Error) {
  case bytes {
    <<>> -> Ok([])
    _ -> {
      use lines <- result.try(split_lines(bytes, maximum_line_bytes, []))
      parse_headers(lines, maximum_header_count, 0, [])
    }
  }
}

/// Compare a parsed field name using HTTP's ASCII case-insensitive rule.
pub fn header_name_equals(header: Header, expected: BitArray) -> Bool {
  let Header(name, _) = header
  ascii_equal_case_insensitive(name, expected)
}

fn parse_header(line: BitArray) -> Result(Header, Error) {
  case line {
    <<0x20, _:bytes>> -> Error(ObsoleteLineFolding)
    <<0x09, _:bytes>> -> Error(ObsoleteLineFolding)
    _ ->
      case find_byte(line, 0x3a, 0) {
        None -> Error(InvalidHeaderName)
        Some(colon) -> {
          use name <- result.try(
            bit_array.slice(line, at: 0, take: colon)
            |> result.replace_error(InvalidHeaderName),
          )
          use raw_value <- result.try(
            bit_array.slice(
              line,
              at: colon + 1,
              take: bit_array.byte_size(line) - colon - 1,
            )
            |> result.replace_error(InvalidHeaderValue),
          )
          use <- require(!contains_ows(name), WhitespaceBeforeColon)
          use <- require(valid_token(name), InvalidHeaderName)
          use <- require(valid_field_value(raw_value), InvalidHeaderValue)
          use value <- result.try(trim_ows(raw_value))
          Ok(Header(name, value))
        }
      }
  }
}

fn analyse_message_fields(
  headers: List(Header),
  fields: MessageFields,
) -> Result(MessageFields, Error) {
  case headers {
    [] -> Ok(fields)
    [Header(name, value), ..rest] -> {
      use fields <- result.try(analyse_message_field(name, value, fields))
      analyse_message_fields(rest, fields)
    }
  }
}

fn analyse_message_field(
  name: BitArray,
  value: BitArray,
  fields: MessageFields,
) -> Result(MessageFields, Error) {
  case ascii_equal_case_insensitive(name, <<"content-length":utf8>>) {
    True -> analyse_content_length_field(value, fields)
    False -> analyse_non_content_length_field(name, value, fields)
  }
}

fn analyse_content_length_field(
  value: BitArray,
  fields: MessageFields,
) -> Result(MessageFields, Error) {
  use <- require(fields.content_length == None, DuplicateContentLength)
  use length <- result.try(parse_content_length(value))
  Ok(MessageFields(..fields, content_length: Some(length)))
}

fn analyse_non_content_length_field(
  name: BitArray,
  value: BitArray,
  fields: MessageFields,
) -> Result(MessageFields, Error) {
  case ascii_equal_case_insensitive(name, <<"transfer-encoding":utf8>>) {
    True -> {
      use <- require(!fields.transfer_encoding, InvalidTransferEncoding)
      use <- require(
        ascii_equal_case_insensitive(value, <<"chunked":utf8>>),
        InvalidTransferEncoding,
      )
      Ok(MessageFields(..fields, transfer_encoding: True))
    }
    False ->
      case ascii_equal_case_insensitive(name, <<"host":utf8>>) {
        True -> {
          use <- require(valid_host(value), InvalidHost)
          Ok(MessageFields(..fields, host_count: fields.host_count + 1))
        }
        False -> Ok(fields)
      }
  }
}

fn finish_request_framing(fields: MessageFields) -> Result(Framing, Error) {
  case fields.host_count {
    0 -> Error(MissingHost)
    1 -> finish_explicit_framing(fields, NoBody)
    _ -> Error(DuplicateHost)
  }
}

fn finish_response_framing(
  fields: MessageFields,
  status: Int,
  request_method: BitArray,
) -> Result(Framing, Error) {
  use _ <- result.try(finish_explicit_framing(fields, CloseDelimited))
  case response_has_no_http_body(status, request_method) {
    Some(framing) -> Ok(framing)
    None -> finish_explicit_framing(fields, CloseDelimited)
  }
}

fn finish_explicit_framing(
  fields: MessageFields,
  absent: Framing,
) -> Result(Framing, Error) {
  case fields.content_length, fields.transfer_encoding {
    Some(_), True -> Error(ConflictingMessageLength)
    None, True -> Ok(Chunked)
    Some(length), False -> Ok(ContentLength(length))
    None, False -> Ok(absent)
  }
}

fn response_has_no_http_body(
  status: Int,
  request_method: BitArray,
) -> Option(Framing) {
  let is_head = ascii_equal_case_insensitive(request_method, <<"HEAD":utf8>>)
  let is_connect =
    ascii_equal_case_insensitive(request_method, <<"CONNECT":utf8>>)
  case status, is_head, is_connect {
    101, _, _ -> Some(Tunnel)
    status, _, _ if status >= 100 && status < 200 -> Some(NoBody)
    204, _, _ -> Some(NoBody)
    304, _, _ -> Some(NoBody)
    status, False, True if status >= 200 && status < 300 -> Some(Tunnel)
    _, True, _ -> Some(NoBody)
    _, False, _ -> None
  }
}

fn parse_content_length(bytes: BitArray) -> Result(Int, Error) {
  case bytes {
    <<>> -> Error(InvalidContentLength)
    _ -> parse_content_length_loop(bytes, 0)
  }
}

fn parse_content_length_loop(
  bytes: BitArray,
  accumulated: Int,
) -> Result(Int, Error) {
  case bytes {
    <<>> -> Ok(accumulated)
    <<byte, rest:bytes>> if byte >= 0x30 && byte <= 0x39 -> {
      let next = accumulated * 10 + byte - 0x30
      use <- require(next <= maximum_content_length, InvalidContentLength)
      parse_content_length_loop(rest, next)
    }
    _ -> Error(InvalidContentLength)
  }
}

fn split_lines(
  bytes: BitArray,
  maximum_line_bytes: Int,
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    _ ->
      case find_crlf(bytes, 0) {
        None -> Error(InvalidLineEnding)
        Some(length) -> {
          use <- require(
            length <= maximum_line_bytes,
            LineTooLong(maximum_line_bytes),
          )
          use line <- result.try(
            bit_array.slice(bytes, at: 0, take: length)
            |> result.replace_error(InvalidLineEnding),
          )
          use rest <- result.try(
            bit_array.slice(
              bytes,
              at: length + 2,
              take: bit_array.byte_size(bytes) - length - 2,
            )
            |> result.replace_error(InvalidLineEnding),
          )
          split_lines(rest, maximum_line_bytes, [line, ..reversed])
        }
      }
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
    <<>> -> None
    _ -> None
  }
}

fn split_on_byte(
  bytes: BitArray,
  separator: Int,
  reversed: List(BitArray),
  current: BitArray,
) -> List(BitArray) {
  case bytes {
    <<>> -> list.reverse([current, ..reversed])
    <<byte, rest:bytes>> if byte == separator ->
      split_on_byte(rest, separator, [current, ..reversed], <<>>)
    <<byte, rest:bytes>> ->
      split_on_byte(rest, separator, reversed, <<current:bits, byte>>)
    _ -> list.reverse([current, ..reversed])
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

fn partial_lines_within_limit(
  bytes: BitArray,
  maximum: Int,
  current: Int,
) -> Bool {
  case bytes {
    <<>> -> current <= maximum
    <<0x0d>> -> current <= maximum
    <<0x0d, 0x0a, rest:bytes>> ->
      current <= maximum && partial_lines_within_limit(rest, maximum, 0)
    <<_, rest:bytes>> ->
      current < maximum
      && partial_lines_within_limit(rest, maximum, current + 1)
    _ -> False
  }
}

fn contains_ows(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> False
    <<byte, _rest:bytes>> if byte == 0x20 || byte == 0x09 -> True
    <<_, rest:bytes>> -> contains_ows(rest)
    _ -> False
  }
}

fn trim_ows(bytes: BitArray) -> Result(BitArray, Error) {
  let without_leading = trim_leading_ows(bytes)
  let retained = last_non_ows_end(without_leading, 0, 0)
  bit_array.slice(without_leading, at: 0, take: retained)
  |> result.replace_error(InvalidHeaderValue)
}

fn trim_leading_ows(bytes: BitArray) -> BitArray {
  case bytes {
    <<byte, rest:bytes>> if byte == 0x20 || byte == 0x09 ->
      trim_leading_ows(rest)
    _ -> bytes
  }
}

fn last_non_ows_end(bytes: BitArray, offset: Int, retained: Int) -> Int {
  case bytes {
    <<>> -> retained
    <<byte, rest:bytes>> if byte == 0x20 || byte == 0x09 ->
      last_non_ows_end(rest, offset + 1, retained)
    <<_, rest:bytes>> -> last_non_ows_end(rest, offset + 1, offset + 1)
    _ -> retained
  }
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

fn valid_host(bytes: BitArray) -> Bool {
  case bytes {
    <<0x5b, rest:bytes>> -> valid_bracketed_host(rest)
    _ ->
      case split_on_byte(bytes, 0x3a, [], <<>>) {
        [host] -> valid_reg_name(host)
        [host, port] -> valid_reg_name(host) && valid_port(port)
        _ -> False
      }
  }
}

fn valid_bracketed_host(bytes: BitArray) -> Bool {
  case find_byte(bytes, 0x5d, 0) {
    None -> False
    Some(closing) ->
      case
        bit_array.slice(bytes, at: 0, take: closing),
        bit_array.slice(
          bytes,
          at: closing + 1,
          take: bit_array.byte_size(bytes) - closing - 1,
        )
      {
        Ok(literal), Ok(following) ->
          valid_ip_literal(literal)
          && case following {
            <<>> -> True
            <<0x3a, port:bytes>> -> valid_port(port)
            _ -> False
          }
        _, _ -> False
      }
  }
}

fn valid_ip_literal(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> False
    _ -> valid_ip_literal_bytes(bytes)
  }
}

fn valid_ip_literal_bytes(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, rest:bytes>> ->
      {
        byte >= 0x30
        && byte <= 0x39
        || byte >= 0x41
        && byte <= 0x5a
        || byte >= 0x61
        && byte <= 0x7a
        || byte == 0x21
        || byte == 0x24
        || byte == 0x25
        || byte == 0x26
        || byte == 0x27
        || byte == 0x28
        || byte == 0x29
        || byte == 0x2a
        || byte == 0x2b
        || byte == 0x2c
        || byte == 0x2d
        || byte == 0x2e
        || byte == 0x3a
        || byte == 0x3b
        || byte == 0x3d
        || byte == 0x5f
        || byte == 0x7e
      }
      && valid_ip_literal_bytes(rest)
    _ -> False
  }
}

fn valid_reg_name(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> False
    _ -> valid_reg_name_bytes(bytes)
  }
}

fn valid_reg_name_bytes(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<0x25, first, second, rest:bytes>> ->
      is_hexadecimal(first)
      && is_hexadecimal(second)
      && valid_reg_name_bytes(rest)
    <<byte, rest:bytes>> ->
      {
        byte >= 0x30
        && byte <= 0x39
        || byte >= 0x41
        && byte <= 0x5a
        || byte >= 0x61
        && byte <= 0x7a
        || byte == 0x21
        || byte == 0x24
        || byte == 0x26
        || byte == 0x27
        || byte == 0x28
        || byte == 0x29
        || byte == 0x2a
        || byte == 0x2b
        || byte == 0x2d
        || byte == 0x2e
        || byte == 0x3b
        || byte == 0x3d
        || byte == 0x5f
        || byte == 0x7e
      }
      && valid_reg_name_bytes(rest)
    _ -> False
  }
}

fn valid_port(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> False
    _ -> valid_port_bytes(bytes, 0)
  }
}

fn valid_port_bytes(bytes: BitArray, port: Int) -> Bool {
  case bytes {
    <<>> -> True
    <<digit, rest:bytes>> if digit >= 0x30 && digit <= 0x39 -> {
      let port = port * 10 + digit - 0x30
      port <= 65_535 && valid_port_bytes(rest, port)
    }
    _ -> False
  }
}

fn is_hexadecimal(byte: Int) -> Bool {
  byte >= 0x30
  && byte <= 0x39
  || byte >= 0x41
  && byte <= 0x46
  || byte >= 0x61
  && byte <= 0x66
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

fn ascii_equal_case_insensitive(left: BitArray, right: BitArray) -> Bool {
  case left, right {
    <<>>, <<>> -> True
    <<left_byte, left_rest:bytes>>, <<right_byte, right_rest:bytes>> ->
      ascii_lower(left_byte) == ascii_lower(right_byte)
      && ascii_equal_case_insensitive(left_rest, right_rest)
    _, _ -> False
  }
}

fn ascii_lower(byte: Int) -> Int {
  case byte >= 0x41 && byte <= 0x5a {
    True -> byte + 0x20
    False -> byte
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
