//// Strict RFC 9110/RFC 9114 HTTP field and pseudo-header validation.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam_quic/internal/qpack/header.{type Header, Header}

/// Context in which one decoded QPACK field section appears.
pub type SectionKind {
  RequestSection
  ResponseSection
  TrailerSection
}

/// Valid request control data.
pub type RequestControl {
  RequestControl(
    method: BitArray,
    scheme: Option(BitArray),
    authority: Option(BitArray),
    path: Option(BitArray),
    protocol: Option(BitArray),
  )
}

/// Control data recovered from a field section.
pub type Control {
  RequestControlData(RequestControl)
  ResponseControlData(status: Int)
  TrailerControlData
}

/// Validated regular fields and framing metadata.
pub type Validated {
  Validated(control: Control, fields: List(Header), content_length: Option(Int))
}

type PseudoFields {
  PseudoFields(
    method: Option(BitArray),
    scheme: Option(BitArray),
    authority: Option(BitArray),
    path: Option(BitArray),
    protocol: Option(BitArray),
    status: Option(BitArray),
  )
}

/// Malformed field section rejected before application delivery.
pub type Error {
  NonByteAligned
  EmptyFieldName
  InvalidFieldName
  UppercaseFieldName
  InvalidFieldValue
  PseudoHeaderAfterRegular
  PseudoHeaderInTrailers
  UnexpectedPseudoHeader(BitArray)
  DuplicatePseudoHeader(BitArray)
  MissingPseudoHeader(BitArray)
  InvalidMethod
  InvalidScheme
  InvalidAuthority
  InvalidPath
  InvalidProtocol
  ExtendedConnectNotEnabled
  InvalidStatus
  SwitchingProtocolsForbidden
  ConnectionSpecificField(BitArray)
  InvalidTeField
  DuplicateHost
  AuthorityHostMismatch
  InvalidContentLength
  ConflictingContentLength
  ForbiddenTrailerField(BitArray)
}

/// Validate ordering, characters, pseudo-header semantics, and message framing.
pub fn validate(
  fields: List(Header),
  section_kind: SectionKind,
  extended_connect_enabled: Bool,
) -> Result(Validated, Error) {
  let pseudo = PseudoFields(None, None, None, None, None, None)
  use #(pseudo, regular, content_length, host) <- result.try(scan(
    fields,
    section_kind,
    False,
    pseudo,
    [],
    None,
    None,
  ))
  case section_kind {
    RequestSection ->
      validate_request(
        pseudo,
        list.reverse(regular),
        content_length,
        host,
        extended_connect_enabled,
      )
    ResponseSection ->
      validate_response(pseudo, list.reverse(regular), content_length)
    TrailerSection ->
      Ok(Validated(TrailerControlData, list.reverse(regular), None))
  }
}

/// Classify a validated response status for message-stream sequencing.
pub fn is_informational_status(status: Int) -> Bool {
  status >= 100 && status < 200
}

// nolint: deep_nesting -- one recursive pass retains all header-ordering invariants.
fn scan(
  fields: List(Header),
  section_kind: SectionKind,
  regular_seen: Bool,
  pseudo: PseudoFields,
  regular_reversed: List(Header),
  content_length: Option(Int),
  host: Option(BitArray),
) -> Result(#(PseudoFields, List(Header), Option(Int), Option(BitArray)), Error) {
  case fields {
    [] -> Ok(#(pseudo, regular_reversed, content_length, host))
    [Header(name, value, _) as field, ..rest] -> {
      use _ <- result.try(validate_name(name))
      use _ <- result.try(validate_value(value))
      case is_pseudo(name) {
        True -> {
          use _ <- result.try(case regular_seen {
            True -> Error(PseudoHeaderAfterRegular)
            False -> Ok(Nil)
          })
          use pseudo <- result.try(update_pseudo(
            pseudo,
            section_kind,
            name,
            value,
          ))
          scan(
            rest,
            section_kind,
            False,
            pseudo,
            regular_reversed,
            content_length,
            host,
          )
        }
        False -> {
          use #(content_length, host) <- result.try(validate_regular_field(
            section_kind,
            name,
            value,
            content_length,
            host,
          ))
          scan(
            rest,
            section_kind,
            True,
            pseudo,
            [field, ..regular_reversed],
            content_length,
            host,
          )
        }
      }
    }
  }
}

fn update_pseudo(
  pseudo: PseudoFields,
  section_kind: SectionKind,
  name: BitArray,
  value: BitArray,
) -> Result(PseudoFields, Error) {
  case section_kind, name {
    TrailerSection, _ -> Error(PseudoHeaderInTrailers)
    RequestSection, <<":method">> ->
      set_pseudo(pseudo.method, name, fn() {
        PseudoFields(..pseudo, method: Some(value))
      })
    RequestSection, <<":scheme">> ->
      set_pseudo(pseudo.scheme, name, fn() {
        PseudoFields(..pseudo, scheme: Some(value))
      })
    RequestSection, <<":authority">> ->
      set_pseudo(pseudo.authority, name, fn() {
        PseudoFields(..pseudo, authority: Some(value))
      })
    RequestSection, <<":path">> ->
      set_pseudo(pseudo.path, name, fn() {
        PseudoFields(..pseudo, path: Some(value))
      })
    RequestSection, <<":protocol">> ->
      set_pseudo(pseudo.protocol, name, fn() {
        PseudoFields(..pseudo, protocol: Some(value))
      })
    ResponseSection, <<":status">> ->
      set_pseudo(pseudo.status, name, fn() {
        PseudoFields(..pseudo, status: Some(value))
      })
    _, _ -> Error(UnexpectedPseudoHeader(name))
  }
}

fn set_pseudo(
  current: Option(BitArray),
  name: BitArray,
  update: fn() -> PseudoFields,
) -> Result(PseudoFields, Error) {
  case current {
    Some(_) -> Error(DuplicatePseudoHeader(name))
    None -> Ok(update())
  }
}

fn validate_regular_field(
  section_kind: SectionKind,
  name: BitArray,
  value: BitArray,
  content_length: Option(Int),
  host: Option(BitArray),
) -> Result(#(Option(Int), Option(BitArray)), Error) {
  use _ <- result.try(case is_connection_specific(name) {
    True -> Error(ConnectionSpecificField(name))
    False -> Ok(Nil)
  })
  use _ <- result.try(case name, section_kind, value {
    <<"te">>, RequestSection, <<"trailers">> -> Ok(Nil)
    <<"te">>, _, _ -> Error(InvalidTeField)
    _, _, _ -> Ok(Nil)
  })
  use _ <- result.try(case section_kind, forbidden_trailer(name) {
    TrailerSection, True -> Error(ForbiddenTrailerField(name))
    _, _ -> Ok(Nil)
  })
  use content_length <- result.try(case name {
    <<"content-length">> -> merge_content_length(content_length, value)
    _ -> Ok(content_length)
  })
  use host <- result.try(case name, host {
    <<"host">>, Some(_) -> Error(DuplicateHost)
    <<"host">>, None -> Ok(Some(value))
    _, _ -> Ok(host)
  })
  Ok(#(content_length, host))
}

fn validate_request(
  pseudo: PseudoFields,
  regular: List(Header),
  content_length: Option(Int),
  host: Option(BitArray),
  extended_connect_enabled: Bool,
) -> Result(Validated, Error) {
  use method <- result.try(require(pseudo.method, <<":method">>))
  use _ <- result.try(case valid_token(method) {
    True -> Ok(Nil)
    False -> Error(InvalidMethod)
  })
  case method, pseudo.protocol {
    <<"CONNECT">>, None ->
      validate_connect(pseudo, regular, content_length, host)
    <<"CONNECT">>, Some(_) ->
      validate_extended_connect(
        pseudo,
        regular,
        content_length,
        host,
        extended_connect_enabled,
      )
    _, Some(_) -> Error(InvalidProtocol)
    _, None -> validate_ordinary_request(pseudo, regular, content_length, host)
  }
}

fn validate_connect(
  pseudo: PseudoFields,
  regular: List(Header),
  content_length: Option(Int),
  host: Option(BitArray),
) -> Result(Validated, Error) {
  use authority <- result.try(require(pseudo.authority, <<":authority">>))
  use _ <- result.try(validate_authority(authority, True))
  use _ <- result.try(case pseudo.scheme, pseudo.path {
    None, None -> Ok(Nil)
    _, _ -> Error(InvalidPath)
  })
  use _ <- result.try(validate_host_match(Some(authority), host, True))
  Ok(Validated(
    RequestControlData(RequestControl(
      <<"CONNECT">>,
      None,
      Some(authority),
      None,
      None,
    )),
    regular,
    content_length,
  ))
}

fn validate_extended_connect(
  pseudo: PseudoFields,
  regular: List(Header),
  content_length: Option(Int),
  host: Option(BitArray),
  extended_connect_enabled: Bool,
) -> Result(Validated, Error) {
  use _ <- result.try(case extended_connect_enabled {
    True -> Ok(Nil)
    False -> Error(ExtendedConnectNotEnabled)
  })
  use scheme <- result.try(require(pseudo.scheme, <<":scheme">>))
  use authority <- result.try(require(pseudo.authority, <<":authority">>))
  use path <- result.try(require(pseudo.path, <<":path">>))
  use protocol <- result.try(require(pseudo.protocol, <<":protocol">>))
  use _ <- result.try(validate_scheme(scheme))
  use _ <- result.try(validate_authority(authority, is_http_scheme(scheme)))
  use _ <- result.try(validate_request_path(path, scheme, <<"CONNECT">>))
  use _ <- result.try(case valid_token(protocol) {
    True -> Ok(Nil)
    False -> Error(InvalidProtocol)
  })
  use _ <- result.try(validate_host_match(Some(authority), host, True))
  Ok(Validated(
    RequestControlData(RequestControl(
      <<"CONNECT">>,
      Some(scheme),
      Some(authority),
      Some(path),
      Some(protocol),
    )),
    regular,
    content_length,
  ))
}

fn validate_ordinary_request(
  pseudo: PseudoFields,
  regular: List(Header),
  content_length: Option(Int),
  host: Option(BitArray),
) -> Result(Validated, Error) {
  use method <- result.try(require(pseudo.method, <<":method">>))
  use scheme <- result.try(require(pseudo.scheme, <<":scheme">>))
  use path <- result.try(require(pseudo.path, <<":path">>))
  use _ <- result.try(validate_scheme(scheme))
  use _ <- result.try(validate_request_path(path, scheme, method))
  use _ <- result.try(case pseudo.authority {
    Some(authority) -> validate_authority(authority, is_http_scheme(scheme))
    None -> Ok(Nil)
  })
  use _ <- result.try(validate_host_match(
    pseudo.authority,
    host,
    is_http_scheme(scheme),
  ))
  Ok(Validated(
    RequestControlData(RequestControl(
      method,
      Some(scheme),
      pseudo.authority,
      Some(path),
      None,
    )),
    regular,
    content_length,
  ))
}

fn validate_response(
  pseudo: PseudoFields,
  regular: List(Header),
  content_length: Option(Int),
) -> Result(Validated, Error) {
  use encoded_status <- result.try(require(pseudo.status, <<":status">>))
  use status <- result.try(parse_status(encoded_status))
  Ok(Validated(ResponseControlData(status), regular, content_length))
}

fn validate_host_match(
  authority: Option(BitArray),
  host: Option(BitArray),
  mandatory: Bool,
) -> Result(Nil, Error) {
  case authority, host, mandatory {
    None, None, True -> Error(MissingPseudoHeader(<<":authority">>))
    Some(<<>>), _, _ -> Error(InvalidAuthority)
    _, Some(<<>>), _ -> Error(InvalidAuthority)
    Some(authority), Some(host), _ if authority != host ->
      Error(AuthorityHostMismatch)
    _, _, _ -> Ok(Nil)
  }
}

fn validate_authority(
  authority: BitArray,
  reject_userinfo: Bool,
) -> Result(Nil, Error) {
  case
    bit_array.byte_size(authority) > 0
    && { !reject_userinfo || !contains_byte(authority, 0x40) }
  {
    True -> Ok(Nil)
    False -> Error(InvalidAuthority)
  }
}

fn validate_scheme(scheme: BitArray) -> Result(Nil, Error) {
  case scheme {
    <<first, rest:bits>> ->
      case ascii_alpha(first) && valid_scheme_tail(rest) {
        True -> Ok(Nil)
        False -> Error(InvalidScheme)
      }
    _ -> Error(InvalidScheme)
  }
}

fn validate_request_path(
  path: BitArray,
  scheme: BitArray,
  method: BitArray,
) -> Result(Nil, Error) {
  case path, method, is_http_scheme(scheme) {
    <<"*">>, <<"OPTIONS">>, _ -> Ok(Nil)
    <<"*">>, _, _ -> Error(InvalidPath)
    <<>>, _, True -> Error(InvalidPath)
    _, _, _ -> Ok(Nil)
  }
}

fn parse_status(encoded: BitArray) -> Result(Int, Error) {
  case encoded {
    <<first, second, third>> ->
      case
        decimal_digit(first) && decimal_digit(second) && decimal_digit(third)
      {
        False -> Error(InvalidStatus)
        True -> {
          let status = { first - 48 } * 100 + { second - 48 } * 10 + third - 48
          case status {
            101 -> Error(SwitchingProtocolsForbidden)
            value if value >= 100 && value <= 599 -> Ok(value)
            _ -> Error(InvalidStatus)
          }
        }
      }
    _ -> Error(InvalidStatus)
  }
}

fn merge_content_length(
  current: Option(Int),
  encoded: BitArray,
) -> Result(Option(Int), Error) {
  case bit_array.to_string(encoded) {
    Error(_) -> Error(InvalidContentLength)
    Ok(value) -> {
      use parsed <- result.try(parse_content_length_parts(
        string.split(value, ","),
        None,
      ))
      case current, parsed {
        None, value -> Ok(Some(value))
        Some(existing), value if existing == value -> Ok(current)
        Some(_), _ -> Error(ConflictingContentLength)
      }
    }
  }
}

fn parse_content_length_parts(
  parts: List(String),
  parsed: Option(Int),
) -> Result(Int, Error) {
  case parts {
    [] -> Error(InvalidContentLength)
    [part, ..rest] -> {
      let part = string.trim(part)
      use value <- result.try(parse_decimal(part))
      use parsed <- result.try(case parsed {
        None -> Ok(Some(value))
        Some(existing) if existing == value -> Ok(parsed)
        Some(_) -> Error(ConflictingContentLength)
      })
      case rest {
        [] -> Ok(value)
        _ -> parse_content_length_parts(rest, parsed)
      }
    }
  }
}

fn parse_decimal(value: String) -> Result(Int, Error) {
  let bytes = <<value:utf8>>
  case bytes != <<>> && all_decimal_digits(bytes), int.parse(value) {
    True, Ok(parsed) if parsed >= 0 -> Ok(parsed)
    _, _ -> Error(InvalidContentLength)
  }
}

fn require(value: Option(BitArray), name: BitArray) -> Result(BitArray, Error) {
  case value {
    Some(value) -> Ok(value)
    None -> Error(MissingPseudoHeader(name))
  }
}

fn validate_name(name: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(name) % 8, name {
    remainder, _ if remainder != 0 -> Error(NonByteAligned)
    _, <<>> -> Error(EmptyFieldName)
    _, <<0x3a, rest:bits>> -> validate_name_bytes(rest)
    _, _ -> validate_name_bytes(name)
  }
}

fn validate_name_bytes(name: BitArray) -> Result(Nil, Error) {
  case name {
    <<>> -> Error(EmptyFieldName)
    _ -> validate_token_bytes(name)
  }
}

fn validate_token_bytes(name: BitArray) -> Result(Nil, Error) {
  case name {
    <<>> -> Ok(Nil)
    <<byte, _:bits>> if byte >= 65 && byte <= 90 -> Error(UppercaseFieldName)
    <<byte, rest:bits>> ->
      case token_byte(byte) {
        True -> validate_token_bytes(rest)
        False -> Error(InvalidFieldName)
      }
    _ -> Error(NonByteAligned)
  }
}

fn validate_value(value: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(value) % 8, value {
    remainder, _ if remainder != 0 -> Error(NonByteAligned)
    _, <<>> -> Ok(Nil)
    _, <<first, _:bits>> if first == 0x20 || first == 0x09 ->
      Error(InvalidFieldValue)
    _, <<first, _:bits>> if first == 0 || first == 0x0a || first == 0x0d ->
      Error(InvalidFieldValue)
    _, <<first, rest:bits>> -> validate_value_bytes(rest, first)
    _, _ -> Error(NonByteAligned)
  }
}

fn validate_value_bytes(value: BitArray, previous: Int) -> Result(Nil, Error) {
  case value, previous {
    <<>>, byte if byte == 0x20 || byte == 0x09 -> Error(InvalidFieldValue)
    <<>>, _ -> Ok(Nil)
    <<byte, _:bits>>, _ if byte == 0 || byte == 0x0a || byte == 0x0d ->
      Error(InvalidFieldValue)
    <<byte, rest:bits>>, _ -> validate_value_bytes(rest, byte)
    _, _ -> Error(NonByteAligned)
  }
}

fn valid_token(value: BitArray) -> Bool {
  case value {
    <<>> -> False
    _ -> all_token_bytes(value)
  }
}

fn all_token_bytes(value: BitArray) -> Bool {
  case value {
    <<>> -> True
    <<byte, rest:bits>> ->
      case token_byte(byte) {
        True -> all_token_bytes(rest)
        False -> False
      }
    _ -> False
  }
}

fn all_decimal_digits(value: BitArray) -> Bool {
  case value {
    <<>> -> True
    <<byte, rest:bits>> ->
      case decimal_digit(byte) {
        True -> all_decimal_digits(rest)
        False -> False
      }
    _ -> False
  }
}

fn valid_scheme_tail(value: BitArray) -> Bool {
  case value {
    <<>> -> True
    <<byte, rest:bits>> ->
      case
        ascii_alpha(byte)
        || decimal_digit(byte)
        || byte == 0x2b
        || byte == 0x2d
        || byte == 0x2e
      {
        True -> valid_scheme_tail(rest)
        False -> False
      }
    _ -> False
  }
}

fn is_pseudo(name: BitArray) -> Bool {
  case name {
    <<0x3a, _:bits>> -> True
    _ -> False
  }
}

fn is_http_scheme(scheme: BitArray) -> Bool {
  scheme == <<"http">> || scheme == <<"https">>
}

fn contains_byte(value: BitArray, target: Int) -> Bool {
  case value {
    <<>> -> False
    <<byte, _:bits>> if byte == target -> True
    <<_, rest:bits>> -> contains_byte(rest, target)
    _ -> False
  }
}

fn is_connection_specific(name: BitArray) -> Bool {
  case name {
    <<"connection">>
    | <<"keep-alive">>
    | <<"proxy-connection">>
    | <<"transfer-encoding">>
    | <<"upgrade">> -> True
    _ -> False
  }
}

fn forbidden_trailer(name: BitArray) -> Bool {
  case name {
    <<"authorization">>
    | <<"content-encoding">>
    | <<"content-length">>
    | <<"content-range">>
    | <<"content-type">>
    | <<"host">>
    | <<"proxy-authenticate">>
    | <<"proxy-authorization">>
    | <<"te">>
    | <<"trailer">>
    | <<"www-authenticate">> -> True
    _ -> False
  }
}

fn token_byte(byte: Int) -> Bool {
  ascii_alpha(byte)
  || decimal_digit(byte)
  || case byte {
    0x21
    | 0x23
    | 0x24
    | 0x25
    | 0x26
    | 0x27
    | 0x2a
    | 0x2b
    | 0x2d
    | 0x2e
    | 0x5e
    | 0x5f
    | 0x60
    | 0x7c
    | 0x7e -> True
    _ -> False
  }
}

fn ascii_alpha(byte: Int) -> Bool {
  { byte >= 65 && byte <= 90 } || { byte >= 97 && byte <= 122 }
}

fn decimal_digit(byte: Int) -> Bool {
  byte >= 48 && byte <= 57
}
