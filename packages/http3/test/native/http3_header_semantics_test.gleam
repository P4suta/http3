import gleam/list
import gleam/option.{None, Some}
import http3/internal/native/header_semantics
import http3/internal/qpack/header

fn field(name: BitArray, value: BitArray) -> header.Header {
  header.Header(name, value, False)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_request_control_fields_and_content_length_test() -> Nil {
  let fields = [
    field(<<":method">>, <<"POST">>),
    field(<<":scheme">>, <<"https">>),
    field(<<":authority">>, <<"example.com">>),
    field(<<":path">>, <<"/upload">>),
    field(<<"host">>, <<"example.com">>),
    field(<<"content-length">>, <<"5, 5">>),
    field(<<"te">>, <<"trailers">>),
  ]
  let assert Ok(header_semantics.Validated(
    header_semantics.RequestControlData(control),
    regular,
    Some(5),
  )) = header_semantics.validate(fields, header_semantics.RequestSection, False)
  assert control.method == <<"POST">>
  assert control.scheme == Some(<<"https">>)
  assert control.authority == Some(<<"example.com">>)
  assert control.path == Some(<<"/upload">>)
  assert control.protocol == None
  assert regular
    == [
      field(<<"host">>, <<"example.com">>),
      field(<<"content-length">>, <<"5, 5">>),
      field(<<"te">>, <<"trailers">>),
    ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_connect_and_negotiated_extended_connect_test() -> Nil {
  let connect = [
    field(<<":method">>, <<"CONNECT">>),
    field(<<":authority">>, <<"example.com:443">>),
  ]
  let assert Ok(header_semantics.Validated(
    header_semantics.RequestControlData(control),
    [],
    None,
  )) =
    header_semantics.validate(connect, header_semantics.RequestSection, False)
  assert control.scheme == None
  assert control.path == None

  let extended = [
    field(<<":method">>, <<"CONNECT">>),
    field(<<":protocol">>, <<"websocket">>),
    field(<<":scheme">>, <<"https">>),
    field(<<":authority">>, <<"example.com">>),
    field(<<":path">>, <<"/chat">>),
  ]
  assert header_semantics.validate(
      extended,
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.ExtendedConnectNotEnabled)
  let assert Ok(header_semantics.Validated(
    header_semantics.RequestControlData(control),
    [],
    None,
  )) =
    header_semantics.validate(extended, header_semantics.RequestSection, True)
  assert control.protocol == Some(<<"websocket">>)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_pseudo_header_order_duplicates_and_missing_values_test() -> Nil {
  assert header_semantics.validate(
      [
        field(<<":method">>, <<"GET">>),
        field(<<"accept">>, <<"*/*">>),
        field(<<":scheme">>, <<"https">>),
      ],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.PseudoHeaderAfterRegular)
  assert header_semantics.validate(
      [
        field(<<":method">>, <<"GET">>),
        field(<<":method">>, <<"POST">>),
      ],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.DuplicatePseudoHeader(<<":method">>))
  assert header_semantics.validate(
      [
        field(<<":method">>, <<"GET">>),
        field(<<":scheme">>, <<"https">>),
        field(<<":path">>, <<"/">>),
      ],
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.MissingPseudoHeader(<<":authority">>))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_smuggling_prone_regular_fields_test() -> Nil {
  let base = [
    field(<<":method">>, <<"GET">>),
    field(<<":scheme">>, <<"https">>),
    field(<<":authority">>, <<"example.com">>),
    field(<<":path">>, <<"/">>),
  ]
  assert header_semantics.validate(
      list.append(base, [field(<<"Connection">>, <<"close">>)]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.UppercaseFieldName)
  assert header_semantics.validate(
      list.append(base, [field(<<"transfer-encoding">>, <<"chunked">>)]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.ConnectionSpecificField(<<"transfer-encoding">>))
  assert header_semantics.validate(
      list.append(base, [field(<<"te">>, <<"gzip">>)]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.InvalidTeField)
  assert header_semantics.validate(
      list.append(base, [
        field(<<"content-length">>, <<"4">>),
        field(<<"content-length">>, <<"5">>),
      ]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.ConflictingContentLength)
  assert header_semantics.validate(
      list.append(base, [field(<<"x">>, <<"bad\r\nvalue">>)]),
      header_semantics.RequestSection,
      False,
    )
    == Error(header_semantics.InvalidFieldValue)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_response_status_and_rejects_http_upgrade_test() -> Nil {
  let assert Ok(header_semantics.Validated(
    header_semantics.ResponseControlData(103),
    [regular],
    None,
  )) =
    header_semantics.validate(
      [field(<<":status">>, <<"103">>), field(<<"link">>, <<"</a>">>)],
      header_semantics.ResponseSection,
      False,
    )
  assert regular == field(<<"link">>, <<"</a>">>)
  assert header_semantics.is_informational_status(103)
  assert !header_semantics.is_informational_status(200)
  assert header_semantics.validate(
      [field(<<":status">>, <<"101">>)],
      header_semantics.ResponseSection,
      False,
    )
    == Error(header_semantics.SwitchingProtocolsForbidden)
  assert header_semantics.validate(
      [field(<<":method">>, <<"GET">>)],
      header_semantics.ResponseSection,
      False,
    )
    == Error(header_semantics.UnexpectedPseudoHeader(<<":method">>))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn trailers_forbid_pseudo_and_framing_fields_test() -> Nil {
  let assert Ok(header_semantics.Validated(
    header_semantics.TrailerControlData,
    [decoded],
    None,
  )) =
    header_semantics.validate(
      [field(<<"checksum">>, <<"ok">>)],
      header_semantics.TrailerSection,
      False,
    )
  assert decoded == field(<<"checksum">>, <<"ok">>)
  assert header_semantics.validate(
      [field(<<":status">>, <<"200">>)],
      header_semantics.TrailerSection,
      False,
    )
    == Error(header_semantics.PseudoHeaderInTrailers)
  assert header_semantics.validate(
      [field(<<"content-length">>, <<"0">>)],
      header_semantics.TrailerSection,
      False,
    )
    == Error(header_semantics.ForbiddenTrailerField(<<"content-length">>))
}
