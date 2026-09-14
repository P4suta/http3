import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleeunit
import http/internal/http2/header_semantics
import http/internal/http2/hpack/decoder
import http/internal/http2/message

pub fn main() -> Nil {
  gleeunit.main()
}

fn field(name: String, value: String, never_index: Bool) -> decoder.Header {
  decoder.Header(<<name:utf8>>, <<value:utf8>>, never_index)
}

pub fn standard_request_becomes_valid_h2_pseudo_and_regular_fields_test() -> Nil {
  let outgoing =
    request.Request(
      method: gleam_http.Post,
      headers: [
        #("host", "example.com:8443"),
        #("authorization", "secret"),
        #("x-test", "yes"),
      ],
      body: Nil,
      scheme: gleam_http.Https,
      host: "example.com",
      port: Some(8443),
      path: "/upload",
      query: Some("mode=test"),
    )
  assert message.request_headers(outgoing)
    == Ok([
      field(":method", "POST", False),
      field(":scheme", "https", False),
      field(":authority", "example.com:8443", False),
      field(":path", "/upload?mode=test", False),
      field("authorization", "secret", True),
      field("x-test", "yes", False),
    ])
}

pub fn arbitrary_methods_and_connect_are_preserved_test() -> Nil {
  let query =
    request.Request(
      method: gleam_http.Other("QUERY"),
      headers: [],
      body: Nil,
      scheme: gleam_http.Https,
      host: "example.com",
      port: None,
      path: "/search",
      query: None,
    )
  let assert Ok([decoder.Header(<<":method">>, <<"QUERY">>, False), ..]) =
    message.request_headers(query)

  let connect =
    request.Request(
      method: gleam_http.Connect,
      headers: [],
      body: Nil,
      scheme: gleam_http.Https,
      host: "example.com",
      port: Some(443),
      path: "",
      query: None,
    )
  assert message.request_headers(connect)
    == Ok([
      field(":method", "CONNECT", False),
      field(":authority", "example.com:443", False),
    ])
}

pub fn rfc8441_outgoing_extended_connect_is_typed_and_fail_closed_test() -> Nil {
  let outgoing =
    request.Request(
      method: gleam_http.Connect,
      headers: [
        #("sec-websocket-version", "13"),
        #("authorization", "Bearer secret"),
      ],
      body: Nil,
      scheme: gleam_http.Https,
      host: "example.com",
      port: None,
      path: "/chat",
      query: Some("room=green"),
    )

  assert message.extended_connect_headers(outgoing, "websocket")
    == Ok([
      field(":method", "CONNECT", False),
      field(":protocol", "websocket", False),
      field(":scheme", "https", False),
      field(":authority", "example.com", False),
      field(":path", "/chat?room=green", False),
      field("sec-websocket-version", "13", False),
      field("authorization", "Bearer secret", True),
    ])
  assert message.extended_connect_headers(outgoing, "not a token")
    == Error(message.SemanticsFailure(header_semantics.InvalidProtocol))
  assert message.extended_connect_headers(
      request.Request(..outgoing, method: gleam_http.Get),
      "websocket",
    )
    == Error(message.InvalidMethod)
  assert message.extended_connect_headers(
      request.Request(..outgoing, headers: [#("upgrade", "websocket")]),
      "websocket",
    )
    == Error(
      message.SemanticsFailure(
        header_semantics.ConnectionSpecificField(<<"upgrade">>),
      ),
    )
}

pub fn invalid_target_port_and_connection_fields_are_rejected_test() -> Nil {
  let base =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: Nil,
      scheme: gleam_http.Https,
      host: "example.com",
      port: None,
      path: "/",
      query: None,
    )
  assert message.request_headers(request.Request(..base, port: Some(0)))
    == Error(message.InvalidPort)
  assert message.request_headers(request.Request(..base, path: "relative"))
    == Error(message.InvalidTarget)
  assert message.request_headers(
      request.Request(..base, headers: [#("connection", "close")]),
    )
    == Error(
      message.SemanticsFailure(
        header_semantics.ConnectionSpecificField(<<"connection">>),
      ),
    )
  assert message.request_headers(
      request.Request(..base, headers: [#("te", "gzip")]),
    )
    == Error(message.SemanticsFailure(header_semantics.InvalidTeField))
}

pub fn standard_response_fields_preserve_sensitive_values_test() -> Nil {
  let outgoing =
    response.Response(
      status: 204,
      headers: [#("set-cookie", "session=secret"), #("x-test", "yes")],
      body: Nil,
    )
  assert message.response_headers(outgoing)
    == Ok([
      field(":status", "204", False),
      field("set-cookie", "session=secret", True),
      field("x-test", "yes", False),
    ])
}

pub fn outgoing_trailers_are_validated_without_pseudo_headers_test() -> Nil {
  assert message.trailer_headers([
      #("checksum", "yes"),
      #("set-cookie", "secret"),
    ])
    == Ok([
      field("checksum", "yes", False),
      field("set-cookie", "secret", True),
    ])
  assert message.trailer_headers([#("content-length", "3")])
    == Error(
      message.SemanticsFailure(
        header_semantics.ForbiddenTrailerField(<<"content-length">>),
      ),
    )
}

pub fn validated_response_fields_become_a_standard_response_test() -> Nil {
  let fields = [field(":status", "200", False), field("x-test", "yes", False)]
  let assert Ok(validated) =
    header_semantics.validate(fields, header_semantics.ResponseSection, False)
  assert message.response_from_validated(validated, <<"body":utf8>>)
    == Ok(
      response.Response(status: 200, headers: [#("x-test", "yes")], body: <<
        "body":utf8,
      >>),
    )
  let assert Ok(trailers) =
    header_semantics.validate(
      [field("checksum", "ok", False)],
      header_semantics.TrailerSection,
      False,
    )
  assert message.response_from_validated(trailers, Nil)
    == Error(message.UnexpectedControlData)
}

pub fn validated_request_fields_become_a_lossless_standard_request_test() -> Nil {
  let fields = [
    field(":method", "QUERY", False),
    field(":scheme", "https", False),
    field(":authority", "example.com:8443", False),
    field(":path", "/search?q=gleam", False),
    field("x-test", "yes", False),
  ]
  let assert Ok(validated) =
    header_semantics.validate(fields, header_semantics.RequestSection, False)
  assert message.request_from_validated(
      validated,
      body: <<"body":utf8>>,
      connection_scheme: gleam_http.Https,
    )
    == Ok(request.Request(
      method: gleam_http.Other("QUERY"),
      headers: [#("x-test", "yes")],
      body: <<"body":utf8>>,
      scheme: gleam_http.Https,
      host: "example.com",
      port: Some(8443),
      path: "/search",
      query: Some("q=gleam"),
    ))
}

pub fn validated_connect_uses_the_listener_scheme_and_ipv6_authority_test() -> Nil {
  let fields = [
    field(":method", "CONNECT", False),
    field(":authority", "[::1]:443", False),
  ]
  let assert Ok(validated) =
    header_semantics.validate(fields, header_semantics.RequestSection, False)
  assert message.request_from_validated(
      validated,
      body: Nil,
      connection_scheme: gleam_http.Https,
    )
    == Ok(request.Request(
      method: gleam_http.Connect,
      headers: [],
      body: Nil,
      scheme: gleam_http.Https,
      host: "::1",
      port: Some(443),
      path: "",
      query: None,
    ))
}

pub fn received_authority_and_text_must_fit_the_standard_request_test() -> Nil {
  let invalid_authority = [
    field(":method", "GET", False),
    field(":scheme", "https", False),
    field(":authority", "example.com:99999", False),
    field(":path", "/", False),
  ]
  let assert Ok(validated) =
    header_semantics.validate(
      invalid_authority,
      header_semantics.RequestSection,
      False,
    )
  assert message.request_from_validated(
      validated,
      body: Nil,
      connection_scheme: gleam_http.Https,
    )
    == Error(message.InvalidAuthority)

  let invalid_text = [
    field(":method", "GET", False),
    field(":scheme", "https", False),
    field(":authority", "example.com", False),
    field(":path", "/", False),
    decoder.Header(<<"x-binary":utf8>>, <<255>>, False),
  ]
  let assert Ok(validated) =
    header_semantics.validate(
      invalid_text,
      header_semantics.RequestSection,
      False,
    )
  assert message.request_from_validated(
      validated,
      body: Nil,
      connection_scheme: gleam_http.Https,
    )
    == Error(message.InvalidHeaderText)
}
