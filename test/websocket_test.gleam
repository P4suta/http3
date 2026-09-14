import gleam/http
import gleam/option.{None, Some}
import gleeunit
import http/websocket

pub fn main() -> Nil {
  gleeunit.main()
}

const rfc_key = "dGhlIHNhbXBsZSBub25jZQ=="

const rfc_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

pub fn rfc6455_accept_and_mask_vectors_test() -> Nil {
  let assert Ok(handshake) =
    websocket.client_handshake_with_key(websocket.Http1, rfc_key, ["chat"])
  assert websocket.request_headers(handshake)
    == [
      #("connection", "Upgrade"),
      #("upgrade", "websocket"),
      #("sec-websocket-version", "13"),
      #("sec-websocket-key", rfc_key),
      #("sec-websocket-protocol", "chat"),
    ]
  assert websocket.validate_response(handshake, 101, [
      #("connection", "upgrade"),
      #("upgrade", "websocket"),
      #("sec-websocket-accept", rfc_accept),
      #("sec-websocket-protocol", "chat"),
    ])
    == Ok(Some("chat"))

  assert websocket.encode_with_mask(
      websocket.Frame(True, websocket.Text, <<"Hello":utf8>>),
      Some(<<0x37, 0xfa, 0x21, 0x3d>>),
    )
    == Ok(<<0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58>>)
}

pub fn h1_and_extended_connect_handshakes_are_distinct_test() -> Nil {
  let request_headers = [
    #("connection", "keep-alive, Upgrade"),
    #("upgrade", "websocket"),
    #("sec-websocket-version", "13"),
    #("sec-websocket-key", rfc_key),
    #("sec-websocket-protocol", "superchat, chat"),
  ]
  let assert Ok(response) =
    websocket.accept_handshake(
      websocket.Http1,
      http.Get,
      "http",
      "example.test",
      None,
      request_headers,
      ["chat"],
    )
  assert websocket.response_status(response) == 101
  assert websocket.selected_protocol(response) == Some("chat")
  assert websocket.response_headers(response)
    == [
      #("connection", "Upgrade"),
      #("upgrade", "websocket"),
      #("sec-websocket-accept", rfc_accept),
      #("sec-websocket-protocol", "chat"),
    ]

  let extended_headers = [
    #("sec-websocket-version", "13"),
  ]
  let assert Ok(h2) =
    websocket.accept_handshake(
      websocket.Http2,
      http.Connect,
      "https",
      "example.test",
      Some("websocket"),
      extended_headers,
      [],
    )
  assert websocket.response_status(h2) == 200
  assert websocket.response_headers(h2) == []

  assert websocket.accept_handshake(
      websocket.Http3,
      http.Get,
      "https",
      "example.test",
      Some("websocket"),
      extended_headers,
      [],
    )
    == Error(websocket.InvalidHandshake)
  assert websocket.accept_handshake(
      websocket.Http2,
      http.Connect,
      "https",
      "example.test",
      Some("not-websocket"),
      extended_headers,
      [],
    )
    == Error(websocket.InvalidHandshake)
}

pub fn rfc8441_h2_handshake_omits_h1_nonce_fields_and_supports_ws_test() -> Nil {
  let assert Ok(client) =
    websocket.client_handshake_with_key(websocket.Http2, rfc_key, ["chat"])
  assert websocket.request_headers(client)
    == [
      #("sec-websocket-version", "13"),
      #("sec-websocket-protocol", "chat"),
    ]
  assert websocket.validate_response(client, 200, [
      #("sec-websocket-protocol", "chat"),
    ])
    == Ok(Some("chat"))

  let assert Ok(server) =
    websocket.accept_handshake(
      websocket.Http2,
      http.Connect,
      "http",
      "example.test",
      Some("websocket"),
      [#("sec-websocket-version", "13")],
      [],
    )
  assert websocket.response_status(server) == 200
  assert websocket.response_headers(server) == []
}

pub fn client_response_rejects_status_accept_extensions_and_protocol_drift_test() -> Nil {
  let assert Ok(h3) =
    websocket.client_handshake_with_key(websocket.Http3, rfc_key, ["chat"])
  assert websocket.validate_response(h3, 101, [
      #("sec-websocket-accept", rfc_accept),
      #("sec-websocket-protocol", "chat"),
    ])
    == Error(websocket.UnexpectedStatus(101))
  assert websocket.validate_response(h3, 200, [
      #("sec-websocket-accept", "not-processed-for-extended-connect"),
    ])
    == Ok(None)
  let assert Ok(h1) =
    websocket.client_handshake_with_key(websocket.Http1, rfc_key, [])
  assert websocket.validate_response(h1, 101, [
      #("connection", "upgrade"),
      #("upgrade", "websocket"),
      #("sec-websocket-accept", "wrong"),
    ])
    == Error(websocket.AcceptMismatch)
  assert websocket.validate_response(h3, 200, [
      #("sec-websocket-extensions", "permessage-deflate"),
    ])
    == Error(websocket.ExtensionsForbidden)
  assert websocket.validate_response(h3, 200, [
      #("sec-websocket-protocol", "other"),
    ])
    == Error(websocket.SubprotocolMismatch)
}

pub fn fragmented_utf8_ping_and_close_are_one_bounded_session_test() -> Nil {
  let limits = websocket.Limits(64, 96)
  let assert Ok(session) = websocket.session(websocket.Server, limits)
  let assert Ok(session) =
    websocket.push(session, <<0x01, 0x81, 1, 2, 3, 4, 0x69>>)
  let assert Ok(websocket.NeedMore(session)) = websocket.next(session)

  // A control frame may be interleaved in a fragmented message.
  let assert Ok(session) =
    websocket.push(session, <<0x89, 0x81, 1, 2, 3, 4, 0x3e>>)
  let assert Ok(websocket.EventReady(
    session,
    websocket.Ping(<<"?":utf8>>),
    [pong],
  )) = websocket.next(session)
  assert pong == <<0x8a, 0x01, "?":utf8>>

  let assert Ok(session) =
    websocket.push(session, <<0x00, 0x81, 1, 2, 3, 4, 0xc2>>)
  let assert Ok(websocket.NeedMore(session)) = websocket.next(session)
  let assert Ok(session) =
    websocket.push(session, <<0x80, 0x81, 1, 2, 3, 4, 0xa8>>)
  let assert Ok(websocket.EventReady(session, websocket.TextMessage("hé"), [])) =
    websocket.next(session)

  let assert Ok(session) =
    websocket.push(session, <<0x88, 0x82, 1, 2, 3, 4, 0x02, 0xea>>)
  let assert Ok(websocket.EventReady(closed_session, close_event, [reply])) =
    websocket.next(session)
  assert websocket.buffered_bytes(closed_session) == 0
  assert close_event == websocket.CloseReceived(Some(1000), "")
  assert reply == <<0x88, 0x02, 1000:size(16)>>
}

pub fn server_requires_masks_and_session_rejects_invalid_fragmentation_test() -> Nil {
  let limits = websocket.Limits(8, 22)
  let assert Ok(server) = websocket.session(websocket.Server, limits)
  let assert Ok(server) = websocket.push(server, <<0x81, 0x01, "x":utf8>>)
  assert websocket.next(server) == Error(websocket.MaskRequired)

  let assert Ok(client) = websocket.session(websocket.Client, limits)
  let assert Ok(client) = websocket.push(client, <<0x80, 0x01, "x":utf8>>)
  assert websocket.next(client) == Error(websocket.ProtocolViolation)

  let assert Ok(client) = websocket.session(websocket.Client, limits)
  let assert Ok(client) = websocket.push(client, <<0x09, 0x00>>)
  assert websocket.next(client) == Error(websocket.FragmentedControl)
}

pub fn finite_buffers_message_limits_and_close_codes_fail_closed_test() -> Nil {
  assert websocket.session(websocket.Client, websocket.Limits(8, 7))
    == Error(websocket.InvalidLimit)
  let assert Ok(client) =
    websocket.session(websocket.Client, websocket.Limits(8, 22))
  assert websocket.push(client, <<0:size(184)>>)
    == Error(websocket.BufferLimitExceeded(22))

  let assert Ok(client) =
    websocket.session(websocket.Client, websocket.Limits(4, 18))
  let assert Ok(client) = websocket.push(client, <<0x82, 0x05, "hello":utf8>>)
  assert websocket.next(client) == Error(websocket.PayloadLimitExceeded(4))

  assert websocket.close_frame(websocket.Server, Some(1005), "")
    == Error(websocket.InvalidClose)
  assert websocket.close_frame(websocket.Server, None, "reason")
    == Error(websocket.InvalidClose)
}
