import gleeunit
import http/internal/http1

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn fragmented_response_preserves_status_reason_headers_and_body_test() -> Nil {
  let assert Ok(parser) =
    http1.response_parser(http1.Limits(1024, 8, 256), <<"GET":utf8>>)
  let assert Ok(http1.ResponseNeedMore(parser)) =
    http1.feed_response(parser, <<"HTTP/1.1 200 All Good\r\nContent-Len":utf8>>)
  let assert Ok(http1.ResponseReady(head, remaining)) =
    http1.feed_response(parser, <<"gth: 4\r\nX-Test: yes\r\n\r\ndatamore":utf8>>)

  let http1.ResponseHead(status, reason, headers, framing) = head
  assert status == 200
  assert reason == <<"All Good":utf8>>
  assert headers
    == [
      http1.Header(<<"Content-Length":utf8>>, <<"4":utf8>>),
      http1.Header(<<"X-Test":utf8>>, <<"yes":utf8>>),
    ]
  assert framing == http1.ContentLength(4)
  assert remaining == <<"datamore":utf8>>
}

pub fn obsolete_line_folding_in_a_response_is_unfolded_test() -> Nil {
  // RFC 9112 section 5.2: a user agent that receives an obs-fold in a response
  // replaces each one with one or more SP characters before interpreting the
  // field value. A server receiving one in a request rejects the message
  // instead, which is why the two directions do not share an answer here.
  let assert Ok(http1.ResponseReady(head, <<>>)) =
    parse(
      <<
        "HTTP/1.1 200 OK\r\nX-Note: one\r\n two\r\nContent-Length: 0\r\n\r\n":utf8,
      >>,
      <<"GET":utf8>>,
    )
  let http1.ResponseHead(_, _, headers, _) = head
  assert headers
    == [
      http1.Header(<<"X-Note":utf8>>, <<"one two":utf8>>),
      http1.Header(<<"Content-Length":utf8>>, <<"0":utf8>>),
    ]

  // A tab folds the same way, several folds fold into several spaces, and the
  // whitespace that introduced the continuation is not kept beside the one
  // space that replaces it.
  let assert Ok(http1.ResponseReady(folded, <<>>)) =
    parse(
      <<"HTTP/1.1 200 OK\r\nX-Note: one\r\n\ttwo\r\n   three  \r\n\r\n":utf8>>,
      <<"GET":utf8>>,
    )
  let http1.ResponseHead(_, _, headers, _) = folded
  assert headers == [http1.Header(<<"X-Note":utf8>>, <<"one two three":utf8>>)]

  // A fold before any field has nothing to continue, so it is still refused.
  assert parse(<<"HTTP/1.1 200 OK\r\n bad\r\n\r\n":utf8>>, <<"GET":utf8>>)
    == Error(http1.ObsoleteLineFolding)

  // A folded framing field cannot smuggle a second message length past the
  // conflict check, because the field is complete before it is analysed.
  assert parse(
      <<
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding:\r\n chunked\r\n\r\n":utf8,
      >>,
      <<"GET":utf8>>,
    )
    == Error(http1.ConflictingMessageLength)

  // A request is not unfolded: a server rejects the message.
  let assert Ok(parser) = http1.request_parser(http1.Limits(1024, 8, 256))
  assert http1.feed_request(parser, <<
      "GET / HTTP/1.1\r\nHost: a\r\nX-Note: one\r\n two\r\n\r\n":utf8,
    >>)
    == Error(http1.ObsoleteLineFolding)
}

pub fn response_without_explicit_length_is_close_delimited_test() -> Nil {
  let assert Ok(http1.ResponseReady(head, <<>>)) =
    parse(<<"HTTP/1.1 200 OK\r\nDate: now\r\n\r\n":utf8>>, <<"GET":utf8>>)
  let http1.ResponseHead(_, _, _, framing) = head

  assert framing == http1.CloseDelimited
}

pub fn response_chunked_coding_is_selected_case_insensitively_test() -> Nil {
  let assert Ok(http1.ResponseReady(head, <<>>)) =
    parse(<<"HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n":utf8>>, <<
      "GET":utf8,
    >>)
  let http1.ResponseHead(_, _, _, framing) = head

  assert framing == http1.Chunked
}

pub fn response_transfer_encoding_content_length_conflict_is_rejected_test() -> Nil {
  let result =
    parse(
      <<
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n":utf8,
      >>,
      <<"GET":utf8>>,
    )

  assert result == Error(http1.ConflictingMessageLength)
}

pub fn head_and_bodyless_statuses_never_consume_a_message_body_test() -> Nil {
  let assert Ok(http1.ResponseReady(head, body)) =
    parse(<<"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nnext":utf8>>, <<
      "HEAD":utf8,
    >>)
  let http1.ResponseHead(_, _, _, head_framing) = head
  assert head_framing == http1.NoBody
  assert body == <<"next":utf8>>

  let assert Ok(http1.ResponseReady(no_content, <<>>)) =
    parse(<<"HTTP/1.1 204 No Content\r\n\r\n":utf8>>, <<"GET":utf8>>)
  let http1.ResponseHead(_, _, _, no_content_framing) = no_content
  assert no_content_framing == http1.NoBody

  let assert Ok(http1.ResponseReady(not_modified, <<>>)) =
    parse(<<"HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n":utf8>>, <<
      "GET":utf8,
    >>)
  let http1.ResponseHead(_, _, _, not_modified_framing) = not_modified
  assert not_modified_framing == http1.NoBody
}

pub fn informational_switching_and_successful_connect_have_no_http_body_test() -> Nil {
  let assert Ok(http1.ResponseReady(informational, <<>>)) =
    parse(<<"HTTP/1.1 103 Early Hints\r\n\r\n":utf8>>, <<"GET":utf8>>)
  let http1.ResponseHead(_, _, _, informational_framing) = informational
  assert informational_framing == http1.NoBody

  let assert Ok(http1.ResponseReady(upgrade, <<>>)) =
    parse(<<"HTTP/1.1 101 Switching Protocols\r\n\r\n":utf8>>, <<"GET":utf8>>)
  let http1.ResponseHead(_, _, _, upgrade_framing) = upgrade
  assert upgrade_framing == http1.Tunnel

  let assert Ok(http1.ResponseReady(connect, <<>>)) =
    parse(<<"HTTP/1.1 200 Connection Established\r\n\r\n":utf8>>, <<
      "CONNECT":utf8,
    >>)
  let http1.ResponseHead(_, _, _, connect_framing) = connect
  assert connect_framing == http1.Tunnel
}

pub fn malformed_status_line_and_request_method_are_typed_test() -> Nil {
  assert parse(<<"HTTP/1.1 20 OK\r\n\r\n":utf8>>, <<"GET":utf8>>)
    == Error(http1.InvalidStatusLine)
  assert http1.response_parser(http1.Limits(64, 8, 32), <<"bad method":utf8>>)
    == Error(http1.InvalidMethod)
}

pub fn response_reuses_strict_header_and_finite_limit_rules_test() -> Nil {
  assert parse(
      <<
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n":utf8,
      >>,
      <<"GET":utf8>>,
    )
    == Error(http1.DuplicateContentLength)
  // A fold with no field before it has nothing to continue and is refused; a
  // fold that does continue one is replaced with a space, which
  // obsolete_line_folding_in_a_response_is_unfolded_test covers.
  assert parse(<<"HTTP/1.1 200 OK\r\n two\r\n\r\n":utf8>>, <<"GET":utf8>>)
    == Error(http1.ObsoleteLineFolding)
}

fn parse(
  bytes: BitArray,
  request_method: BitArray,
) -> Result(http1.ResponseOutcome, http1.Error) {
  let assert Ok(parser) =
    http1.response_parser(http1.Limits(1024, 16, 256), request_method)
  http1.feed_response(parser, bytes)
}
