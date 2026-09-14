import gleeunit
import http/internal/http1

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn fragmented_request_head_preserves_wire_values_and_body_test() -> Nil {
  let assert Ok(parser) = http1.request_parser(http1.Limits(1024, 8, 256))
  let assert Ok(http1.NeedMore(parser)) =
    http1.feed_request(parser, <<
      "QUERY /items?tag=a HTTP/1.1\r\nHost: example.test\r\nX-Raw: a":utf8,
    >>)
  let assert Ok(http1.RequestReady(head, body)) =
    http1.feed_request(parser, <<
      "  b\r\nContent-Length: 4\r\n\r\ndataafter":utf8,
    >>)

  let http1.RequestHead(method, target, headers, framing) = head
  assert method == <<"QUERY":utf8>>
  assert target == <<"/items?tag=a":utf8>>
  assert headers
    == [
      http1.Header(<<"Host":utf8>>, <<"example.test":utf8>>),
      http1.Header(<<"X-Raw":utf8>>, <<"a  b":utf8>>),
      http1.Header(<<"Content-Length":utf8>>, <<"4":utf8>>),
    ]
  assert framing == http1.ContentLength(4)
  assert body == <<"dataafter":utf8>>
}

pub fn transfer_encoding_and_content_length_conflict_is_rejected_test() -> Nil {
  let result =
    parse(<<
      "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n":utf8,
    >>)

  assert result == Error(http1.ConflictingMessageLength)
}

pub fn obsolete_line_folding_is_rejected_test() -> Nil {
  let result =
    parse(<<"GET / HTTP/1.1\r\nHost: example.test\r\n folded\r\n\r\n":utf8>>)

  assert result == Error(http1.ObsoleteLineFolding)
}

pub fn whitespace_before_header_colon_is_rejected_test() -> Nil {
  let result = parse(<<"GET / HTTP/1.1\r\nHost : example.test\r\n\r\n":utf8>>)

  assert result == Error(http1.WhitespaceBeforeColon)
}

pub fn duplicate_content_length_is_rejected_even_when_equal_test() -> Nil {
  let result =
    parse(<<
      "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n":utf8,
    >>)

  assert result == Error(http1.DuplicateContentLength)
}

pub fn incomplete_head_cannot_grow_past_its_cumulative_limit_test() -> Nil {
  let assert Ok(parser) = http1.request_parser(http1.Limits(32, 8, 24))
  let assert Ok(http1.NeedMore(parser)) =
    http1.feed_request(parser, <<"GET / HTTP/1.1\r\nHost":utf8>>)

  assert http1.feed_request(parser, <<": example.test":utf8>>)
    == Error(http1.HeadTooLarge(32))
}

pub fn a_complete_small_head_does_not_charge_coalesced_body_bytes_test() -> Nil {
  let assert Ok(parser) = http1.request_parser(http1.Limits(64, 8, 32))
  let assert Ok(http1.RequestReady(_, body)) =
    http1.feed_request(parser, <<
      "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 80\r\n\r\n01234567890123456789012345678901234567890123456789012345678901234567890123456789":utf8,
    >>)

  assert body
    == <<
      "01234567890123456789012345678901234567890123456789012345678901234567890123456789":utf8,
    >>
}

pub fn chunked_transfer_coding_is_recognised_case_insensitively_test() -> Nil {
  let assert Ok(http1.RequestReady(head, <<>>)) =
    parse(<<
      "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: ChUnKeD\r\n\r\n":utf8,
    >>)
  let http1.RequestHead(_, _, _, framing) = head

  assert framing == http1.Chunked
}

pub fn unsupported_transfer_coding_is_rejected_test() -> Nil {
  let result =
    parse(<<
      "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip\r\n\r\n":utf8,
    >>)

  assert result == Error(http1.InvalidTransferEncoding)
}

pub fn non_decimal_content_length_is_rejected_test() -> Nil {
  let result =
    parse(<<
      "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: +5\r\n\r\n":utf8,
    >>)

  assert result == Error(http1.InvalidContentLength)
}

pub fn missing_or_duplicate_host_is_rejected_test() -> Nil {
  assert parse(<<"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n":utf8>>)
    == Error(http1.MissingHost)
  assert parse(<<
      "GET / HTTP/1.1\r\nHost: first.test\r\nHost: second.test\r\n\r\n":utf8,
    >>)
    == Error(http1.DuplicateHost)
}

pub fn ambiguous_or_malformed_host_authorities_are_rejected_test() -> Nil {
  assert parse(<<
      "GET / HTTP/1.1\r\nHost: example.test,other.test\r\n\r\n":utf8,
    >>)
    == Error(http1.InvalidHost)
  assert parse(<<"GET / HTTP/1.1\r\nHost: user@example.test\r\n\r\n":utf8>>)
    == Error(http1.InvalidHost)
  assert parse(<<"GET / HTTP/1.1\r\nHost: example.test:99999\r\n\r\n":utf8>>)
    == Error(http1.InvalidHost)
  assert parse(<<"GET / HTTP/1.1\r\nHost: [::1\r\n\r\n":utf8>>)
    == Error(http1.InvalidHost)
}

pub fn bracketed_ipv6_host_with_a_finite_port_is_accepted_test() -> Nil {
  let assert Ok(http1.RequestReady(head, <<>>)) =
    parse(<<"GET / HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n":utf8>>)
  let http1.RequestHead(_, _, headers, _) = head

  assert headers == [http1.Header(<<"Host":utf8>>, <<"[::1]:8443":utf8>>)]
}

pub fn bare_line_feed_is_rejected_before_the_buffer_limit_test() -> Nil {
  let result = parse(<<"GET / HTTP/1.1\nHost: example.test\n\n":utf8>>)

  assert result == Error(http1.InvalidLineEnding)
}

pub fn header_count_limit_is_enforced_test() -> Nil {
  let assert Ok(parser) = http1.request_parser(http1.Limits(1024, 1, 256))
  let result =
    http1.feed_request(parser, <<
      "GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: yes\r\n\r\n":utf8,
    >>)

  assert result == Error(http1.TooManyHeaders(1))
}

pub fn line_limit_is_enforced_on_complete_and_partial_lines_test() -> Nil {
  let assert Ok(complete) = http1.request_parser(http1.Limits(1024, 8, 16))
  assert http1.feed_request(complete, <<
      "GET /too-long HTTP/1.1\r\nHost: a\r\n\r\n":utf8,
    >>)
    == Error(http1.LineTooLong(16))

  let assert Ok(partial) = http1.request_parser(http1.Limits(1024, 8, 16))
  assert http1.feed_request(partial, <<"GET /too-long HTTP/1":utf8>>)
    == Error(http1.LineTooLong(16))
}

pub fn invalid_parser_limits_and_non_byte_input_are_typed_test() -> Nil {
  assert http1.request_parser(http1.Limits(0, 8, 8))
    == Error(http1.InvalidLimit)
  let assert Ok(parser) = http1.request_parser(http1.Limits(64, 8, 32))
  assert http1.feed_request(parser, <<1:1>>) == Error(http1.NonByteAligned)
}

pub fn control_bytes_in_header_values_are_rejected_test() -> Nil {
  let result =
    parse(<<
      "GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: ":utf8,
      0,
      "\r\n\r\n":utf8,
    >>)

  assert result == Error(http1.InvalidHeaderValue)
}

fn parse(bytes: BitArray) -> Result(http1.RequestOutcome, http1.Error) {
  let assert Ok(parser) = http1.request_parser(http1.Limits(1024, 16, 256))
  http1.feed_request(parser, bytes)
}
