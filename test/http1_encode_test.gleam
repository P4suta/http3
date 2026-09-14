import gleeunit
import http/internal/http1
import http/internal/http1/encode

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn request_head_preserves_unknown_method_and_headers_and_adds_length_test() -> Nil {
  let assert Ok(bytes) =
    encode.request(
      <<"QUERY":utf8>>,
      <<"/items?tag=a":utf8>>,
      [
        http1.Header(<<"Host":utf8>>, <<"example.test":utf8>>),
        http1.Header(<<"X-Custom":utf8>>, <<"one  two":utf8>>),
      ],
      http1.ContentLength(4),
      limits(),
    )

  assert bytes
    == <<
      "QUERY /items?tag=a HTTP/1.1\r\nHost: example.test\r\nX-Custom: one  two\r\nContent-Length: 4\r\n\r\n":utf8,
    >>
}

pub fn request_requires_exactly_one_host_test() -> Nil {
  assert encode.request(
      <<"GET":utf8>>,
      <<"/":utf8>>,
      [],
      http1.NoBody,
      limits(),
    )
    == Error(encode.MissingHost)
  assert encode.request(
      <<"GET":utf8>>,
      <<"/":utf8>>,
      [
        http1.Header(<<"Host":utf8>>, <<"one.test":utf8>>),
        http1.Header(<<"host":utf8>>, <<"two.test":utf8>>),
      ],
      http1.NoBody,
      limits(),
    )
    == Error(encode.DuplicateHost)
}

pub fn caller_cannot_supply_message_length_headers_test() -> Nil {
  assert encode.request(
      <<"POST":utf8>>,
      <<"/":utf8>>,
      [
        http1.Header(<<"Host":utf8>>, <<"example.test":utf8>>),
        http1.Header(<<"Content-Length":utf8>>, <<"4":utf8>>),
      ],
      http1.ContentLength(4),
      limits(),
    )
    == Error(encode.ReservedFramingHeader)
  assert encode.response(
      200,
      <<"OK":utf8>>,
      [http1.Header(<<"Transfer-Encoding":utf8>>, <<"chunked":utf8>>)],
      http1.Chunked,
      limits(),
    )
    == Error(encode.ReservedFramingHeader)
}

pub fn response_head_adds_chunked_framing_without_requiring_host_test() -> Nil {
  let assert Ok(bytes) =
    encode.response(
      200,
      <<"All Good":utf8>>,
      [http1.Header(<<"X-Test":utf8>>, <<"yes":utf8>>)],
      http1.Chunked,
      limits(),
    )

  assert bytes
    == <<
      "HTTP/1.1 200 All Good\r\nX-Test: yes\r\nTransfer-Encoding: chunked\r\n\r\n":utf8,
    >>
}

pub fn head_injection_and_invalid_tokens_are_rejected_test() -> Nil {
  let host = http1.Header(<<"Host":utf8>>, <<"example.test":utf8>>)
  assert encode.request(
      <<"bad method":utf8>>,
      <<"/":utf8>>,
      [host],
      http1.NoBody,
      limits(),
    )
    == Error(encode.InvalidMethod)
  assert encode.request(
      <<"GET":utf8>>,
      <<"/fragment#bad":utf8>>,
      [host],
      http1.NoBody,
      limits(),
    )
    == Error(encode.InvalidTarget)
  assert encode.response(
      200,
      <<"OK\r\nInjected: yes":utf8>>,
      [],
      http1.NoBody,
      limits(),
    )
    == Error(encode.InvalidReason)
  assert encode.response(
      200,
      <<"OK":utf8>>,
      [http1.Header(<<"X-Test":utf8>>, <<"yes\r\nInjected: yes":utf8>>)],
      http1.NoBody,
      limits(),
    )
    == Error(encode.InvalidHeaderValue)
}

pub fn output_head_count_line_and_total_limits_are_enforced_test() -> Nil {
  let host = http1.Header(<<"Host":utf8>>, <<"example.test":utf8>>)
  assert encode.request(
      <<"GET":utf8>>,
      <<"/":utf8>>,
      [host],
      http1.NoBody,
      http1.Limits(32, 8, 24),
    )
    == Error(encode.HeadTooLarge(32))
  assert encode.request(
      <<"GET":utf8>>,
      <<"/":utf8>>,
      [host],
      http1.NoBody,
      http1.Limits(1024, 8, 8),
    )
    == Error(encode.LineTooLong(8))
  assert encode.response(
      200,
      <<"OK":utf8>>,
      [
        http1.Header(<<"X-One":utf8>>, <<"1":utf8>>),
        http1.Header(<<"X-Two":utf8>>, <<"2":utf8>>),
      ],
      http1.NoBody,
      http1.Limits(1024, 1, 256),
    )
    == Error(encode.TooManyHeaders(1))
}

pub fn unsupported_outgoing_framing_and_status_are_rejected_test() -> Nil {
  let host = [http1.Header(<<"Host":utf8>>, <<"example.test":utf8>>)]
  assert encode.request(
      <<"GET":utf8>>,
      <<"/":utf8>>,
      host,
      http1.CloseDelimited,
      limits(),
    )
    == Error(encode.InvalidFraming)
  assert encode.response(99, <<"No":utf8>>, [], http1.NoBody, limits())
    == Error(encode.InvalidStatus)
}

pub fn chunks_and_final_trailers_are_encoded_without_ambiguity_test() -> Nil {
  assert encode.chunk(<<"Wiki":utf8>>) == Ok(<<"4\r\nWiki\r\n":utf8>>)
  assert encode.final_chunk(
      [http1.Header(<<"Digest":utf8>>, <<"ok":utf8>>)],
      limits(),
    )
    == Ok(<<"0\r\nDigest: ok\r\n\r\n":utf8>>)

  assert encode.chunk(<<>>) == Error(encode.EmptyChunk)
  assert encode.chunk(<<1:1>>) == Error(encode.NonByteAligned)
  assert encode.final_chunk(
      [http1.Header(<<"Content-Length":utf8>>, <<"1":utf8>>)],
      limits(),
    )
    == Error(encode.ForbiddenTrailer)
}

fn limits() -> http1.Limits {
  http1.Limits(4096, 32, 1024)
}
