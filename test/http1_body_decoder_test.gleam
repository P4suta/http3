import gleeunit
import http/internal/http1
import http/internal/http1/body as http1_body

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn content_length_streams_and_returns_next_message_bytes_test() -> Nil {
  let assert Ok(decoder) = decoder(http1.ContentLength(5))
  let assert Ok(http1_body.BodyData(<<"he":utf8>>, decoder)) =
    http1_body.feed(decoder, <<"he":utf8>>)
  let assert Ok(http1_body.BodyComplete(data, [], remaining)) =
    http1_body.feed(decoder, <<"lloNEXT":utf8>>)

  assert data == <<"llo":utf8>>
  assert remaining == <<"NEXT":utf8>>
}

pub fn fixed_length_requires_all_declared_bytes_before_eof_test() -> Nil {
  let assert Ok(decoder) = decoder(http1.ContentLength(3))
  let assert Ok(http1_body.BodyData(_, decoder)) =
    http1_body.feed(decoder, <<"ab":utf8>>)

  assert http1_body.finish(decoder) == Error(http1_body.UnexpectedEndOfBody)
}

pub fn no_body_preserves_every_input_byte_test() -> Nil {
  let assert Ok(decoder) = decoder(http1.NoBody)

  assert http1_body.feed(decoder, <<"NEXT":utf8>>)
    == Ok(http1_body.BodyComplete(<<>>, [], <<"NEXT":utf8>>))
}

pub fn close_delimited_stream_completes_only_at_eof_test() -> Nil {
  let assert Ok(decoder) = decoder(http1.CloseDelimited)
  let assert Ok(http1_body.BodyData(<<"one":utf8>>, decoder)) =
    http1_body.feed(decoder, <<"one":utf8>>)
  let assert Ok(http1_body.BodyData(<<"two":utf8>>, decoder)) =
    http1_body.feed(decoder, <<"two":utf8>>)

  assert http1_body.finish(decoder)
    == Ok(http1_body.BodyComplete(<<>>, [], <<>>))
}

pub fn chunked_body_is_incremental_and_preserves_trailers_and_remainder_test() -> Nil {
  let assert Ok(decoder) = decoder(http1.Chunked)
  let assert Ok(http1_body.BodyNeedMore(decoder)) =
    http1_body.feed(decoder, <<"4;name=value\r":utf8>>)
  let assert Ok(http1_body.BodyComplete(data, trailers, remaining)) =
    http1_body.feed(decoder, <<
      "\nWiki\r\n5\r\npedia\r\n0\r\nDigest: ok\r\n\r\nNEXT":utf8,
    >>)

  assert data == <<"Wikipedia":utf8>>
  assert trailers == [http1.Header(<<"Digest":utf8>>, <<"ok":utf8>>)]
  assert remaining == <<"NEXT":utf8>>
}

pub fn chunked_body_emits_available_data_before_waiting_for_more_test() -> Nil {
  let assert Ok(decoder) = decoder(http1.Chunked)
  let assert Ok(http1_body.BodyData(<<"Wi":utf8>>, decoder)) =
    http1_body.feed(decoder, <<"4\r\nWi":utf8>>)
  let assert Ok(http1_body.BodyComplete(<<"ki":utf8>>, [], <<"next":utf8>>)) =
    http1_body.feed(decoder, <<"ki\r\n0\r\n\r\nnext":utf8>>)
  Nil
}

pub fn malformed_chunk_size_and_terminator_are_rejected_test() -> Nil {
  let assert Ok(size_decoder) = decoder(http1.Chunked)
  assert http1_body.feed(size_decoder, <<"z\r\n":utf8>>)
    == Error(http1_body.InvalidChunkSize)

  let assert Ok(terminator_decoder) = decoder(http1.Chunked)
  assert http1_body.feed(terminator_decoder, <<"1\r\naX":utf8>>)
    == Error(http1_body.InvalidChunkTerminator)
}

pub fn chunk_extensions_accept_bws_tokens_and_escaped_quoted_strings_test() -> Nil {
  let assert Ok(decoder) = decoder(http1.Chunked)
  let assert Ok(http1_body.BodyComplete(data, [], <<>>)) =
    http1_body.feed(decoder, <<
      "3 ; flag ; note = \"a\\\";b\"\r\nabc\r\n0 ; done\r\n\r\n":utf8,
    >>)

  assert data == <<"abc":utf8>>
}

pub fn malformed_chunk_extensions_are_rejected_test() -> Nil {
  let assert Ok(missing_name) = decoder(http1.Chunked)
  assert http1_body.feed(missing_name, <<"1;=bad\r\na\r\n0\r\n\r\n":utf8>>)
    == Error(http1_body.InvalidChunkExtension)

  let assert Ok(missing_value) = decoder(http1.Chunked)
  assert http1_body.feed(missing_value, <<"1;name=\r\na\r\n0\r\n\r\n":utf8>>)
    == Error(http1_body.InvalidChunkExtension)

  let assert Ok(unterminated_quote) = decoder(http1.Chunked)
  assert http1_body.feed(unterminated_quote, <<
      "1;name=\"open\r\na\r\n0\r\n\r\n":utf8,
    >>)
    == Error(http1_body.InvalidChunkExtension)
}

pub fn declared_chunk_total_is_rejected_before_retaining_its_data_test() -> Nil {
  let assert Ok(decoder) =
    http1_body.decoder(http1.Chunked, http1_body.Limits(4, 64, 32, 4, 16))

  assert http1_body.feed(decoder, <<"5\r\n":utf8>>)
    == Error(http1_body.BodyTooLarge(4))
}

pub fn forbidden_framing_trailer_is_rejected_test() -> Nil {
  let assert Ok(decoder) = decoder(http1.Chunked)

  assert http1_body.feed(decoder, <<"0\r\nContent-Length: 1\r\n\r\n":utf8>>)
    == Error(http1_body.ForbiddenTrailer)
}

pub fn authentication_and_content_metadata_trailers_are_rejected_test() -> Nil {
  let assert Ok(authentication) = decoder(http1.Chunked)
  assert http1_body.feed(authentication, <<
      "0\r\nAuthorization: Bearer secret\r\n\r\n":utf8,
    >>)
    == Error(http1_body.ForbiddenTrailer)

  let assert Ok(content_type) = decoder(http1.Chunked)
  assert http1_body.feed(content_type, <<
      "0\r\nContent-Type: text/plain\r\n\r\n":utf8,
    >>)
    == Error(http1_body.ForbiddenTrailer)
}

pub fn trailer_limits_do_not_charge_bytes_after_the_trailer_block_test() -> Nil {
  let assert Ok(decoder) =
    http1_body.decoder(http1.Chunked, http1_body.Limits(64, 64, 24, 1, 20))
  let assert Ok(http1_body.BodyComplete(<<>>, [_], remaining)) =
    http1_body.feed(decoder, <<
      "0\r\nX: y\r\n\r\n012345678901234567890123456789":utf8,
    >>)

  assert remaining == <<"012345678901234567890123456789":utf8>>
}

pub fn partial_chunk_metadata_and_trailers_are_finitely_bounded_test() -> Nil {
  let chunk_limits = http1_body.Limits(64, 16, 16, 2, 8)
  let assert Ok(chunk_line) = http1_body.decoder(http1.Chunked, chunk_limits)
  assert http1_body.feed(chunk_line, <<"1;toolong":utf8>>)
    == Error(http1_body.LineTooLong(8))

  let trailer_limits = http1_body.Limits(64, 16, 16, 2, 16)
  let assert Ok(trailers) = http1_body.decoder(http1.Chunked, trailer_limits)
  assert http1_body.feed(trailers, <<"0\r\nX: 1234567890123":utf8>>)
    == Error(http1_body.TrailerTooLarge(16))
}

pub fn body_decoder_rejects_invalid_policy_tunnel_and_non_byte_data_test() -> Nil {
  assert http1_body.decoder(http1.NoBody, http1_body.Limits(0, 16, 16, 2, 8))
    == Error(http1_body.InvalidLimit)
  assert decoder(http1.Tunnel) == Error(http1_body.InvalidFraming)

  let assert Ok(decoder) = decoder(http1.ContentLength(1))
  assert http1_body.feed(decoder, <<1:1>>) == Error(http1_body.NonByteAligned)
}

fn decoder(
  framing: http1.Framing,
) -> Result(http1_body.Decoder, http1_body.Error) {
  http1_body.decoder(framing, http1_body.Limits(1024, 1024, 512, 8, 128))
}
