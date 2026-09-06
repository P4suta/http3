import gleeunit
import http/internal/http2/preface
import http/internal/http2/settings

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn client_magic_is_the_exact_rfc_connection_preface_test() -> Nil {
  assert preface.client_magic() == <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":utf8>>
}

pub fn server_preface_is_checked_incrementally_and_returns_extra_bytes_test() -> Nil {
  let decoder = preface.server_decoder()
  let assert Ok(preface.NeedMore(decoder)) =
    preface.feed(decoder, <<"PRI * HTTP/2":utf8>>)
  let assert Ok(preface.Ready(<<1, 2, 3>>)) =
    preface.feed(decoder, <<".0\r\n\r\nSM\r\n\r\n":utf8, 1, 2, 3>>)
  Nil
}

pub fn malformed_or_non_aligned_preface_is_rejected_early_test() -> Nil {
  let decoder = preface.server_decoder()
  assert preface.feed(decoder, <<"X":utf8>>) == Error(preface.InvalidPreface)
  assert preface.feed(decoder, <<1:size(1)>>) == Error(preface.NonByteAligned)
}

pub fn initial_client_and_server_bytes_contain_validated_settings_test() -> Nil {
  let values = [
    settings.EnablePush(False),
    settings.MaxConcurrentStreams(100),
  ]
  let assert Ok(client) = preface.client_initial_bytes(values, 16_384)
  let assert Ok(server) = preface.server_initial_bytes(values, 16_384)
  let magic = preface.client_magic()
  assert client == <<magic:bits, server:bits>>
  assert server
    == <<
      0,
      0,
      12,
      4,
      0,
      0,
      0,
      0,
      0,
      0,
      2,
      0,
      0,
      0,
      0,
      0,
      3,
      0,
      0,
      0,
      100,
    >>
}
