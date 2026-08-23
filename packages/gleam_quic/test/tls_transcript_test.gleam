import gleam_quic/internal/crypto
import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/handshake
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/transcript

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn appends_only_complete_bounded_handshake_messages_test() -> Nil {
  let assert Ok(initial) = transcript.new(crypto.Sha256, 16)
  let assert Ok(client_hello) =
    handshake.encode(handshake.Message(handshake.ClientHello, <<"one">>), 12)
  let assert Ok(updated) = transcript.append(initial, client_hello)
  let assert Ok(expected_hash) = crypto.hash(crypto.Sha256, client_hello)
  assert transcript.bytes(updated) == client_hello
  assert transcript.hash(updated) == Ok(expected_hash)

  assert transcript.append(updated, <<1, 0, 0>>) == Error(transcript.Truncated)
  let assert Ok(too_large) =
    handshake.encode(handshake.Message(handshake.ServerHello, <<0:64>>), 12)
  assert transcript.append(updated, too_large)
    == Error(transcript.TranscriptTooLarge(19))
  let assert Ok(forbidden) =
    handshake.encode(handshake.Message(handshake.KeyUpdate, <<0>>), 12)
  assert transcript.append(initial, forbidden)
    == Error(transcript.ForbiddenInQuic(handshake.KeyUpdate))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn replaces_first_client_hello_for_retry_test() -> Nil {
  let assert Ok(initial) = transcript.new(crypto.Sha256, 1024)
  let assert Ok(client_hello) =
    handshake.encode(handshake.Message(handshake.ClientHello, <<"first">>), 32)
  let assert Ok(after_client) = transcript.append(initial, client_hello)
  let assert Ok(retry_body) =
    hello.encode_server(
      hello.HelloRetryRequest(<<>>, hello.Aes128GcmSha256, [
        extension.Extension(extension.SupportedVersions, <<3, 4>>),
        extension.Extension(extension.KeyShare, <<0, 29>>),
      ]),
      hello.default_limits(),
    )
  let assert Ok(retry) =
    handshake.encode(handshake.Message(handshake.ServerHello, retry_body), 512)
  let assert Ok(replaced) =
    transcript.replace_for_hello_retry_request(after_client, retry)
  let assert Ok(client_hash) = crypto.hash(crypto.Sha256, client_hello)

  assert transcript.bytes(replaced)
    == <<254, 0, 0, 32, client_hash:bits, retry:bits>>
  assert transcript.replace_for_hello_retry_request(replaced, retry)
    == Error(transcript.InvalidHelloRetryRequest)
}
