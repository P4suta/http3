import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/hello

const random = <<
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
>>

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_tls13_client_hello_body_test() -> Nil {
  let client =
    hello.ClientHello(
      random,
      <<1, 2, 3, 4>>,
      [
        hello.Aes128GcmSha256,
        hello.Aes256GcmSha384,
        hello.Chacha20Poly1305Sha256,
        hello.UnknownCipherSuite(0xaaaa),
      ],
      [
        extension.Extension(extension.SupportedVersions, <<2, 3, 4>>),
        extension.Extension(extension.QuicTransportParameters, <<1, 0>>),
      ],
    )
  let limits = hello.default_limits()
  let assert Ok(encoded) = hello.encode_client(client, limits)
  assert hello.decode_client(encoded, limits) == Ok(client)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_server_hello_and_retry_request_bodies_test() -> Nil {
  let extensions = [
    extension.Extension(extension.SupportedVersions, <<3, 4>>),
    extension.Extension(extension.KeyShare, <<0, 29>>),
  ]
  let server =
    hello.ServerHello(random, <<1, 2>>, hello.Aes128GcmSha256, extensions)
  let retry =
    hello.HelloRetryRequest(<<1, 2>>, hello.Aes128GcmSha256, extensions)
  let limits = hello.default_limits()
  let assert Ok(encoded_server) = hello.encode_server(server, limits)
  let assert Ok(encoded_retry) = hello.encode_server(retry, limits)
  assert hello.decode_server(encoded_server, limits) == Ok(server)
  assert hello.decode_server(encoded_retry, limits) == Ok(retry)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_malformed_tls_hello_bodies_test() -> Nil {
  let limits = hello.default_limits()
  assert hello.decode_client(<<1:size(1)>>, limits)
    == Error(hello.NonByteAligned)
  assert hello.decode_client(<<3, 2, 0:256, 0>>, limits)
    == Error(hello.InvalidLegacyVersion(0x0302))
  assert hello.decode_client(
      <<3, 3, random:bits, 0, 0, 1, 0, 0, 1, 0, 0>>,
      limits,
    )
    == Error(hello.InvalidCipherSuites)
  assert hello.decode_client(
      <<3, 3, random:bits, 0, 0, 2, 0x13, 0x01, 1, 1, 0, 0>>,
      limits,
    )
    == Error(hello.InvalidCompression)
  assert hello.decode_server(<<3, 3, random:bits, 33, 0:264>>, limits)
    == Error(hello.InvalidSessionId(33))
  assert hello.decode_server(
      <<3, 3, random:bits, 0, 0x13, 0x01, 0, 0, 4, 0, 43, 0>>,
      limits,
    )
    == Error(hello.Truncated)
  assert hello.decode_server(
      <<3, 3, random:bits, 0, 0x13, 0x01, 0, 0, 3, 0, 43, 0>>,
      limits,
    )
    == Error(hello.ExtensionFailure(extension.Truncated))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_invalid_tls_hello_encoding_test() -> Nil {
  let limits = hello.default_limits()
  assert hello.encode_client(
      hello.ClientHello(<<0:248>>, <<>>, [hello.Aes128GcmSha256], []),
      limits,
    )
    == Error(hello.InvalidRandom)
  assert hello.encode_client(
      hello.ClientHello(random, <<0:264>>, [hello.Aes128GcmSha256], []),
      limits,
    )
    == Error(hello.InvalidSessionId(33))
  assert hello.encode_client(hello.ClientHello(random, <<>>, [], []), limits)
    == Error(hello.InvalidCipherSuites)
  assert hello.encode_server(
      hello.ServerHello(random, <<>>, hello.UnknownCipherSuite(0x1301), []),
      limits,
    )
    == Error(hello.InvalidCipherSuites)
}
