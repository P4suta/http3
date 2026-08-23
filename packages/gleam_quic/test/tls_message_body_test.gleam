import gleam_quic/internal/crypto
import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/message_body

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_encrypted_extensions_and_certificates_test() -> Nil {
  let encrypted_extensions = [
    extension.Extension(extension.ApplicationLayerProtocolNegotiation, <<
      0,
      3,
      2,
      "h3",
    >>),
    extension.Extension(extension.QuicTransportParameters, <<1, 1, 0>>),
  ]
  let limits = message_body.default_limits()
  let assert Ok(encoded_extensions) =
    message_body.encode_encrypted_extensions(encrypted_extensions, limits)
  assert message_body.decode_encrypted_extensions(encoded_extensions, limits)
    == Ok(encrypted_extensions)

  let certificate =
    message_body.CertificateMessage(request_context: <<>>, entries: [
      message_body.CertificateEntry(
        certificate_der: <<0x30, 3, 1, 2, 3>>,
        extensions: [],
      ),
      message_body.CertificateEntry(
        certificate_der: <<0x30, 1, 9>>,
        extensions: [
          extension.Extension(extension.StatusRequest, <<1, 0>>),
        ],
      ),
    ])
  let assert Ok(encoded_certificate) =
    message_body.encode_certificate(certificate, limits)
  assert message_body.decode_certificate(encoded_certificate, limits)
    == Ok(certificate)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_authentication_and_ticket_messages_test() -> Nil {
  let limits = message_body.default_limits()
  let request =
    message_body.CertificateRequest(<<1, 2>>, [
      extension.Extension(extension.SignatureAlgorithms, <<0, 2, 8, 7>>),
    ])
  let assert Ok(encoded_request) =
    message_body.encode_certificate_request(request, limits)
  assert message_body.decode_certificate_request(encoded_request, limits)
    == Ok(request)

  let verify =
    message_body.CertificateVerify(extension_value.Ed25519, <<1, 2, 3, 4>>)
  let assert Ok(encoded_verify) =
    message_body.encode_certificate_verify(verify, limits)
  assert message_body.decode_certificate_verify(encoded_verify, limits)
    == Ok(verify)

  assert message_body.encode_finished(crypto.Sha256, <<1:256>>) == Ok(<<1:256>>)
  assert message_body.decode_finished(crypto.Sha256, <<1:256>>) == Ok(<<1:256>>)

  let ticket =
    message_body.NewSessionTicket(
      ticket_lifetime: 86_400,
      ticket_age_add: 0xf00d_cafe,
      ticket_nonce: <<1, 2>>,
      ticket: <<3, 4, 5>>,
      extensions: [extension.Extension(extension.EarlyData, <<0, 0, 4, 0>>)],
    )
  let assert Ok(encoded_ticket) =
    message_body.encode_new_session_ticket(ticket, limits)
  assert message_body.decode_new_session_ticket(encoded_ticket, limits)
    == Ok(ticket)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn constructs_certificate_verify_context_and_rejects_bad_lengths_test() -> Nil {
  let transcript_hash = <<1:256>>
  let server_content =
    message_body.certificate_verify_content(
      message_body.Server,
      transcript_hash,
    )
  assert server_content
    == <<
      "                                                                ",
      "TLS 1.3, server CertificateVerify",
      0,
      transcript_hash:bits,
    >>

  let limits = message_body.default_limits()
  assert message_body.decode_certificate(<<0, 0, 0, 1, 0>>, limits)
    == Error(message_body.Truncated)
  assert message_body.decode_certificate_verify(<<8, 7, 0, 0>>, limits)
    == Error(message_body.EmptySignature)
  assert message_body.decode_finished(crypto.Sha384, <<0:256>>)
    == Error(message_body.InvalidFinishedLength(32))
  assert message_body.encode_new_session_ticket(
      message_body.NewSessionTicket(604_801, 0, <<>>, <<1>>, []),
      limits,
    )
    == Error(message_body.InvalidTicketLifetime)
}
