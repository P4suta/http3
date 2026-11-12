import gleam/bit_array
import gleam/list
import quic_core/internal/connection_state
import quic_core/internal/driver
import quic_core/internal/qlog
import quic_core/internal/runtime/connection_worker_diagnostic_code as diagnostic_code
import quic_core/internal/runtime/server_transport
import quic_core/internal/tls/authentication
import quic_core/internal/tls/engine
import quic_core/internal/tls/extension_value
import quic_core/internal/wire_packet

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

@external(erlang, "qlog_test_ffi", "with_directory")
fn with_directory(run: fn(String) -> value) -> value

@external(erlang, "qlog_test_ffi", "file_contains")
fn file_contains(directory: String, text: String) -> Bool

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn failure_codes_are_stable_finite_and_payload_free_test() -> Nil {
  assert diagnostic_code.operation(diagnostic_code.ReceiveDatagram) == 3004

  assert diagnostic_code.server_transport_error(
      server_transport.DriverFailure(
        driver.ConnectionFailure(connection_state.TlsFailure(
          engine.UnexpectedMessage,
        )),
      ),
    )
    == [3103, 3205, 3330, 3403]

  assert diagnostic_code.server_transport_error(
      server_transport.DriverFailure(
        driver.ConnectionFailure(connection_state.WirePacketFailure(
          wire_packet.AuthenticationFailed,
        )),
      ),
    )
    == [3103, 3205, 3322]

  assert diagnostic_code.server_transport_error(
      server_transport.DriverFailure(
        driver.ConnectionFailure(connection_state.ProtocolViolation(
          connection_state.ReservedBitsViolation,
        )),
      ),
    )
    == [3103, 3205, 3313, 3729]

  assert diagnostic_code.server_transport_error(
      server_transport.DriverFailure(
        driver.ConnectionFailure(connection_state.ProtocolViolation(
          connection_state.NewTokenAtServer,
        )),
      ),
    )
    == [3103, 3205, 3313, 3732]

  assert diagnostic_code.server_transport_error(
      server_transport.DriverFailure(
        driver.ConnectionFailure(connection_state.FrameAtWrongEncryptionLevel(
          engine.Handshake,
          connection_state.DatagramFrame,
        )),
      ),
    )
    == [3103, 3205, 3331, 3502, 3622]

  assert diagnostic_code.server_transport_error(server_transport.DriverFailure(
      driver.DestinationConnectionIdMismatch,
    ))
    == [3103, 3202]

  assert diagnostic_code.server_transport_error(server_transport.InvalidInput)
    == [3101]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn authentication_subcauses_preserve_existing_failure_chain_test() -> Nil {
  // The codes are a compatibility contract for retained traces.
  // A new cause must append a distinct code, without changing the existing TLS class.
  let cases = [
    #(authentication.NonByteAligned, 3801),
    #(authentication.InvalidInput, 3802),
    #(authentication.InvalidPem, 3803),
    #(authentication.EmptyCertificateChain, 3804),
    #(authentication.UntrustedCertificate, 3805),
    #(authentication.IdentityMismatch, 3806),
    #(authentication.InvalidSignature, 3807),
    #(authentication.IncompatibleSignatureScheme, 3808),
    #(authentication.InvalidCertificatePurpose, 3809),
    #(authentication.RuntimeUnavailable, 3810),
  ]
  list.each(cases, fn(pair) {
    let #(cause, expected) = pair
    assert authentication_codes(cause) == [3103, 3205, 3330, 3423, expected]
    assert diagnostic_code.server_transport_error(
        server_transport.TlsFailure(engine.AuthenticationFailure(cause)),
      )
      == [3102, 3423, expected]
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn real_authentication_failures_emit_only_fixed_qlog_causes_test() -> Nil {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(server_pem) = fixture("server.pem")
  let assert Ok(key_pem) = fixture("server-key.pem")
  let assert Ok(trust) = authentication.trust_store_from_pem(ca_pem)
  let assert Ok(chain) = authentication.certificate_chain_from_pem(server_pem)
  let assert Ok(key) = authentication.signing_key_from_pem(key_pem)
  let assert Ok(peer) =
    authentication.validate_server_certificate(chain, trust, "localhost")
  let content = <<"private-authentication-exception-marker">>
  let assert Error(scheme) =
    authentication.sign(key, extension_value.RsaPssRsaeSha256, content)
  let assert Ok(signature) =
    authentication.sign(key, extension_value.Ed25519, content)
  let assert Error(signing) =
    authentication.verify(
      peer,
      extension_value.Ed25519,
      <<content:bits, 0>>,
      signature,
    )
  let assert Ok(wrong_trust) = authentication.trust_store_from_pem(server_pem)
  let assert Ok(ca_chain) = authentication.certificate_chain_from_pem(ca_pem)
  let assert Error(certificate) =
    authentication.validate_server_certificate(
      ca_chain,
      wrong_trust,
      "localhost",
    )
  let assert Error(pem) = authentication.signing_key_from_pem(content)
  let causes = [scheme, signing, certificate, pem]
  assert causes
    == [
      authentication.IncompatibleSignatureScheme,
      authentication.InvalidSignature,
      authentication.UntrustedCertificate,
      authentication.InvalidPem,
    ]
  with_directory(fn(directory) {
    let assert Ok(writer) = qlog.open(directory, qlog.Server, 1000, 64)
    list.each(causes, fn(cause) {
      list.each(authentication_codes(cause), fn(code) {
        qlog.application_error(writer, 1000, code)
      })
    })
    assert qlog.close(writer) == Ok(Nil)
    assert file_contains(directory, "\"code\":3423")
    assert file_contains(directory, "\"code\":3808")
    assert file_contains(directory, "\"code\":3807")
    assert file_contains(directory, "\"code\":3805")
    assert file_contains(directory, "\"code\":3803")
    assert !file_contains(directory, "BEGIN CERTIFICATE")
    assert !file_contains(directory, "PRIVATE KEY")
    assert !file_contains(directory, "private-authentication-exception-marker")
    assert !file_contains(directory, bit_array.base64_encode(signature, True))
    assert !file_contains(directory, bit_array.base16_encode(signature))
    assert !file_contains(directory, bit_array.base64_encode(server_pem, True))
    assert !file_contains(directory, "badarg")
    assert !file_contains(directory, "stacktrace")
  })
}

fn authentication_codes(cause: authentication.Error) -> List(Int) {
  diagnostic_code.server_transport_error(
    server_transport.DriverFailure(
      driver.ConnectionFailure(
        connection_state.TlsFailure(engine.AuthenticationFailure(cause)),
      ),
    ),
  )
}
