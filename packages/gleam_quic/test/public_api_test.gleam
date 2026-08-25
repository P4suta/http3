import gleam_quic
import gleam_quic/client
import gleam_quic/config
import gleam_quic/failure
import gleam_quic/server
import gleeunit/should

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn finite_defaults_and_validated_updates_test() -> Nil {
  let deadlines = config.default_deadlines()
  let limits = config.default_limits()

  assert config.deadline(deadlines, failure.Dns) == 5000
  assert config.deadline(deadlines, failure.Handshake) == 10_000
  assert config.deadline(deadlines, failure.Total) == 30_000
  assert config.limit(limits, failure.Buffer) == 262_144
  assert config.limit(limits, failure.Connections) == 1024
  assert config.limit(limits, failure.Queue) == 1024

  assert config.with_deadline(deadlines, failure.Operation, 0)
    == Error(config.InvalidDeadline(failure.Operation, 0))
  assert config.uniform_deadlines(3_600_001)
    == Error(config.InvalidDeadline(failure.Total, 3_600_001))
  assert config.with_limit(limits, failure.Datagram, 0)
    == Error(config.InvalidLimit(failure.Datagram, 0))

  let updated_deadlines =
    config.with_deadline(deadlines, failure.Operation, 2500) |> should.be_ok
  let uniform = config.uniform_deadlines(1200) |> should.be_ok
  let updated_limits =
    config.with_limit(limits, failure.Queue, 64) |> should.be_ok
  assert config.deadline(updated_deadlines, failure.Operation) == 2500
  assert config.deadline(uniform, failure.Drain) == 1200
  assert config.limit(updated_limits, failure.Queue) == 64
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_configuration_rejects_ambiguous_inputs_test() -> Nil {
  assert client.new("", 443, "sample") == Error(client.InvalidHost)
  assert client.new("localhost", 0, "sample") == Error(client.InvalidPort(0))
  assert client.new("localhost", 65_536, "sample")
    == Error(client.InvalidPort(65_536))
  assert client.new("localhost", 443, "")
    == Error(client.InvalidApplicationProtocol)

  let configured = client.new("localhost", 443, "sample") |> should.be_ok
  let client_certificate = fixture("client.pem") |> should.be_ok
  let client_private_key = fixture("client-key.pem") |> should.be_ok
  let server_certificate = fixture("server.pem") |> should.be_ok
  let server_private_key = fixture("server-key.pem") |> should.be_ok
  assert client.with_application_protocols(configured, [])
    == Error(client.InvalidApplicationProtocol)
  assert client.with_application_protocols(configured, ["sample", "sample"])
    == Error(client.InvalidApplicationProtocol)
  assert client.ticket_storage_key(<<0:size(248)>>)
    == Error(client.InvalidTicketStorageKey)
  let _credential =
    client.with_client_certificate(
      configured,
      client_certificate,
      client_private_key,
    )
    |> should.be_ok
  assert client.with_client_certificate(
      configured,
      client_certificate,
      server_private_key,
    )
    == Error(client.IncompatibleClientPrivateKey)
  assert client.with_client_certificate(
      configured,
      server_certificate,
      server_private_key,
    )
    == Error(client.InvalidClientCertificate)
  assert client.with_client_certificate(
      configured,
      <<"not pem">>,
      client_private_key,
    )
    == Error(client.InvalidClientCertificate)

  let deadlines = config.uniform_deadlines(1000) |> should.be_ok
  let limits =
    config.default_limits()
    |> config.with_limit(failure.Queue, 8)
    |> should.be_ok
  let _configured =
    configured
    |> client.with_address_family(gleam_quic.Ipv4)
    |> client.with_deadlines(deadlines)
    |> client.with_limits(limits)
    |> client.with_version(gleam_quic.QuicV2)
    |> client.with_congestion_control(gleam_quic.Cubic)
    |> client.with_zero_rtt
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_configuration_validates_credentials_and_keys_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let configured =
    server.new(certificate, private_key, "sample") |> should.be_ok
  let client_certificate = fixture("client.pem") |> should.be_ok

  assert server.with_port(configured, -1) == Error(server.InvalidPort(-1))
  assert server.with_application_protocols(configured, [])
    == Error(server.InvalidApplicationProtocol)
  assert server.operational_key(<<0:size(248)>>)
    == Error(server.InvalidOperationalKey)
  assert server.replay_guard(0, fn(_, _) { Ok(True) })
    == Error(server.InvalidReplayGuardTimeout)
  assert server.client_certificate_authorities(<<"not pem">>)
    == Error(server.InvalidClientCaCertificate)
  assert server.new(client_certificate, private_key, "sample")
    == Error(server.IncompatiblePrivateKey)

  let first_key = server.operational_key(<<1:size(256)>>) |> should.be_ok
  let second_key = server.operational_key(<<2:size(256)>>) |> should.be_ok
  let address_key = server.operational_key(<<3:size(256)>>) |> should.be_ok
  let reset_key = server.operational_key(<<4:size(256)>>) |> should.be_ok
  let ring = server.key_ring(first_key)
  assert server.rotate_key_ring(ring, first_key)
    == Error(server.DuplicateOperationalKey)
  let rotated = server.rotate_key_ring(ring, second_key) |> should.be_ok
  let address_keys = server.key_ring(address_key)
  let reset_keys = server.key_ring(reset_key)
  assert server.operational_keys(
      ticket: rotated,
      address_token: address_keys,
      stateless_reset: rotated,
    )
    == Error(server.DuplicateOperationalKey)
  let operational_keys =
    server.operational_keys(
      ticket: rotated,
      address_token: address_keys,
      stateless_reset: reset_keys,
    )
    |> should.be_ok
  let guard = server.replay_guard(100, fn(_, _) { Ok(True) }) |> should.be_ok
  let deadlines = config.uniform_deadlines(1000) |> should.be_ok
  let limits = config.default_limits()
  let _configured =
    configured
    |> server.with_address_family(gleam_quic.Ipv4)
    |> server.with_deadlines(deadlines)
    |> server.with_limits(limits)
    |> server.with_congestion_control(gleam_quic.Cubic)
    |> server.with_external_zero_rtt(guard)
    |> server.with_operational_keys(operational_keys)
  Nil
}
