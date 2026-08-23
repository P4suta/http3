import gleam/option.{None, Some}
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/message_body
import gleam_quic/internal/tls/session_ticket

const issued_at = 1_000_000

const ticket_key = <<0x11:256>>

const resumption_master_secret = <<0x22:256>>

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn protects_and_restores_bound_resumption_ticket_test() -> Nil {
  let assert Ok(new_ticket) =
    session_ticket.issue(
      ticket_key:,
      issued_at_milliseconds: issued_at,
      lifetime_seconds: 3600,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "example.com",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: <<1, 2, 3>>,
      permit_early_data: True,
    )
  let message_body.NewSessionTicket(lifetime, _, _, opaque_ticket, extensions) =
    new_ticket
  assert lifetime == 3600
  assert extensions
    == [extension.Extension(extension.EarlyData, <<0xffff_ffff:size(32)>>)]

  let assert Ok(client_ticket) =
    session_ticket.store(
      new_ticket:,
      received_at_milliseconds: issued_at + 25,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "example.com",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: <<1, 2, 3>>,
    )
  assert session_ticket.early_data_allowed(client_ticket)
  assert session_ticket.is_usable(
    client_ticket,
    issued_at + 1000,
    "example.com",
    <<"h3">>,
    1,
  )

  let assert Ok(claims) =
    session_ticket.open(
      ticket_key:,
      opaque_ticket:,
      now_milliseconds: issued_at + 1000,
      expected_server_name: "example.com",
      expected_alpn: <<"h3">>,
      expected_quic_version: 1,
    )
  let assert Ok(obfuscated_age) =
    session_ticket.obfuscated_ticket_age(client_ticket, issued_at + 1000)
  assert session_ticket.ticket_age_is_valid(
    claims,
    obfuscated_age,
    issued_at + 1000,
    100,
  )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_tampered_expired_or_cross_origin_tickets_test() -> Nil {
  let assert Ok(new_ticket) = issue_without_early_data()
  let message_body.NewSessionTicket(_, _, _, opaque_ticket, _) = new_ticket

  assert session_ticket.open(
      ticket_key:,
      opaque_ticket: <<opaque_ticket:bits, 0>>,
      now_milliseconds: issued_at + 1,
      expected_server_name: "example.com",
      expected_alpn: <<"h3">>,
      expected_quic_version: 1,
    )
    == Error(session_ticket.InvalidTicket)
  assert session_ticket.open(
      ticket_key:,
      opaque_ticket:,
      now_milliseconds: issued_at + 1,
      expected_server_name: "other.example",
      expected_alpn: <<"h3">>,
      expected_quic_version: 1,
    )
    == Error(session_ticket.OriginMismatch)
  assert session_ticket.open(
      ticket_key:,
      opaque_ticket:,
      now_milliseconds: issued_at + 3601 * 1000,
      expected_server_name: "example.com",
      expected_alpn: <<"h3">>,
      expected_quic_version: 1,
    )
    == Error(session_ticket.Expired)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_quic_early_data_and_ticket_bounds_test() -> Nil {
  let invalid_early_data =
    message_body.NewSessionTicket(
      ticket_lifetime: 60,
      ticket_age_add: 0,
      ticket_nonce: <<1>>,
      ticket: <<1>>,
      extensions: [extension.Extension(extension.EarlyData, <<0, 0, 0, 1>>)],
    )
  assert session_ticket.store(
      new_ticket: invalid_early_data,
      received_at_milliseconds: issued_at,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "example.com",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: <<>>,
    )
    == Error(session_ticket.InvalidEarlyData)
  assert session_ticket.issue(
      ticket_key:,
      issued_at_milliseconds: issued_at,
      lifetime_seconds: 604_801,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "example.com",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: <<>>,
      permit_early_data: False,
    )
    == Error(session_ticket.InvalidLifetime)

  let assert Ok(new_ticket) = issue_without_early_data()
  let assert Ok(client_ticket) =
    session_ticket.store(
      new_ticket:,
      received_at_milliseconds: issued_at,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "example.com",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: <<>>,
    )
  assert !session_ticket.early_data_allowed(client_ticket)
  assert session_ticket.maximum_early_data_size(client_ticket) == None
  assert session_ticket.remembered_parameters(client_ticket) == <<>>
  assert session_ticket.maximum_early_data_size_for_quic(True)
    == Some(0xffff_ffff)
}

fn issue_without_early_data() -> Result(
  message_body.NewSessionTicket,
  session_ticket.Error,
) {
  session_ticket.issue(
    ticket_key:,
    issued_at_milliseconds: issued_at,
    lifetime_seconds: 3600,
    resumption_master_secret:,
    algorithm: crypto.Sha256,
    cipher_suite: hello.Aes128GcmSha256,
    server_name: "example.com",
    alpn: <<"h3">>,
    quic_version: 1,
    remembered_transport_parameters: <<>>,
    permit_early_data: False,
  )
}
