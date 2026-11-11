import gleam/option.{None, Some}
import quic_core/internal/crypto
import quic_core/internal/tls/extension
import quic_core/internal/tls/hello
import quic_core/internal/tls/message_body
import quic_core/internal/tls/session_ticket

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
  assert !session_ticket.is_usable(
    client_ticket,
    issued_at + 1000,
    "example.com",
    <<"h3">>,
    0x6b33_43cf,
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
  assert session_ticket.open(
      ticket_key:,
      opaque_ticket:,
      now_milliseconds: issued_at + 1000,
      expected_server_name: "example.com",
      expected_alpn: <<"h3">>,
      expected_quic_version: 0x6b33_43cf,
    )
    == Error(session_ticket.OriginMismatch)
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

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn application_context_is_bounded_authenticated_and_versioned_test() -> Nil {
  let server_context = <<"http3-settings-v1">>
  let assert Ok(new_ticket) =
    session_ticket.issue_with_application_context(
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
      remembered_application_context: server_context,
      permit_early_data: True,
    )
  let message_body.NewSessionTicket(_, _, _, opaque_ticket, _) = new_ticket
  let assert Ok(session_ticket.Claims(
    remembered_application_context: recovered_server_context,
    ..,
  )) =
    session_ticket.open(
      ticket_key,
      opaque_ticket,
      issued_at + 1,
      "example.com",
      <<"h3">>,
      1,
    )
  assert recovered_server_context == server_context

  let assert Ok(client_ticket) =
    session_ticket.store(
      new_ticket,
      issued_at,
      resumption_master_secret,
      crypto.Sha256,
      hello.Aes128GcmSha256,
      "example.com",
      <<"h3">>,
      1,
      <<1, 2, 3>>,
    )
  assert session_ticket.application_context(client_ticket) == <<>>
  let client_context = <<"remembered-http3-settings">>
  let assert Ok(client_ticket) =
    session_ticket.with_application_context(client_ticket, client_context)
  let storage_key = <<0x44:256>>
  let assert Ok(exported) =
    session_ticket.export_client(
      client_ticket,
      storage_key,
      issued_at + 10,
      issued_at + 100,
    )
  let assert Ok(restored) =
    session_ticket.import_client(
      exported,
      storage_key,
      issued_at + 20,
      issued_at + 110,
    )
  assert session_ticket.application_context(restored) == client_context
  let assert <<_, export_tail:bits>> = exported
  assert session_ticket.import_client(
      <<1, export_tail:bits>>,
      storage_key,
      issued_at + 20,
      issued_at + 110,
    )
    == Error(session_ticket.InvalidTicket)

  let oversized_context_bits = 32_776
  assert session_ticket.with_application_context(client_ticket, <<
      0:size(oversized_context_bits),
    >>)
    == Error(session_ticket.InvalidApplicationContext)
  assert session_ticket.with_application_context(client_ticket, <<0:1>>)
    == Error(session_ticket.InvalidApplicationContext)
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
