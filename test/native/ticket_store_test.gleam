import gleam/bit_array
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/session_ticket
import http3/internal/native/ticket_store

const issued_at = 5_000_000

const exported_at = 1_700_000_000_000

const ticket_key = <<0x11:256>>

const storage_key = <<0x22:256>>

const different_storage_key = <<0x23:256>>

const resumption_master_secret = <<0x33:256>>

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn survives_restart_without_reusing_wall_time_for_protocol_timers_test() -> Nil {
  let ticket = client_ticket()
  let stored =
    ticket_store.Stored(
      hostname: "example.com",
      port: 443,
      ticket: ticket,
      address_token: <<1, 2, 3, 4>>,
    )
  let assert Ok(ciphertext) =
    ticket_store.export_at(stored, storage_key, issued_at + 1000, exported_at)

  // A restarted VM has a new monotonic-clock origin. Only elapsed wall time
  // from the authenticated export timestamp is carried across that boundary.
  let restarted_now = 50
  let assert Ok(restored) =
    ticket_store.restore_at(
      ciphertext,
      storage_key,
      restarted_now,
      exported_at + 2000,
    )
  let ticket_store.Stored(hostname, port, restored_ticket, address_token) =
    restored
  assert hostname == "example.com"
  assert port == 443
  assert address_token == <<1, 2, 3, 4>>
  assert session_ticket.is_usable(
    restored_ticket,
    restarted_now,
    "example.com",
    <<"h3":utf8>>,
    1,
  )
  assert !session_ticket.early_data_allowed(restored_ticket)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_wrong_key_tampering_rollback_and_expiry_test() -> Nil {
  let stored =
    ticket_store.Stored("example.com", 443, client_ticket(), <<9, 8, 7>>)
  let assert Ok(ciphertext) =
    ticket_store.export_at(stored, storage_key, issued_at + 1000, exported_at)

  assert ticket_store.restore_at(
      ciphertext,
      different_storage_key,
      10,
      exported_at + 1000,
    )
    == Error(ticket_store.InvalidTicket)
  assert ticket_store.restore_at(
      flip_last(ciphertext),
      storage_key,
      10,
      exported_at + 1000,
    )
    == Error(ticket_store.InvalidTicket)
  assert ticket_store.restore_at(ciphertext, storage_key, 10, exported_at - 1)
    == Error(ticket_store.ClockRollback)
  assert ticket_store.restore_at(
      ciphertext,
      storage_key,
      10,
      exported_at + 3_600_001,
    )
    == Error(ticket_store.Expired)
}

fn client_ticket() -> session_ticket.ClientTicket {
  let assert Ok(new_ticket) =
    session_ticket.issue(
      ticket_key:,
      issued_at_milliseconds: issued_at,
      lifetime_seconds: 3600,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "example.com",
      alpn: <<"h3":utf8>>,
      quic_version: 1,
      remembered_transport_parameters: <<1, 2, 3>>,
      permit_early_data: False,
    )
  let assert Ok(ticket) =
    session_ticket.store(
      new_ticket:,
      received_at_milliseconds: issued_at + 25,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "example.com",
      alpn: <<"h3":utf8>>,
      quic_version: 1,
      remembered_transport_parameters: <<1, 2, 3>>,
    )
  ticket
}

fn flip_last(bytes: BitArray) -> BitArray {
  let prefix_size = { bit_array.byte_size(bytes) - 1 } * 8
  let assert <<prefix:bits-size(prefix_size), last>> = bytes
  let changed = { last + 1 } % 256
  <<prefix:bits, changed>>
}
