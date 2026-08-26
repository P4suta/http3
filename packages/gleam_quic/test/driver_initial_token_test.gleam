import gleam/bit_array
import gleam/option.{None, Some}
import gleam_quic/internal/connection_state
import gleam_quic/internal/driver
import gleam_quic/internal/retry_integrity
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/packet
import gleam_quic/transport_parameter
import gleam_quic/version

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

const original_destination_connection_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

const client_connection_id = <<9, 10, 11, 12, 13, 14, 15, 16>>

const retry_source_connection_id = <<21, 22, 23, 24, 25, 26, 27, 28>>

/// RFC 9000 section 14.1: every path carries this much, and nothing is known
/// to carry more until DPLPMTUD confirms it.
const minimum_datagram_bytes = 1200

/// The widest Retry token this endpoint will repeat: the floor minus what
/// protecting an Initial costs around its frames and the payload one Initial
/// keeps in reserve. The server picks this width, so it is the part of an
/// Initial's overhead a budget computed without the token under-counts by.
const wide_retry_token = <<0:size(861)-unit(8)>>

/// A token no Initial can repeat and still fit the floor. This endpoint
/// carries none of it rather than building a datagram past the floor.
const oversized_retry_token = <<0:size(4096)-unit(8)>>

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_a_post_retry_initial_inside_the_smallest_path_test() -> Nil {
  let client = started_client()
  let assert Ok(Some(first)) = driver.prepare_datagram(client, 1000, 1)
  assert bit_array.byte_size(driver.prepared_bytes(first))
    == minimum_datagram_bytes
  let assert Ok(client) = driver.commit_datagram(first, 1)

  // The server demands address validation and picks the token width itself.
  // Every Initial from here on repeats that token, so the payload one Initial
  // may carry has to shrink by exactly what the token costs.
  let assert Ok(client) =
    driver.receive_datagram(client, retry_datagram(wide_retry_token), 10)
  assert driver.peer_connection_id(client) == retry_source_connection_id

  let assert Ok(Some(retried)) = driver.prepare_datagram(client, 1000, 11)
  let datagram = driver.prepared_bytes(retried)
  let assert Ok(#(packet.Initial(_, token, _), _)) = packet.parse_long(datagram)
  assert token == wide_retry_token
  assert bit_array.byte_size(datagram) == minimum_datagram_bytes
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn fails_fast_on_an_authenticated_retry_no_initial_can_carry_test() -> Nil {
  let client = started_client()

  // The server chose a token no Initial can repeat inside the 1200-byte
  // floor, so this connection cannot continue: it can neither drop the token
  // (the server would reject the Initial) nor send it (no path is known to
  // carry the datagram). Reporting that as a typed transport failure ends the
  // attempt now instead of stalling until the idle timeout.
  //
  // The failure is local, and says so. RFC 9000 puts no upper bound on a Retry
  // token, so a server that issues a wide one has violated nothing: the width
  // that defeats us is this stack's own conservative Initial budget, and a
  // CONNECTION_CLOSE blaming the peer would read as a peer bug in the log and
  // the qlog.
  let failure =
    driver.receive_datagram(client, retry_datagram(oversized_retry_token), 10)
  assert failure
    == Error(driver.RetryTokenTooLarge(
      bit_array.byte_size(oversized_retry_token),
      connection_state.maximum_initial_token_bytes(),
    ))
  let assert Error(error) = failure
  assert !driver.discardable_receive_error(error)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn discards_an_unauthenticated_oversized_retry_test() -> Nil {
  let client = started_client()

  // The width check happens only after the Retry integrity tag verifies, so
  // an off-path attacker cannot end a connection by forging one wide token.
  let forged = retry_datagram(oversized_retry_token)
  let assert Ok(prefix) =
    bit_array.slice(forged, 0, bit_array.byte_size(forged) - 16)
  let assert Ok(client) =
    driver.receive_datagram(client, <<prefix:bits, 0:128>>, 10)
  assert driver.peer_connection_id(client) == original_destination_connection_id

  let assert Ok(Some(next)) = driver.prepare_datagram(client, 1000, 11)
  let assert Ok(#(packet.Initial(_, token, _), _)) =
    packet.parse_long(driver.prepared_bytes(next))
  assert token == <<>>
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ignores_a_cached_token_no_initial_can_carry_test() -> Nil {
  let assert Ok(tls) = engine.start_client(client_tls_config())

  // A cached NEW_TOKEN is an optimization: it saves a round trip when the
  // server accepts it. One too wide to ride an Initial is dropped and the
  // connection starts without it, rather than refusing to connect at all.
  let assert Ok(client) =
    driver.start_client_with_token(
      connection_state.default_config(connection_state.Client),
      tls,
      original_destination_connection_id,
      client_connection_id,
      oversized_retry_token,
      0,
    )

  let assert Ok(Some(first)) = driver.prepare_datagram(client, 1000, 1)
  let datagram = driver.prepared_bytes(first)
  let assert Ok(#(packet.Initial(_, token, _), _)) = packet.parse_long(datagram)
  assert token == <<>>
  assert bit_array.byte_size(datagram) == minimum_datagram_bytes
}

/// One client driver with nothing sent yet.
fn started_client() -> driver.State {
  let assert Ok(tls) = engine.start_client(client_tls_config())
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  client
}

fn client_tls_config() -> engine.ClientConfig {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(trust_store) = authentication.trust_store_from_pem(ca_pem)
  engine.ClientConfig(
    version: version.Version1,
    hostname: "localhost",
    application_protocols: [<<"h3">>],
    transport_parameters: [
      transport_parameter.InitialSourceConnectionId(client_connection_id),
      transport_parameter.MaxUdpPayloadSize(1200),
      // A reserved GREASE parameter (RFC 9000 section 18.1, 31 * N + 27) with
      // a payload wide enough that the ClientHello alone cannot share one
      // 1200-byte Initial with a server-chosen token. Real first flights reach
      // this size through certificate-compression, ECH, and key-share
      // extensions; this is the smallest way to build one here.
      transport_parameter.Unknown(3127, <<0:size(600)-unit(8)>>),
    ],
    trust_store: trust_store,
    client_credential: None,
    retried: False,
    version_negotiated: False,
  )
}

/// One authenticated Retry packet carrying `token`.
fn retry_datagram(token: BitArray) -> BitArray {
  let retry_without_tag = <<
    0xf0,
    1:32,
    8,
    client_connection_id:bits,
    8,
    retry_source_connection_id:bits,
    token:bits,
  >>
  let assert Ok(tag) =
    retry_integrity.tag(
      version.Version1,
      original_destination_connection_id,
      retry_without_tag,
    )
  <<retry_without_tag:bits, tag:bits>>
}
