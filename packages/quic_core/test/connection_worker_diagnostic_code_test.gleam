import quic_core/internal/connection_state
import quic_core/internal/driver
import quic_core/internal/runtime/connection_worker_diagnostic_code as diagnostic_code
import quic_core/internal/runtime/server_transport
import quic_core/internal/tls/engine
import quic_core/internal/wire_packet

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
