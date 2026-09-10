//// Test-only finite task and credential fixtures.

import http/masque

/// Race every HTTP/1 listener phase writer against fixed-size snapshots.
@external(erlang, "http_test_ffi", "http1_listener_snapshot_race")
pub fn http1_listener_snapshot_race(
  iterations_per_writer: Int,
) -> #(Int, Int, Int, Int, Int, Int, Int, Int, Int, Int, Int, Int, Int, Int)

/// Leave an HTTP/1 diagnostic writer orphaned and require finite fallback.
@external(erlang, "http_test_ffi", "http1_listener_orphaned_writer_trace")
pub fn http1_listener_orphaned_writer_trace() -> #(Bool, Bool, Bool)

/// Race every HTTP/2 listener/drain writer against fixed-size snapshots.
@external(erlang, "http_test_ffi", "http2_listener_snapshot_race")
pub fn http2_listener_snapshot_race(
  iterations_per_writer: Int,
) -> #(
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
)

/// Leave an HTTP/2 diagnostic writer orphaned and require finite fallback.
@external(erlang, "http_test_ffi", "http2_listener_orphaned_writer_trace")
pub fn http2_listener_orphaned_writer_trace() -> #(Bool, Bool, Bool)

/// Race both idle-activity directions against payload-free snapshots.
@external(erlang, "http_test_ffi", "idle_direction_snapshot_race")
pub fn idle_direction_snapshot_race(
  iterations_per_direction: Int,
) -> #(Int, Int, Int, Int)

/// Race every listener accept outcome against atomic diagnostic snapshots.
@external(erlang, "http_test_ffi", "masque_listener_snapshot_race")
pub fn masque_listener_snapshot_race(
  iterations_per_outcome: Int,
) -> #(Int, Int, Int, Int, Int, Int)

/// Leave the listener diagnostics in an orphaned active-writer state. Later
/// writers must proceed, and readers must expose their inconsistent fallback.
@external(erlang, "http_test_ffi", "masque_listener_orphaned_writer_trace")
pub fn masque_listener_orphaned_writer_trace() -> #(Bool, Bool, Bool)

/// Race every listener setup outcome and duplicate admission against
/// payload-free atomic snapshots.
@external(erlang, "http_test_ffi", "masque_listener_setup_snapshot_race")
pub fn masque_listener_setup_snapshot_race(
  iterations_per_outcome: Int,
) -> #(Int, Int, Int, Int, Int, Int, Int)

/// Race one Packet Too Big diagnostic writer against atomic snapshots.
@external(erlang, "http_test_ffi", "packet_too_big_snapshot_race")
pub fn packet_too_big_snapshot_race(
  iterations: Int,
) -> #(Int, Int, Int, Int, Int)

/// Exercise the production token bucket at one instant and after one refill.
@external(erlang, "http_test_ffi", "packet_too_big_limiter_trace")
pub fn packet_too_big_limiter_trace() -> #(Int, Int, Int)

/// Exercise token refill when BEAM's monotonic epoch is represented by a
/// negative integer. The result is delivery, attempts, rate-limited, failures.
@external(erlang, "http_test_ffi", "packet_too_big_negative_epoch_refill_trace")
pub fn packet_too_big_negative_epoch_refill_trace() -> #(Int, Int, Int, Int)

/// Corrupt one seqlock into an orphaned writer state and verify both the
/// writer and snapshot paths terminate instead of spinning forever.
@external(erlang, "http_test_ffi", "packet_too_big_orphaned_seqlock_trace")
pub fn packet_too_big_orphaned_seqlock_trace() -> #(Bool, Bool)

/// Return deterministic IPv4 and IPv6 Packet Too Big wire vectors.
@external(erlang, "http_test_ffi", "packet_too_big_wire_vectors")
pub fn packet_too_big_wire_vectors() -> #(BitArray, BitArray)

/// Exercise quote truncation, maximum MTUs, malformed lengths, and prohibited
/// destinations in the production Packet Too Big builder.
@external(erlang, "http_test_ffi", "packet_too_big_builder_boundary_trace")
pub fn packet_too_big_builder_boundary_trace() -> #(
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
)

/// One monitored test task.
pub type Task(value)

@external(erlang, "http_test_ffi", "start_task")
pub fn start_task(run: fn() -> value) -> Task(value)

@external(erlang, "http_test_ffi", "await_task")
pub fn await_task(task: Task(value)) -> value

/// Terminate the current test worker with an abnormal exit.
@external(erlang, "http_test_ffi", "exit_now")
pub fn exit_now() -> Nil

/// Violate the declared resolver return type at the Erlang boundary.
@external(erlang, "http_test_ffi", "malformed_dns_adapter")
pub fn malformed_dns_adapter(
  host: String,
  timeout_milliseconds: Int,
) -> Result(List(masque.IpAddress), masque.DnsLookupFailure)

/// Violate the declared socket-resource return type at the Erlang boundary.
@external(erlang, "http_test_ffi", "malformed_udp_socket_adapter")
pub fn malformed_udp_socket_adapter(
  endpoint: masque.UdpEndpoint,
  timeout_milliseconds: Int,
) -> Result(masque.UdpSocketResource(String), masque.UdpSocketOpenFailure)

/// Send one packet across real unconnected IPv4 loopback sockets.
@external(erlang, "http_test_ffi", "udp_loopback_packet")
pub fn udp_loopback_packet(
  payload: BitArray,
) -> #(masque.UdpEndpoint, masque.UdpEndpoint, BitArray)

/// One test-owned UDP echo endpoint with a finite active-once mailbox.
pub type UdpEchoServer

/// One test-owned socket that excludes a second IPv4 bind to its port.
pub type UdpPortGuard

/// Reserve one real loopback UDP port without address/port reuse.
@external(erlang, "http_test_ffi", "start_exclusive_udp_port_guard")
pub fn start_exclusive_udp_port_guard() -> #(UdpPortGuard, Int)

/// Release an exclusive loopback UDP port and await owner convergence.
@external(erlang, "http_test_ffi", "stop_exclusive_udp_port_guard")
pub fn stop_exclusive_udp_port_guard(guard: UdpPortGuard) -> Nil

/// Start a real IPv4 loopback UDP echo endpoint.
@external(erlang, "http_test_ffi", "start_udp_echo_server")
pub fn start_udp_echo_server() -> #(UdpEchoServer, masque.UdpEndpoint)

/// Start a real active-once peer that returns one fixed response per packet.
@external(erlang, "http_test_ffi", "start_udp_fixed_response_server")
pub fn start_udp_fixed_response_server(
  response: BitArray,
) -> #(UdpEchoServer, masque.UdpEndpoint)

/// Start an IPv4 echo peer that observes incoming TOS and marks replies CE.
@external(erlang, "http_test_ffi", "start_udp_ecn_echo_server")
pub fn start_udp_ecn_echo_server() -> #(UdpEchoServer, masque.UdpEndpoint)

/// Return packet count, last incoming TOS, and configured reply TOS.
@external(erlang, "http_test_ffi", "udp_ecn_echo_snapshot")
pub fn udp_ecn_echo_snapshot(server: UdpEchoServer) -> #(Int, Int, Int)

/// Stop the loopback endpoint and wait for its socket owner to terminate.
@external(erlang, "http_test_ffi", "stop_udp_echo_server")
pub fn stop_udp_echo_server(server: UdpEchoServer) -> Nil

/// Construct a closed production-shaped socket handle for fatal-event tests.
@external(erlang, "http_test_ffi", "closed_system_udp_socket")
pub fn closed_system_udp_socket() -> masque.SystemUdpSocket

/// Kill the dedicated production UDP owner and wait for its termination.
@external(erlang, "http_test_ffi", "kill_system_udp_owner")
pub fn kill_system_udp_owner(socket: masque.SystemUdpSocket) -> Nil

/// Close the actor-owned UDP port and inject OTP's canonical close event.
///
/// An external `gen_udp:close/1` does not itself notify the controlling
/// process, so this deterministic fixture supplies the production-shaped
/// `{udp_closed, Socket}` message after closing the real port.
@external(erlang, "http_test_ffi", "close_system_udp_port_and_notify_owner")
pub fn close_system_udp_port_and_notify_owner(
  socket: masque.SystemUdpSocket,
) -> Nil

/// Inject OTP's canonical payload-free UDP error notification.
@external(erlang, "http_test_ffi", "notify_system_udp_error")
pub fn notify_system_udp_error(socket: masque.SystemUdpSocket) -> Nil

/// Suspend the dedicated production UDP owner for bounded admission tests.
@external(erlang, "http_test_ffi", "suspend_system_udp_owner")
pub fn suspend_system_udp_owner(socket: masque.SystemUdpSocket) -> Nil

/// Return the caller's mailbox length for convergence assertions.
@external(erlang, "http_test_ffi", "message_queue_length")
pub fn message_queue_length() -> Int

/// Return the public loopback certificate PEM, private-key PEM, and CA DER.
@external(erlang, "http_test_ffi", "server_credentials")
pub fn server_credentials() -> #(BitArray, BitArray, BitArray)
