import gleam/list
import gleam/option.{None, Some}
import http3/failure

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn every_public_failure_category_is_constructible_test() -> Nil {
  let failures = [
    failure.Resolution,
    failure.Socket(failure.OpenSocket),
    failure.Socket(failure.BindSocket),
    failure.Socket(failure.ConnectSocket),
    failure.Socket(failure.SendDatagram),
    failure.Socket(failure.ReceiveDatagram),
    failure.Socket(failure.ReadFile),
    failure.Socket(failure.WriteFile),
    failure.Tls(failure.Local),
    failure.Tls(failure.Peer),
    failure.Quic(failure.Peer, Some(0x0a)),
    failure.Http3(failure.Peer, Some(0x0102)),
    failure.Timeout(failure.Dns),
    failure.Timeout(failure.Connect),
    failure.Timeout(failure.Handshake),
    failure.Timeout(failure.Operation),
    failure.Timeout(failure.Idle),
    failure.Timeout(failure.Drain),
    failure.Timeout(failure.Total),
    failure.Cancelled,
    failure.Closed(failure.Local, None),
    failure.Closed(failure.Peer, Some(0x010c)),
    failure.Limit(failure.Connections, 1024),
    failure.Limit(failure.Handshakes, 128),
    failure.Limit(failure.BidirectionalStreams, 100),
    failure.Limit(failure.UnidirectionalStreams, 100),
    failure.Limit(failure.RequestBody, 8_388_608),
    failure.Limit(failure.ResponseBody, 8_388_608),
    failure.Limit(failure.Buffer, 262_144),
    failure.Limit(failure.EndpointMemory, 67_108_864),
    failure.Limit(failure.Queue, 1024),
    failure.Limit(failure.Frame, 65_536),
    failure.Limit(failure.Datagram, 1200),
    failure.Limit(failure.QpackTable, 4096),
    failure.Limit(failure.QpackBlockedStreams, 16),
    failure.Limit(failure.AcceptWaiters, 1),
    failure.Overload(failure.Telemetry),
  ]
  assert list.length(failures) == 37
}
