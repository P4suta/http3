import gleam/list
import gleam/option.{None, Some}
import http/error
import http/internal/http3/failure as adapter
import http3/failure as h3

pub fn http3_failure_adapter_preserves_connection_and_cancellation_categories_test() -> Nil {
  list.each(
    [
      #(h3.Resolution, error.Dns),
      #(h3.Tls(h3.Local), error.Tls),
      #(h3.Tls(h3.Peer), error.Tls),
      #(h3.Quic(h3.Peer, Some(17)), error.Protocol(error.Quic)),
      #(h3.Http3(h3.Local, None), error.Protocol(error.Http3)),
      #(h3.Cancelled, error.Cancelled),
      #(h3.Closed(h3.Local, None), error.Cancelled),
      #(h3.Closed(h3.Peer, Some(0x10c)), error.Cancelled),
      #(h3.Closed(h3.Peer, None), error.Protocol(error.Http3)),
    ],
    fn(pair) {
      let #(incoming, expected) = pair
      assert error.kind(adapter.from_runtime(incoming)) == expected
    },
  )
}

pub fn http3_failure_adapter_preserves_every_deadline_phase_test() -> Nil {
  list.each(
    [
      #(h3.Dns, error.DnsLookup),
      #(h3.Connect, error.Connect),
      #(h3.Handshake, error.TlsHandshake),
      #(h3.Operation, error.Operation),
      #(h3.Drain, error.Operation),
      #(h3.Idle, error.Idle),
      #(h3.Total, error.Total),
    ],
    fn(pair) {
      let #(phase, expected) = pair
      assert error.kind(adapter.from_runtime(h3.Timeout(phase)))
        == error.Timeout(expected)
    },
  )
}

pub fn http3_failure_adapter_preserves_socket_operation_categories_test() -> Nil {
  list.each(
    [
      #(h3.OpenSocket, error.ConnectFailed),
      #(h3.BindSocket, error.ConnectFailed),
      #(h3.ConnectSocket, error.ConnectFailed),
      #(h3.SendDatagram, error.Protocol(error.Quic)),
      #(h3.ReceiveDatagram, error.Protocol(error.Quic)),
      #(h3.ReadFile, error.Service),
      #(h3.WriteFile, error.Service),
    ],
    fn(pair) {
      let #(operation, expected) = pair
      assert error.kind(adapter.from_runtime(h3.Socket(operation))) == expected
    },
  )
}

pub fn http3_failure_adapter_preserves_every_resource_category_test() -> Nil {
  list.each(
    [
      #(h3.Connections, error.Connections),
      #(h3.Handshakes, error.Connections),
      #(h3.BidirectionalStreams, error.Streams),
      #(h3.UnidirectionalStreams, error.Streams),
      #(h3.Buffer, error.Memory),
      #(h3.EndpointMemory, error.Memory),
      #(h3.QpackTable, error.Memory),
      #(h3.Queue, error.Queue),
      #(h3.Frame, error.Memory),
      #(h3.Datagram, error.Queue),
      #(h3.QpackBlockedStreams, error.Queue),
      #(h3.AcceptWaiters, error.Queue),
      #(h3.Telemetry, error.Queue),
    ],
    fn(pair) {
      let #(resource, expected) = pair
      assert error.kind(adapter.from_runtime(h3.Limit(resource, 123)))
        == error.Resource(expected)
      assert error.kind(adapter.from_runtime(h3.Overload(resource)))
        == error.Resource(expected)
    },
  )
  list.each([h3.RequestBody, h3.ResponseBody], fn(resource) {
    assert error.kind(adapter.from_runtime(h3.Limit(resource, 123)))
      == error.Body(error.TooLarge(123))
    assert error.kind(adapter.from_runtime(h3.Overload(resource)))
      == error.Resource(error.BufferedBody)
  })
}
