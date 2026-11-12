//// Redacted HTTP/3 runtime failures shared by the unified adapters.

import gleam/option.{Some}
import http/error
import http3/failure as h3_failure

pub fn from_runtime(failure: h3_failure.Failure) -> error.Error {
  case failure {
    h3_failure.Resolution -> error.new(error.Dns)
    h3_failure.Tls(_) -> error.new(error.Tls)
    h3_failure.Quic(_, _) -> error.new(error.Protocol(error.Quic))
    h3_failure.Http3(_, _) -> error.new(error.Protocol(error.Http3))
    h3_failure.Cancelled
    | h3_failure.Closed(h3_failure.Local, _)
    | h3_failure.Closed(h3_failure.Peer, Some(0x10c)) ->
      error.new(error.Cancelled)
    h3_failure.Closed(h3_failure.Peer, _) ->
      error.new(error.Protocol(error.Http3))
    h3_failure.Timeout(phase) -> {
      let phase = case phase {
        h3_failure.Dns -> error.DnsLookup
        h3_failure.Connect -> error.Connect
        h3_failure.Handshake -> error.TlsHandshake
        h3_failure.Operation | h3_failure.Drain -> error.Operation
        h3_failure.Idle -> error.Idle
        h3_failure.Total -> error.Total
      }
      error.new(error.Timeout(phase))
    }
    h3_failure.Socket(operation) ->
      case operation {
        h3_failure.OpenSocket
        | h3_failure.BindSocket
        | h3_failure.ConnectSocket -> error.new(error.ConnectFailed)
        h3_failure.SendDatagram | h3_failure.ReceiveDatagram ->
          error.new(error.Protocol(error.Quic))
        h3_failure.ReadFile | h3_failure.WriteFile -> error.new(error.Service)
      }
    h3_failure.Limit(h3_failure.RequestBody, maximum)
    | h3_failure.Limit(h3_failure.ResponseBody, maximum) ->
      error.new(error.Body(error.TooLarge(maximum)))
    h3_failure.Limit(resource, _) | h3_failure.Overload(resource) ->
      error.new(error.Resource(map_resource(resource)))
  }
}

fn map_resource(resource: h3_failure.Resource) -> error.ResourceKind {
  case resource {
    h3_failure.Connections | h3_failure.Handshakes -> error.Connections
    h3_failure.BidirectionalStreams | h3_failure.UnidirectionalStreams ->
      error.Streams
    h3_failure.RequestBody | h3_failure.ResponseBody -> error.BufferedBody
    h3_failure.Buffer
    | h3_failure.Frame
    | h3_failure.EndpointMemory
    | h3_failure.QpackTable -> error.Memory
    h3_failure.Queue
    | h3_failure.Datagram
    | h3_failure.QpackBlockedStreams
    | h3_failure.AcceptWaiters
    | h3_failure.Telemetry -> error.Queue
  }
}
