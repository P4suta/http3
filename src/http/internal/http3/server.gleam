//// Public-HTTP/3 adapter for the protocol-neutral server executor.
////
//// QUIC, UDP, TLS, Retry, token, and connection ownership remain entirely in
//// the public `http3/server` implementation. This module only translates
//// standard messages, pull-based bodies, and redacted request context.

import gleam/bit_array
import gleam/erlang/process
import gleam/http as gleam_http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import http/body
import http/context
import http/error
import http3/address as h3_address
import http3/server as h3_server
import http3/transport as h3_transport

const default_operation_milliseconds = 30_000

const default_pull_bytes = 65_536

/// The structurally shared application handler contract.
pub type Handler =
  fn(Request(body.Body), context.Context) ->
    Result(Response(body.Body), error.Error)

/// Validated HTTP/3 listener policy without transport handles.
pub opaque type Config {
  Config(
    configuration: h3_server.Configuration,
    service_identity: String,
    operation_milliseconds: Int,
    pull_bytes: Int,
  )
}

/// An owned public HTTP/3 listener and its redacted local endpoint.
pub opaque type Listener {
  Listener(listener: h3_server.Listener, endpoint: context.Endpoint)
}

/// Build secure HTTP/3 defaults. Certificate and key parsing is eager.
pub fn defaults(
  certificate: BitArray,
  private_key: BitArray,
  service_identity: String,
) -> Result(Config, error.Error) {
  use _ <- result.try(require(service_identity != "", security_policy_error()))
  use configuration <- result.try(
    h3_server.new(certificate, private_key)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  Ok(Config(
    configuration:,
    service_identity:,
    operation_milliseconds: default_operation_milliseconds,
    pull_bytes: default_pull_bytes,
  ))
}

/// Replace all HTTP/3 deadlines with one finite upper bound.
pub fn with_timeout(
  config: Config,
  milliseconds: Int,
) -> Result(Config, error.Error) {
  use configuration <- result.try(
    h3_server.with_timeout(config.configuration, milliseconds)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  Ok(Config(..config, configuration:, operation_milliseconds: milliseconds))
}

/// Replace request, response, and one-pull retained-byte limits.
pub fn with_body_limits(
  config: Config,
  request_bytes: Int,
  response_bytes: Int,
  pull_bytes: Int,
) -> Result(Config, error.Error) {
  use configuration <- result.try(
    h3_server.with_request_body_limit(config.configuration, request_bytes)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  use configuration <- result.try(
    h3_server.with_response_body_limit(configuration, response_bytes)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  use configuration <- result.try(
    h3_server.with_stream_buffer_limit(configuration, pull_bytes)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  Ok(Config(..config, configuration:, pull_bytes:))
}

/// Start the public HTTP/3 listener and one finite accept loop.
pub fn listen(
  handler: Handler,
  address: BitArray,
  port: Int,
  config: Config,
) -> Result(Listener, error.Error) {
  use bind_address <- result.try(
    h3_address.from_bytes(address)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  use configuration <- result.try(
    h3_server.with_port(config.configuration, port)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  let configuration = h3_server.with_bind_address(configuration, bind_address)
  use listener <- result.try(
    h3_server.start(configuration) |> result.map_error(map_h3_error),
  )
  use bound_port <- result.try(
    h3_server.port(listener) |> result.map_error(map_h3_error),
  )
  let endpoint =
    context.Endpoint(h3_address.to_string(bind_address), bound_port)
  let _acceptor =
    process.spawn_unlinked(fn() {
      accept_loop(
        listener,
        handler,
        endpoint,
        config.service_identity,
        config.operation_milliseconds,
        config.pull_bytes,
      )
    })
  Ok(Listener(listener, endpoint))
}

/// Return the bound local endpoint without exposing the UDP socket.
pub fn endpoint(listener: Listener) -> context.Endpoint {
  listener.endpoint
}

/// Send GOAWAY and wait for accepted request streams to complete.
pub fn drain(listener: Listener) -> Result(Nil, error.Error) {
  h3_server.graceful_stop(listener.listener)
  |> result.map(fn(_) { Nil })
  |> result.map_error(map_h3_error)
}

/// Stop the listener idempotently.
pub fn stop(listener: Listener) -> Result(Nil, error.Error) {
  h3_server.stop(listener.listener)
  |> result.map(fn(_) { Nil })
  |> result.map_error(map_h3_error)
}

fn accept_loop(
  listener: h3_server.Listener,
  handler: Handler,
  local_endpoint: context.Endpoint,
  service_identity: String,
  operation_milliseconds: Int,
  pull_bytes: Int,
) -> Nil {
  case h3_server.accept(listener) {
    Error(_) -> Nil
    Ok(incoming) -> {
      let _worker =
        process.spawn_unlinked(fn() {
          serve_request(
            incoming,
            handler,
            local_endpoint,
            service_identity,
            operation_milliseconds,
            pull_bytes,
          )
        })
      accept_loop(
        listener,
        handler,
        local_endpoint,
        service_identity,
        operation_milliseconds,
        pull_bytes,
      )
    }
  }
}

fn serve_request(
  incoming: h3_server.Request,
  handler: Handler,
  local_endpoint: context.Endpoint,
  service_identity: String,
  operation_milliseconds: Int,
  pull_bytes: Int,
) -> Nil {
  let outcome = {
    use request_body <- result.try(make_request_body(incoming))
    use request <- result.try(make_request(incoming, request_body))
    use peer_endpoint <- result.try(peer_endpoint(incoming))
    use request_context <- result.try(context.new(
      protocol: context.Http3,
      peer_endpoint:,
      local_endpoint:,
      within_milliseconds: operation_milliseconds,
      tls_identity: context.TlsIdentity(service_identity, None),
      early_data: early_data(incoming),
    ))
    use request_context <- result.try(attach_extended_connect_protocol(
      request_context,
      h3_server.protocol(incoming),
    ))
    use response <- result.try(handler(request, request_context))
    send_response(incoming, request.method, response, pull_bytes)
  }
  case outcome {
    Ok(Nil) -> Nil
    Error(failure) -> finish_failed_request(incoming, failure)
  }
}

fn finish_failed_request(
  incoming: h3_server.Request,
  failure: error.Error,
) -> Nil {
  case error.kind(failure) {
    error.Cancelled | error.Timeout(_) -> {
      let _cancelled = h3_server.cancel(incoming)
      Nil
    }
    _ -> {
      let _ignored = h3_server.respond(incoming, 500, [], <<>>)
      Nil
    }
  }
}

fn attach_extended_connect_protocol(
  request_context: context.Context,
  protocol: Option(String),
) -> Result(context.Context, error.Error) {
  case protocol {
    None -> Ok(request_context)
    Some(protocol) ->
      context.with_extended_connect_protocol(request_context, protocol)
  }
}

fn make_request_body(
  incoming: h3_server.Request,
) -> Result(body.Body, error.Error) {
  body.from_pull(
    request_pull(incoming, <<>>, None),
    content_length(h3_server.headers(incoming)),
    None,
    fn() {
      let _cancelled = h3_server.cancel(incoming)
      Nil
    },
  )
}

fn request_pull(
  incoming: h3_server.Request,
  pending: BitArray,
  trailers: Option(body.Headers),
) -> body.Pull {
  body.pull(fn(maximum_bytes) {
    pull_request(incoming, pending, trailers, maximum_bytes)
  })
}

fn pull_request(
  incoming: h3_server.Request,
  pending: BitArray,
  trailers: Option(body.Headers),
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  case bit_array.byte_size(pending) > 0 {
    True -> emit_request_bytes(incoming, pending, trailers, maximum_bytes)
    False ->
      case h3_server.next_event(incoming) {
        Ok(h3_server.Data(bytes)) ->
          case bit_array.byte_size(bytes) {
            0 -> pull_request(incoming, <<>>, trailers, maximum_bytes)
            _ -> emit_request_bytes(incoming, bytes, trailers, maximum_bytes)
          }
        Ok(h3_server.Trailers(received)) ->
          case trailers {
            None -> pull_request(incoming, <<>>, Some(received), maximum_bytes)
            Some(_) -> Error(protocol_error())
          }
        Ok(h3_server.End) -> Ok(body.PullEnd(option_trailers(trailers)))
        Error(failure) -> Error(map_h3_error(failure))
      }
  }
}

fn emit_request_bytes(
  incoming: h3_server.Request,
  bytes: BitArray,
  trailers: Option(body.Headers),
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  let size = bit_array.byte_size(bytes)
  case size <= maximum_bytes {
    True -> Ok(body.PullData(bytes, request_pull(incoming, <<>>, trailers)))
    False -> {
      use chunk <- result.try(
        bit_array.slice(bytes, at: 0, take: maximum_bytes)
        |> result.map_error(fn(_) { protocol_error() }),
      )
      use pending <- result.try(
        bit_array.slice(bytes, at: maximum_bytes, take: size - maximum_bytes)
        |> result.map_error(fn(_) { protocol_error() }),
      )
      Ok(body.PullData(chunk, request_pull(incoming, pending, trailers)))
    }
  }
}

fn make_request(
  incoming: h3_server.Request,
  request_body: body.Body,
) -> Result(Request(body.Body), error.Error) {
  use _ <- result.try(require(
    h3_server.scheme(incoming) == "https",
    protocol_error(),
  ))
  use #(host, port) <- result.try(
    parse_authority(h3_server.authority(incoming)),
  )
  let #(path, query) = split_target(h3_server.path(incoming))
  Ok(request.Request(
    method: h3_server.method(incoming),
    headers: h3_server.headers(incoming),
    body: request_body,
    scheme: gleam_http.Https,
    host:,
    port:,
    path:,
    query:,
  ))
}

fn parse_authority(
  authority: String,
) -> Result(#(String, Option(Int)), error.Error) {
  case uri.parse("https://" <> authority) {
    Ok(uri.Uri(
      scheme: Some("https"),
      userinfo: None,
      host: Some(host),
      port:,
      path: "",
      query: None,
      fragment: None,
    )) ->
      case host != "" && valid_port(port) {
        True -> Ok(#(host, port))
        False -> Error(protocol_error())
      }
    _ -> Error(protocol_error())
  }
}

fn split_target(target: String) -> #(String, Option(String)) {
  case string.split_once(target, on: "?") {
    Ok(#(path, query)) -> #(path, Some(query))
    Error(Nil) -> #(target, None)
  }
}

fn peer_endpoint(
  incoming: h3_server.Request,
) -> Result(context.Endpoint, error.Error) {
  use endpoint <- result.try(
    h3_server.peer_endpoint(incoming) |> result.map_error(map_h3_error),
  )
  Ok(context.Endpoint(
    h3_address.to_string(h3_address.endpoint_address(endpoint)),
    h3_address.port(endpoint),
  ))
}

fn early_data(incoming: h3_server.Request) -> context.EarlyData {
  case
    h3_server.request_transport(incoming)
    |> h3_transport.stream_early_data_status
  {
    Ok(h3_transport.Accepted) -> context.EarlyDataAccepted
    Ok(h3_transport.Rejected) -> context.EarlyDataRejected
    _ -> context.EarlyDataDisabled
  }
}

fn send_response(
  incoming: h3_server.Request,
  method: gleam_http.Method,
  outgoing: Response(body.Body),
  pull_bytes: Int,
) -> Result(Nil, error.Error) {
  use _ <- result.try(
    h3_server.send_response(incoming, outgoing.status, outgoing.headers)
    |> result.map_error(map_h3_error),
  )
  case method {
    gleam_http.Head -> {
      body.cancel(outgoing.body)
      h3_server.finish_response(incoming) |> result.map_error(map_h3_error)
    }
    _ -> send_response_body(incoming, outgoing.body, pull_bytes)
  }
}

fn send_response_body(
  incoming: h3_server.Request,
  outgoing: body.Body,
  pull_bytes: Int,
) -> Result(Nil, error.Error) {
  case body.read(outgoing, pull_bytes) {
    Error(failure) -> {
      body.cancel(outgoing)
      Error(failure)
    }
    Ok(body.Data(bytes, next)) -> {
      use _ <- result.try(
        h3_server.send_chunk(incoming, bytes) |> result.map_error(map_h3_error),
      )
      send_response_body(incoming, next, pull_bytes)
    }
    Ok(body.Done(completed)) ->
      case body.trailers(completed) {
        Some([_, ..] as trailers) ->
          h3_server.send_trailers(incoming, trailers)
          |> result.map_error(map_h3_error)
        _ ->
          h3_server.finish_response(incoming) |> result.map_error(map_h3_error)
      }
  }
}

fn content_length(headers: List(#(String, String))) -> Option(Int) {
  case headers {
    [] -> None
    [#(name, value), ..rest] ->
      case string.lowercase(name) {
        "content-length" ->
          case int.parse(value) {
            Ok(length) if length >= 0 -> Some(length)
            _ -> None
          }
        _ -> content_length(rest)
      }
  }
}

fn option_trailers(trailers: Option(body.Headers)) -> body.Headers {
  case trailers {
    Some(headers) -> headers
    None -> []
  }
}

fn valid_port(port: Option(Int)) -> Bool {
  case port {
    None -> True
    Some(value) -> value > 0 && value <= 65_535
  }
}

fn map_h3_error(failure: h3_server.Error) -> error.Error {
  case failure {
    h3_server.RequestBodyTooLarge(limit) ->
      error.new(error.Body(error.TooLarge(limit)))
    h3_server.ResponseBodyTooLarge(limit) ->
      error.new(error.Body(error.TooLarge(limit)))
    h3_server.ConsumerTooSlow(_) -> error.new(error.Resource(error.Memory))
    _ -> protocol_error()
  }
}

fn require(condition: Bool, failure: error.Error) -> Result(Nil, error.Error) {
  case condition {
    True -> Ok(Nil)
    False -> Error(failure)
  }
}

fn protocol_error() -> error.Error {
  error.new(error.Protocol(error.Http3))
}

fn security_policy_error() -> error.Error {
  error.new(error.Policy(error.SecurityPolicy))
}
