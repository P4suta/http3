import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleeunit
import http/body
import http/context
import http/server
import http3/client as http3_client
import http3/failure as http3_failure
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn unified_server_adapts_streaming_http3_over_the_public_api_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(incoming: request.Request(body.Body), request_context) {
    assert context.protocol(request_context) == context.Http3
    assert context.tls_identity(request_context)
      == context.TlsIdentity("localhost", None)
    assert context.early_data(request_context) == context.EarlyDataDisabled
    assert incoming.method == http.Post
    assert incoming.scheme == http.Https
    assert incoming.host == "localhost"
    assert incoming.path == "/unified"
    assert incoming.query == Some("transport=h3")
    let assert Ok(#(<<"request":utf8>>, [])) = body.read_all(incoming.body, 7)
    Ok(response.Response(
      status: 201,
      headers: [#("content-type", "text/plain")],
      body: body.from_bytes_with_trailers(<<"response":utf8>>, [
        #("x-complete", "yes"),
      ]),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(adapter) =
    server.http3_defaults(
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let assert Ok(listener) =
    server.listen_http3(executor, <<127, 0, 0, 1>>, 0, adapter)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let outgoing =
    request.Request(
      method: http.Post,
      headers: [],
      body: <<"request":utf8>>,
      scheme: http.Https,
      host: "localhost",
      port: Some(port),
      path: "/unified",
      query: Some("transport=h3"),
    )
  let assert Ok(incoming) = http3_client.send(configuration, outgoing)

  assert incoming.status == 201
  assert incoming.body == <<"response":utf8>>
  assert response.get_header(incoming, "content-type") == Ok("text/plain")
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn unified_server_context_cancellation_resets_http3_request_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let started = process.new_subject()
  let handler = fn(_: request.Request(body.Body), request_context) {
    process.send(started, request_context)
    process.sleep(1000)
    Ok(response.Response(status: 200, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(adapter) =
    server.http3_defaults(
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let assert Ok(listener) =
    server.listen_http3(executor, <<127, 0, 0, 1>>, 0, adapter)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let assert Ok(connection) =
    http3_client.connect(configuration, "localhost", port)
  let outbound =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path("/cancel-context")
    |> request.set_body(Nil)
  let assert Ok(stream) = http3_client.open_stream(connection, outbound)
  assert http3_client.finish(stream) == Ok(Nil)
  let assert Ok(request_context) = process.receive(started, within: 1000)

  context.cancel(request_context)

  assert http3_client.next_event(stream)
    == Error(
      http3_client.Failure(http3_failure.Closed(http3_failure.Peer, Some(0x10c))),
    )
  let _closed = http3_client.close(connection)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}
