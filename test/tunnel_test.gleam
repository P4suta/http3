import gleam/bit_array
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleeunit
import http/body
import http/client
import http/error
import http/internal/transport
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn connect_tunnel_exposes_bytes_only_after_a_successful_2xx_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let peer =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use #(socket, head) <- result.try(read_until_head(socket, []))
      use text <- result.try(bytes_text(head))
      assert string.starts_with(text, "CONNECT target.example:443 HTTP/1.1\r\n")
      assert string.contains(text, "Host: 127.0.0.1:" <> int.to_string(port))
      use _ <- result.try(transport.send(
        socket,
        bit_array.from_string(
          "HTTP/1.1 200 Connection Established\r\n"
          <> "Proxy-Agent: fixture\r\n\r\nwelcome",
        ),
      ))
      use #(socket, ping) <- result.try(read_exact(socket, 4, []))
      use _ <- result.try(transport.send(socket, <<"pong":utf8>>))
      use _ <- result.try(transport.close(socket))
      Ok(ping)
    })
  let assert Ok(owner) =
    client.start(client.defaults() |> client.allow_plain_http)
  let outgoing =
    request.Request(
      method: gleam_http.Connect,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(port),
      path: "target.example:443",
      query: None,
    )
  let assert Ok(handshake) = client.open_tunnel(client: owner, outgoing:)
  let incoming = client.tunnel_response(handshake)
  assert incoming.status == 200
  assert response.get_header(incoming, "proxy-agent") == Ok("fixture")
  let assert Ok(#(<<>>, [])) = body.read_all(incoming.body, 0)
  let tunnel = client.tunnel_connection(handshake)
  let assert Ok(client.TunnelData(<<"welcome":utf8>>, tunnel)) =
    client.read_tunnel(tunnel:, maximum_bytes: 7)
  let assert Ok(Nil) = client.send_tunnel(tunnel:, bytes: <<"ping":utf8>>)
  let assert Ok(client.TunnelData(<<"pong":utf8>>, tunnel)) =
    client.read_tunnel(tunnel:, maximum_bytes: 4)
  assert client.read_tunnel(tunnel:, maximum_bytes: 4) == Ok(client.TunnelEnd)
  let assert Ok(Nil) = client.close_tunnel(tunnel)
  let assert Ok(Nil) = client.close_tunnel(tunnel)
  let assert Ok(Nil) = client.close(owner)
  let assert Ok(<<"ping":utf8>>) = http_test_support.await_task(peer)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn upgrade_tunnel_requires_a_101_before_returning_the_stream_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let peer =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use #(socket, head) <- result.try(read_until_head(socket, []))
      use text <- result.try(bytes_text(head))
      assert string.starts_with(text, "GET /chat HTTP/1.1\r\n")
      assert string.contains(text, "connection: Upgrade")
      assert string.contains(text, "upgrade: websocket")
      use _ <- result.try(transport.send(
        socket,
        bit_array.from_string(
          "HTTP/1.1 101 Switching Protocols\r\n"
          <> "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\nready",
        ),
      ))
      use _ <- result.try(transport.close(socket))
      Ok(Nil)
    })
  let assert Ok(owner) =
    client.start(client.defaults() |> client.allow_plain_http)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [#("connection", "Upgrade"), #("upgrade", "websocket")],
      body: <<>>,
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(port),
      path: "/chat",
      query: None,
    )
  let assert Ok(handshake) = client.open_tunnel(client: owner, outgoing:)
  assert client.tunnel_response(handshake).status == 101
  let tunnel = client.tunnel_connection(handshake)
  let assert Ok(client.TunnelData(<<"ready":utf8>>, tunnel)) =
    client.read_tunnel(tunnel:, maximum_bytes: 5)
  assert client.read_tunnel(tunnel:, maximum_bytes: 1) == Ok(client.TunnelEnd)
  let assert Ok(Nil) = client.close_tunnel(tunnel)
  let assert Ok(Nil) = client.close(owner)
  let assert Ok(Nil) = http_test_support.await_task(peer)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn optimistic_tunnel_payload_is_rejected_before_connecting_test() -> Nil {
  let assert Ok(owner) =
    client.start(client.defaults() |> client.allow_plain_http)
  let outgoing =
    request.Request(
      method: gleam_http.Connect,
      headers: [],
      body: <<"forbidden":utf8>>,
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(9),
      path: "target.example:443",
      query: None,
    )
  let assert Error(failure) = client.open_tunnel(client: owner, outgoing:)
  assert error.kind(failure) == error.Policy(error.SecurityPolicy)
  let assert Ok(Nil) = client.close(owner)
  Nil
}

pub fn websocket_upgrade_payload_is_rejected_before_the_101_response_test() -> Nil {
  let assert Ok(owner) =
    client.start(client.defaults() |> client.allow_plain_http)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [#("connection", "Upgrade"), #("upgrade", "websocket")],
      body: <<"forbidden-before-101":utf8>>,
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(9),
      path: "/chat",
      query: None,
    )
  let assert Error(failure) = client.open_tunnel(client: owner, outgoing:)
  assert error.kind(failure) == error.Policy(error.SecurityPolicy)
  let assert Ok(Nil) = client.close(owner)
  Nil
}

fn read_until_head(
  socket: transport.Socket,
  reversed: List(BitArray),
) -> Result(#(transport.Socket, BitArray), transport.Error) {
  use outcome <- result.try(transport.read(socket, 4096, 1000))
  case outcome {
    transport.ReadEnd(_) -> Error(transport.Closed)
    transport.ReadData(bytes, socket) -> {
      let collected = [bytes, ..reversed] |> list.reverse |> bit_array.concat
      case bit_array.to_string(collected) {
        Error(_) -> Error(transport.ReadFailure)
        Ok(text) ->
          case string.contains(text, "\r\n\r\n") {
            True -> Ok(#(socket, collected))
            False -> read_until_head(socket, [bytes, ..reversed])
          }
      }
    }
  }
}

fn read_exact(
  socket: transport.Socket,
  remaining: Int,
  reversed: List(BitArray),
) -> Result(#(transport.Socket, BitArray), transport.Error) {
  case remaining {
    0 -> Ok(#(socket, reversed |> list.reverse |> bit_array.concat))
    _ ->
      case transport.read(socket, remaining, 1000) {
        Error(failure) -> Error(failure)
        Ok(transport.ReadEnd(_)) -> Error(transport.Closed)
        Ok(transport.ReadData(bytes, socket)) ->
          read_exact(socket, remaining - bit_array.byte_size(bytes), [
            bytes,
            ..reversed
          ])
      }
  }
}

fn bytes_text(bytes: BitArray) -> Result(String, transport.Error) {
  bit_array.to_string(bytes) |> result.replace_error(transport.ReadFailure)
}
