import gleam/bit_array
import gleam/erlang/process
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleeunit
import http/body
import http/error
import http/internal/http1/exchange
import http/internal/transport
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn plain_request_and_incremental_response_round_trip_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let host = "127.0.0.1:" <> int.to_string(port)
  let expected_request =
    bit_array.from_string(
      "POST /upload?mode=test HTTP/1.1\r\n"
      <> "x-client: yes\r\n"
      <> "Host: "
      <> host
      <> "\r\n"
      <> "Connection: close\r\n"
      <> "Content-Length: 7\r\n\r\n"
      <> "payload",
    )
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use received <- result.try(
        receive_exact(socket, bit_array.byte_size(expected_request), []),
      )
      use _ <- result.try(
        transport.send(socket, <<"HTTP/1.1 200 OK\r\nContent-Len":utf8>>),
      )
      use _ <- result.try(
        transport.send(socket, <<
          "gth: 11\r\nx-server: active-once\r\n\r\nhello world":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(received)
    })

  let outgoing =
    request.Request(
      method: gleam_http.Post,
      headers: [#("x-client", "yes")],
      body: body.from_text("payload"),
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(port),
      path: "/upload",
      query: Some("mode=test"),
    )
  let assert Ok(incoming) = exchange.run(outgoing, exchange.defaults())
  assert incoming.status == 200
  assert response.get_header(incoming, "x-server") == Ok("active-once")
  let assert Ok(#(received_body, trailers)) = body.read_all(incoming.body, 32)
  assert received_body == <<"hello world":utf8>>
  assert trailers == []

  let assert Ok(received_request) = http_test_support.await_task(server_task)
  assert received_request == expected_request
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn total_deadline_also_bounds_already_buffered_body_bytes_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let host = "127.0.0.1:" <> int.to_string(port)
  let expected_request =
    bit_array.from_string(
      "GET /deadline HTTP/1.1\r\nHost: "
      <> host
      <> "\r\nConnection: close\r\n\r\n",
    )
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(
        receive_exact(socket, bit_array.byte_size(expected_request), []),
      )
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(Nil)
    })
  let assert Ok(config) =
    exchange.with_timeouts(exchange.defaults(), 1000, 1000, 1000, 1000, 200)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(port),
      path: "/deadline",
      query: None,
    )
  let assert Ok(incoming) = exchange.run(outgoing, config)
  let assert Ok(body.Data(<<"ab":utf8>>, next)) = body.read(incoming.body, 2)
  process.sleep(250)
  let assert Error(failure) = body.read(next, 2)
  assert error.kind(failure) == error.Timeout(error.Total)

  let assert Ok(Nil) = http_test_support.await_task(server_task)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn authenticated_https_uses_the_same_bounded_exchange_path_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let host = "localhost:" <> int.to_string(port)
  let expected_request =
    bit_array.from_string(
      "GET /secure HTTP/1.1\r\nHost: "
      <> host
      <> "\r\nConnection: close\r\n\r\n",
    )
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use ready <- result.try(transport.upgrade_server_tls(
        socket,
        certificate,
        private_key,
        [<<"http/1.1":utf8>>],
        1000,
      ))
      let assert transport.TlsReady(socket, <<"http/1.1":utf8>>, _) = ready
      use received <- result.try(
        receive_exact(socket, bit_array.byte_size(expected_request), []),
      )
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 204 No Content\r\nx-secure: yes\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(received)
    })
  let config =
    exchange.defaults()
    |> exchange.with_ca_certificates([ca_certificate])
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/secure",
      query: None,
    )
  let assert Ok(incoming) = exchange.run(outgoing, config)
  assert incoming.status == 204
  assert response.get_header(incoming, "x-secure") == Ok("yes")
  let assert Ok(#(<<>>, [])) = body.read_all(incoming.body, 0)

  let assert Ok(received_request) = http_test_support.await_task(server_task)
  assert received_request == expected_request
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn declared_response_body_over_the_endpoint_limit_is_typed_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(socket, 4096, 1000))
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(Nil)
    })
  let assert Ok(config) =
    exchange.defaults() |> exchange.with_maximum_body_bytes(4)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(port),
      path: "/too-large",
      query: None,
    )
  let assert Error(failure) = exchange.run(outgoing, config)
  assert error.kind(failure) == error.Body(error.TooLarge(4))

  let assert Ok(Nil) = http_test_support.await_task(server_task)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn invalid_streamed_body_closes_the_connection_at_the_failure_site_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use request_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(_, socket) = request_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n":utf8,
        >>),
      )
      transport.read(socket, 1, 500)
    })
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(port),
      path: "/invalid-chunk",
      query: None,
    )
  let assert Ok(incoming) = exchange.run(outgoing, exchange.defaults())
  let assert Error(failure) = body.read(incoming.body, 16)
  assert error.kind(failure) == error.Protocol(error.Http1)
  let assert Ok(transport.ReadEnd(_)) =
    http_test_support.await_task(server_task)

  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn chunked_request_informational_response_and_trailers_round_trip_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let host = "127.0.0.1:" <> int.to_string(port)
  let expected_request =
    bit_array.from_string(
      "POST /chunks HTTP/1.1\r\n"
      <> "trailer: x-client-trailer\r\n"
      <> "Host: "
      <> host
      <> "\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
      <> "2\r\nab\r\n2\r\ncd\r\n0\r\nx-client-trailer: done\r\n\r\n",
    )
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use received <- result.try(
        receive_exact(socket, bit_array.byte_size(expected_request), []),
      )
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 103 Early Hints\r\nLink: </asset>\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(
        transport.send(socket, <<
          "4;safe=yes\r\nWiki\r\n5\r\npedia\r\n0\r\nx-checksum: yes\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(received)
    })
  let assert Ok(outgoing_body) =
    body.from_pull(
      pull_chunks([<<"ab":utf8>>, <<"cd":utf8>>], [
        #("x-client-trailer", "done"),
      ]),
      None,
      None,
      fn() { Nil },
    )
  let outgoing =
    request.Request(
      method: gleam_http.Post,
      headers: [#("trailer", "x-client-trailer")],
      body: outgoing_body,
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(port),
      path: "/chunks",
      query: None,
    )
  let assert Ok(incoming) = exchange.run(outgoing, exchange.defaults())
  let assert Ok(#(received_body, trailers)) = collect_body(incoming.body, 3, [])
  assert received_body == <<"Wikipedia":utf8>>
  assert trailers == [#("x-checksum", "yes")]

  let assert Ok(received_request) = http_test_support.await_task(server_task)
  assert received_request == expected_request
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn expect_continue_defers_the_request_body_until_the_100_response_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let pulled = process.new_subject()
  let assert Ok(outgoing_body) =
    body.from_pull(signalled_body(pulled), Some(5), None, fn() { Nil })
  let outgoing =
    request.Request(
      method: gleam_http.Post,
      headers: [#("expect", "100-continue"), #("connection", "close")],
      body: outgoing_body,
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(port),
      path: "/continue",
      query: None,
    )
  let client_task =
    http_test_support.start_task(fn() {
      exchange.run(outgoing, exchange.defaults())
    })
  let assert Ok(socket) = transport.accept(listener, 1000)
  let expected_head =
    bit_array.from_string(
      "POST /continue HTTP/1.1\r\nexpect: 100-continue\r\n"
      <> "connection: close\r\nHost: 127.0.0.1:"
      <> int.to_string(port)
      <> "\r\nContent-Length: 5\r\n\r\n",
    )
  let assert Ok(#(socket, received_head)) =
    receive_exact_with_socket(socket, bit_array.byte_size(expected_head), [])
  assert received_head == expected_head
  assert process.receive(pulled, within: 20) == Error(Nil)

  let assert Ok(Nil) =
    transport.send(socket, <<"HTTP/1.1 100 Continue\r\n\r\n":utf8>>)
  let assert Ok(Nil) = process.receive(pulled, within: 1000)
  let assert Ok(#(socket, received_body)) =
    receive_exact_with_socket(socket, 5, [])
  assert received_body == <<"hello":utf8>>
  let assert Ok(Nil) =
    transport.send(socket, <<
      "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n":utf8,
    >>)
  let assert Ok(Nil) = transport.close(socket)

  let assert Ok(incoming) = http_test_support.await_task(client_task)
  assert incoming.status == 204
  let assert Ok(#(<<>>, [])) = body.read_all(incoming.body, 0)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

fn receive_exact(
  socket: transport.Socket,
  remaining: Int,
  reversed: List(BitArray),
) -> Result(BitArray, transport.Error) {
  case remaining {
    0 -> Ok(reversed |> list.reverse |> bit_array.concat)
    _ ->
      case transport.read(socket, remaining, 1000) {
        Error(failure) -> Error(failure)
        Ok(transport.ReadEnd(_)) -> Error(transport.Closed)
        Ok(transport.ReadData(bytes, socket)) ->
          receive_exact(socket, remaining - bit_array.byte_size(bytes), [
            bytes,
            ..reversed
          ])
      }
  }
}

fn receive_exact_with_socket(
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
          receive_exact_with_socket(
            socket,
            remaining - bit_array.byte_size(bytes),
            [bytes, ..reversed],
          )
      }
  }
}

fn signalled_body(pulled: process.Subject(Nil)) -> body.Pull {
  body.pull(fn(_) {
    process.send(pulled, Nil)
    Ok(body.PullData(
      <<"hello":utf8>>,
      body.pull(fn(_) { Ok(body.PullEnd([])) }),
    ))
  })
}

fn pull_chunks(values: List(BitArray), trailers: body.Headers) -> body.Pull {
  body.pull(fn(_) {
    case values {
      [] -> Ok(body.PullEnd(trailers))
      [first, ..rest] -> Ok(body.PullData(first, pull_chunks(rest, trailers)))
    }
  })
}

fn collect_body(
  incoming: body.Body,
  maximum_bytes: Int,
  reversed: List(BitArray),
) -> Result(#(BitArray, body.Headers), error.Error) {
  case body.read(incoming, maximum_bytes) {
    Error(failure) -> Error(failure)
    Ok(body.Data(bytes, next)) ->
      case bit_array.byte_size(bytes) <= maximum_bytes {
        True -> collect_body(next, maximum_bytes, [bytes, ..reversed])
        False -> Error(error.new(error.Service))
      }
    Ok(body.Done(completed)) -> {
      let trailers = case body.trailers(completed) {
        Some(trailers) -> trailers
        None -> []
      }
      Ok(#(reversed |> list.reverse |> bit_array.concat, trailers))
    }
  }
}
