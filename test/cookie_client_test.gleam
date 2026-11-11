import gleam/bit_array
import gleam/erlang/process
import gleam/http.{Get, Http}
import gleam/http/request.{type Request}
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleeunit
import gleeunit/should
import http/client
import http/client_store
import http/internal/transport
import http_test_support

type CookiePersistenceMutation {
  CookieUpsert
  CookieRemoval(key_matches: Bool)
}

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn cookie_enabled_client_processes_set_cookie_on_error_status_test() -> Nil {
  let listener = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000) |> should.be_ok
  let #(_, port) = transport.local_endpoint(listener) |> should.be_ok
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(first, 4096, 1000))
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 500 Internal Server Error\r\n":utf8,
          "Set-Cookie: status=retained; Path=/; Max-Age=60\r\n":utf8,
          "Content-Length: 0\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(first))

      use second <- result.try(transport.accept(listener, 1000))
      use read <- result.try(transport.read(second, 4096, 1000))
      let #(bytes, second) =
        case read {
          transport.ReadData(bytes, second) -> Ok(#(bytes, second))
          unexpected -> Error(unexpected)
        }
        |> should.be_ok
      use _ <- result.try(
        transport.send(second, <<
          "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(second))
      Ok(bytes)
    })
  let config =
    client.defaults()
    |> client.allow_plain_http
    |> client.enable_cookies(client.StoreLimits(8, 4096))
    |> should.be_ok
  let running = client.start(config) |> should.be_ok
  let first = client.fetch(running, request_for(port, [])) |> should.be_ok
  assert first.status == 500
  let _second_response =
    client.fetch(running, request_for(port, [])) |> should.be_ok

  let bytes = http_test_support.await_task(server_task) |> should.be_ok
  let text = bit_array.to_string(bytes) |> should.be_ok
  assert string.contains(text, "cookie: status=retained\r\n")
  let Nil = client.close(running) |> should.be_ok
  let Nil = transport.stop(listener) |> should.be_ok
  Nil
}

pub fn disabled_cookie_policy_ignores_set_cookie_test() -> Nil {
  let listener = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000) |> should.be_ok
  let #(_, port) = transport.local_endpoint(listener) |> should.be_ok
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(first, 4096, 1000))
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Set-Cookie: disabled=ignored; Path=/; Max-Age=60\r\n":utf8,
          "Content-Length: 0\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(first))

      use second <- result.try(transport.accept(listener, 1000))
      use read <- result.try(transport.read(second, 4096, 1000))
      let #(bytes, second) =
        case read {
          transport.ReadData(bytes, second) -> Ok(#(bytes, second))
          unexpected -> Error(unexpected)
        }
        |> should.be_ok
      use _ <- result.try(
        transport.send(second, <<
          "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(second))
      Ok(bytes)
    })
  let running =
    client.start(client.defaults() |> client.allow_plain_http) |> should.be_ok
  let _first_response =
    client.fetch(running, request_for(port, [])) |> should.be_ok
  let _second_response =
    client.fetch(running, request_for(port, [])) |> should.be_ok

  let bytes = http_test_support.await_task(server_task) |> should.be_ok
  let text = bit_array.to_string(bytes) |> should.be_ok
  assert !string.contains(text, "cookie:")
  let Nil = client.close(running) |> should.be_ok
  let Nil = transport.stop(listener) |> should.be_ok
  Nil
}

pub fn cookie_enabled_client_emits_at_most_one_cookie_field_test() -> Nil {
  let listener = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000) |> should.be_ok
  let #(_, port) = transport.local_endpoint(listener) |> should.be_ok
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use read <- result.try(transport.read(socket, 4096, 1000))
      let #(bytes, socket) =
        case read {
          transport.ReadData(bytes, socket) -> Ok(#(bytes, socket))
          unexpected -> Error(unexpected)
        }
        |> should.be_ok
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(bytes)
    })
  let config =
    client.defaults()
    |> client.allow_plain_http
    |> client.enable_cookies(client.StoreLimits(8, 4096))
    |> should.be_ok
  let running = client.start(config) |> should.be_ok
  let _response =
    client.fetch(
      running,
      request_for(port, [#("cookie", "first=1"), #("cookie", "second=2")]),
    )
    |> should.be_ok

  let bytes = http_test_support.await_task(server_task) |> should.be_ok
  let text = bit_array.to_string(bytes) |> should.be_ok
  assert text
    |> string.lowercase
    |> string.split(on: "cookie:")
    |> list.length
    == 2
  let Nil = client.close(running) |> should.be_ok
  let Nil = transport.stop(listener) |> should.be_ok
  Nil
}

pub fn session_cookie_removes_persisted_record_instead_of_upserting_test() -> Nil {
  let mutations = process.new_subject()
  let adapter =
    client_store.new(
      fn(_, _) {
        Ok([
          client_store.CookieRecord(
            key: session_cookie_key(),
            name: "session",
            value: "persisted",
            domain: "127.0.0.1",
            path: "/",
            host_only: True,
            secure: False,
            expires_in_milliseconds: 60_000,
            age_milliseconds: 0,
          ),
        ])
      },
      fn(_, _, _) {
        process.send(mutations, CookieUpsert)
        Ok(Nil)
      },
      fn(_, key, _) {
        process.send(mutations, cookie_removal_observation(key))
        Ok(Nil)
      },
      250,
    )
    |> should.be_ok
  let listener = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000) |> should.be_ok
  let #(_, port) = transport.local_endpoint(listener) |> should.be_ok
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(first, 4096, 1000))
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Set-Cookie: session=live; Path=/\r\n":utf8,
          "Content-Length: 0\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(first))

      use second <- result.try(transport.accept(listener, 1000))
      use read <- result.try(transport.read(second, 4096, 1000))
      let #(bytes, second) =
        case read {
          transport.ReadData(bytes, second) -> Ok(#(bytes, second))
          unexpected -> Error(unexpected)
        }
        |> should.be_ok
      use _ <- result.try(
        transport.send(second, <<
          "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(second))
      Ok(bytes)
    })
  let config =
    client.defaults()
    |> client.allow_plain_http
    |> client.enable_cookies(client.StoreLimits(8, 4096))
    |> should.be_ok
  let running =
    config
    |> client.with_cookie_store_adapter(adapter)
    |> client.start
    |> should.be_ok
  let first = client.fetch(running, request_for(port, []))
  let second = client.fetch(running, request_for(port, []))
  let server_result = http_test_support.await_task(server_task)
  let mutation = process.receive(mutations, within: 1000)
  let extra_mutation = process.receive(mutations, within: 0)

  let Nil = client.close(running) |> should.be_ok
  let Nil = transport.stop(listener) |> should.be_ok
  let _first_response = first |> should.be_ok
  let _second_response = second |> should.be_ok
  let bytes = server_result |> should.be_ok
  let text = bit_array.to_string(bytes) |> should.be_ok
  let replacement_was_sent = string.contains(text, "cookie: session=live\r\n")
  let stale_value_was_not_sent =
    !string.contains(text, "cookie: session=persisted\r\n")
  assert replacement_was_sent
  assert stale_value_was_not_sent
  case mutation |> should.be_ok {
    CookieRemoval(True) -> Ok(Nil)
    unexpected -> Error(unexpected)
  }
  |> should.be_ok
  assert extra_mutation == Error(Nil)
  Nil
}

pub fn persistence_mutation_observation_redacts_cookie_key_test() -> Nil {
  assert cookie_removal_observation(session_cookie_key()) == CookieRemoval(True)
  assert cookie_removal_observation("different") == CookieRemoval(False)
}

fn cookie_removal_observation(key: String) -> CookiePersistenceMutation {
  CookieRemoval(key_matches: key == session_cookie_key())
}

fn session_cookie_key() -> String {
  "127.0.0.1\u{0000}/\u{0000}session"
}

fn request_for(
  port: Int,
  headers: List(#(String, String)),
) -> Request(BitArray) {
  request.Request(
    method: Get,
    headers:,
    body: <<>>,
    scheme: Http,
    host: "127.0.0.1",
    port: Some(port),
    path: "/cookie",
    query: None,
  )
}
