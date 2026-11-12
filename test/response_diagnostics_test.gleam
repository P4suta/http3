import gleam/bit_array
import gleam/erlang/process
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleam/result
import gleeunit
import http/body
import http/context
import http/diagnostics
import http/error
import http/internal/http1/exchange as h1
import http/internal/http2/exchange as h2
import http/server
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn http1_final_trailers_complete_the_correlated_exchange_test() -> Nil {
  live_transfer(context.Http1, False)
}

pub fn http2_final_trailers_complete_the_correlated_exchange_test() -> Nil {
  live_transfer(context.Http2, False)
}

pub fn http1_rejected_final_trailers_are_failed_after_source_eof_test() -> Nil {
  live_transfer(context.Http1, True)
}

pub fn http2_rejected_final_trailers_are_failed_after_source_eof_test() -> Nil {
  live_transfer(context.Http2, True)
}

fn live_transfer(protocol: context.Protocol, invalid_trailers: Bool) -> Nil {
  let terminal = process.new_subject()
  let read_done = process.new_subject()
  let released = process.new_subject()
  let started = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 16,
      sink_timeout_milliseconds: 1000,
      sink: fn(record) {
        case record.event {
          diagnostics.RequestStarted(id, observed_protocol) ->
            process.send(started, #(id, observed_protocol, record.sequence))
          diagnostics.ResponseBodyReadFinished(id, _, _) ->
            process.send(read_done, #(id, record.sequence))
          diagnostics.RequestFinished(id, _, status, _) ->
            process.send(terminal, #(id, Ok(status), record.sequence))
          diagnostics.RequestFailed(id, _, failure, _) ->
            process.send(terminal, #(
              id,
              Error(error.kind(failure)),
              record.sequence,
            ))
          diagnostics.RequestReleased(id, _, cleanup, _) ->
            process.send(released, #(
              id,
              result.map_error(cleanup, error.kind),
              record.sequence,
            ))
          _ -> Nil
        }
        Ok(Nil)
      },
    )
  let trailers = case invalid_trailers {
    True -> [#("bad\nname", "rejected")]
    False -> [#("x-checksum", "complete")]
  }
  let assert Ok(executor) =
    server.start(server.with_diagnostics(server.defaults(), reporter), fn(_, _) {
      let assert Ok(outgoing) =
        body.from_pull(
          body.pull(fn(_) {
            Ok(body.PullData(
              <<"chunk":utf8>>,
              body.pull(fn(_) { Ok(body.PullEnd(trailers)) }),
            ))
          }),
          None,
          None,
          fn() { Nil },
        )
      Ok(response.new(200) |> response.set_body(outgoing))
    })
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let listener_result = case protocol {
    context.Http1 ->
      server.listen_http1(
        executor,
        <<127, 0, 0, 1>>,
        0,
        server.http1_defaults() |> server.allow_http1_cleartext,
      )
    context.Http2 ->
      server.listen_http2_tls(
        executor,
        <<127, 0, 0, 1>>,
        0,
        server.http2_defaults(),
        certificate,
        private_key,
        "localhost",
      )
    context.Http3 -> Error(error.new(error.Service))
  }
  let assert Ok(listener) = listener_result
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: case protocol {
        context.Http1 -> gleam_http.Http
        _ -> gleam_http.Https
      },
      host: case protocol {
        context.Http1 -> "127.0.0.1"
        _ -> "localhost"
      },
      port: Some(port),
      path: "/",
      query: None,
    )
  let received = case protocol {
    context.Http1 -> h1.run(outgoing, h1.defaults())
    context.Http2 -> {
      h2.run(outgoing, h2.with_ca_certificates(h2.defaults(), [ca_certificate]))
      |> result.try(fn(outcome) {
        case outcome {
          h2.Http2Response(response) -> Ok(response)
          _ -> Error(error.new(error.Service))
        }
      })
    }
    context.Http3 -> Error(error.new(error.Service))
  }
  let client_observation =
    received
    |> result.try(fn(incoming) { body.read_all(incoming.body, 1024) })
    |> result.map(fn(collected) {
      bit_array.byte_size(collected.0) == 5 && collected.1 == trailers
    })
    |> result.map_error(error.kind)
  let assert Ok(#(start_id, observed_protocol, start_sequence)) =
    process.receive(started, within: 1000)
  let assert Ok(#(read_id, read_sequence)) =
    process.receive(read_done, within: 1000)
  let assert Ok(#(terminal_id, outcome, final_sequence)) =
    process.receive(terminal, within: 1000)
  let assert Ok(#(release_id, cleanup, release_sequence)) =
    process.receive(released, within: 1000)
  assert server.stop_listener(listener) == Ok(Nil)
  assert server.stop(executor) == Ok(Nil)
  assert diagnostics.stop(reporter) == Ok(Nil)
  assert start_id == read_id
    && read_id == terminal_id
    && terminal_id == release_id
  assert observed_protocol == protocol
  assert start_sequence < read_sequence && read_sequence < final_sequence
  assert final_sequence < release_sequence
  assert cleanup == Ok(Nil)
  assert process.receive(terminal, within: 0) == Error(Nil)
  case invalid_trailers {
    False -> {
      assert outcome == Ok(200)
      assert client_observation == Ok(True)
    }
    True -> {
      let expected_layer = case protocol {
        context.Http1 -> error.Http1
        _ -> error.Http2
      }
      assert outcome == Error(error.Protocol(expected_layer))
      assert result.is_error(client_observation)
    }
  }
}
