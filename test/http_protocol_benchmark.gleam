//// Public-API performance workload.
//// Values returned across the observation boundary contain only bounded counters, timings and typed failure stages.

import gleam/bit_array
import gleam/bool
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import http/body
import http/client
import http/context
import http/error
import http/server
import http_test_support

pub type Failure {
  Operation(stage: Int, cause: error.Error)
  Invalid(stage: Int)
  UnexpectedResponse(status: Int, server_phase: Int)
  CleanupFailed(primary: option.Option(Failure), cause: Failure)
}

pub type Latency {
  Latency(headers_microseconds: Int, complete_microseconds: Int)
}

pub type Sample {
  Sample(
    protocol: Int,
    requests: Int,
    payload_bytes: Int,
    server_completed: Int,
    server_rejected: Int,
    accepted_connections: option.Option(Int),
    elapsed_microseconds: Int,
    latencies: List(Latency),
  )
}

type Counter

@external(erlang, "http_protocol_benchmark_ffi", "counter")
fn counter() -> Counter

@external(erlang, "http_protocol_benchmark_ffi", "record")
fn record(counter: Counter, phase: Int) -> Nil

@external(erlang, "http_protocol_benchmark_ffi", "counts")
fn counts(counter: Counter) -> #(Int, Int, Int)

@external(erlang, "http_protocol_benchmark_ffi", "payload")
fn payload(bytes: Int) -> BitArray

@external(erlang, "http_protocol_benchmark_ffi", "valid_payload")
fn valid_payload(bytes: BitArray) -> Bool

@external(erlang, "http_protocol_benchmark_ffi", "now")
fn now() -> Int

@external(erlang, "http_protocol_benchmark_ffi", "finally")
fn finally(
  run: fn() -> Result(value, Failure),
  cleanup: fn() -> Result(Nil, Failure),
) -> Result(value, Failure)

const trailers = [#("x-benchmark-complete", "yes")]

pub fn run(
  protocol protocol: Int,
  requests requests: Int,
  payload_bytes payload_bytes: Int,
) -> Result(Sample, Failure) {
  run_source(protocol:, requests:, payload_bytes:, streaming: False)
}

fn run_source(
  protocol protocol: Int,
  requests requests: Int,
  payload_bytes payload_bytes: Int,
  streaming streaming: Bool,
) -> Result(Sample, Failure) {
  use _ <- result.try(check(
    protocol >= 1
      && protocol <= 3
      && requests >= 1
      && requests <= 1000
      && payload_bytes >= 0
      && payload_bytes <= 1_048_576,
    1,
  ))
  let #(certificate, key, ca) = http_test_support.server_credentials()
  let counter = counter()
  let handler = fn(incoming: request.Request(body.Body), metadata) {
    let valid_metadata =
      context.protocol(metadata) == server_protocol(protocol)
      && context.tls_identity(metadata)
      == context.TlsIdentity("localhost", None)
      && incoming.method == http.Post
    let received =
      verify_body(source: incoming.body, expected: payload_bytes, seen: 0)
    let phase = case valid_metadata, received {
      True, Ok(Nil) -> 0
      False, _ -> 18
      _, Error(Operation(stage, _)) | _, Error(Invalid(stage)) -> stage
      _, Error(UnexpectedResponse(_, _)) -> 8
      _, Error(CleanupFailed(_, _)) -> 21
    }
    record(counter, phase)
    case phase {
      0 -> {
        use outgoing <- result.try(benchmark_body(
          bytes: payload_bytes,
          streaming:,
        ))
        Ok(response.Response(
          status: 200,
          headers: [#("trailer", "x-benchmark-complete")],
          body: outgoing,
        ))
      }
      _ -> Error(error.new(error.Service))
    }
  }
  use running <- result.try(stage(server.start(server.defaults(), handler), 2))
  finally(
    fn() {
      use listener <- result.try(stage(
        listen(running:, protocol:, certificate:, key:),
        3,
      ))
      finally(
        fn() {
          let context.Endpoint(_, port) = server.listener_endpoint(listener)
          use configuration <- result.try(stage(
            client.with_pool_limits(
              client.defaults()
                |> client.with_ca_certificates([ca])
                |> client.without_retries,
              client.PoolLimits(1, 1, 30_000),
            ),
            4,
          ))
          let configuration = case protocol {
            3 ->
              client.with_https_record_resolver(
                configuration,
                fn(_, origin_port, _) {
                  Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
                },
              )
            _ -> client.without_protocol_discovery(configuration)
          }
          use connection <- result.try(stage(client.start(configuration), 5))
          finally(
            fn() {
              let started = now()
              use latencies <- result.try(
                exchange_many(
                  connection:,
                  counter:,
                  protocol:,
                  port:,
                  remaining: requests,
                  bytes: payload_bytes,
                  streaming:,
                  reversed: [],
                ),
              )
              let elapsed = now() - started
              let #(completed, rejected, _) = counts(counter)
              use _ <- result.try(check(
                completed == requests && rejected == 0,
                12,
              ))
              use accepted <- result.try(connection_count(listener, protocol:))
              Ok(Sample(
                protocol,
                requests,
                payload_bytes,
                completed,
                rejected,
                accepted,
                elapsed,
                latencies,
              ))
            },
            fn() { stage(client.close(connection), 13) },
          )
        },
        fn() { stage(server.stop_listener(listener), 14) },
      )
    },
    fn() { stage(server.stop(running), 15) },
  )
}

fn listen(
  running running: server.Server,
  protocol protocol: Int,
  certificate certificate: BitArray,
  key key: BitArray,
) -> Result(server.Listener, error.Error) {
  case protocol {
    1 ->
      server.listen_http1_tls(
        running,
        <<127, 0, 0, 1>>,
        0,
        server.http1_defaults(),
        certificate,
        key,
        "localhost",
      )
    2 ->
      server.listen_http2_tls(
        running,
        <<127, 0, 0, 1>>,
        0,
        server.http2_defaults(),
        certificate,
        key,
        "localhost",
      )
    _ -> {
      use configuration <- result.try(server.http3_defaults(
        certificate,
        key,
        "localhost",
      ))
      server.listen_http3(running, <<127, 0, 0, 1>>, 0, configuration)
    }
  }
}

fn exchange_many(
  connection connection: client.Client,
  counter counter: Counter,
  protocol protocol: Int,
  port port: Int,
  remaining remaining: Int,
  bytes bytes: Int,
  streaming streaming: Bool,
  reversed reversed: List(Latency),
) -> Result(List(Latency), Failure) {
  case remaining {
    0 -> Ok(list.reverse(reversed))
    _ -> {
      use source <- result.try(stage(benchmark_body(bytes:, streaming:), 19))
      let outgoing =
        request.new()
        |> request.set_method(http.Post)
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_header("trailer", "x-benchmark-complete")
        |> request.set_body(source)
      let started = now()
      use exchange <- result.try(stage(client.exchange(connection, outgoing), 6))
      let headers_elapsed = now() - started
      let response = client.response(exchange)
      use latency <- result.try(
        finally(
          fn() {
            use _ <- result.try(check(
              client.selected_protocol(exchange) == client_protocol(protocol),
              7,
            ))
            let #(_, _, server_phase) = counts(counter)
            use _ <- result.try(case response.status == 200 {
              True -> Ok(Nil)
              False -> Error(UnexpectedResponse(response.status, server_phase))
            })
            use _ <- result.try(verify_body(
              source: response.body,
              expected: bytes,
              seen: 0,
            ))
            let completed = now() - started
            Ok(Latency(headers_elapsed, completed))
          },
          fn() {
            body.cancel(response.body)
            Ok(Nil)
          },
        ),
      )
      exchange_many(
        connection:,
        counter:,
        protocol:,
        port:,
        remaining: remaining - 1,
        bytes:,
        streaming:,
        reversed: [latency, ..reversed],
      )
    }
  }
}

fn benchmark_body(
  bytes bytes: Int,
  streaming streaming: Bool,
) -> Result(body.Body, error.Error) {
  use <- bool.lazy_guard(!streaming, fn() {
    Ok(body.from_bytes_with_trailers(payload(bytes), trailers))
  })
  body.from_pull(benchmark_pull(bytes), Some(bytes), None, fn() { Nil })
}

fn benchmark_pull(remaining: Int) -> body.Pull {
  body.pull(fn(maximum) {
    case remaining {
      0 -> Ok(body.PullEnd(trailers))
      _ -> {
        let count = case remaining <= maximum {
          True -> remaining
          False -> maximum
        }
        Ok(body.PullData(payload(count), benchmark_pull(remaining - count)))
      }
    }
  })
}

fn verify_body(
  source source: body.Body,
  expected expected: Int,
  seen seen: Int,
) -> Result(Nil, Failure) {
  use event <- result.try(stage(body.read(source, 8192), 9))
  case event {
    body.Done(completed) ->
      check(seen == expected && body.trailers(completed) == Some(trailers), 10)
    body.Data(bytes, next) -> {
      let size = bit_array.byte_size(bytes)
      use _ <- result.try(check(
        size > 0
          && size <= 8192
          && seen + size <= expected
          && valid_payload(bytes),
        11,
      ))
      verify_body(source: next, expected:, seen: seen + size)
    }
  }
}

fn connection_count(
  listener: server.Listener,
  protocol protocol: Int,
) -> Result(option.Option(Int), Failure) {
  case protocol {
    1 -> {
      use snapshot <- result.try(stage(
        server.http1_listener_snapshot(listener),
        16,
      ))
      use _ <- result.try(check(
        snapshot.consistent
          && snapshot.started_connections == 1
          && snapshot.connection_failures == 0,
        17,
      ))
      Ok(Some(snapshot.accepted_connections))
    }
    2 -> {
      use snapshot <- result.try(stage(
        server.http2_listener_snapshot(listener),
        16,
      ))
      use _ <- result.try(check(
        snapshot.consistent
          && snapshot.started_connections == 1
          && snapshot.connection_failures == 0,
        17,
      ))
      Ok(Some(snapshot.accepted_connections))
    }
    _ -> Ok(None)
  }
}

fn server_protocol(protocol: Int) -> context.Protocol {
  case protocol {
    1 -> context.Http1
    2 -> context.Http2
    _ -> context.Http3
  }
}

fn client_protocol(protocol: Int) -> client.Protocol {
  case protocol {
    1 -> client.Http1
    2 -> client.Http2
    _ -> client.Http3
  }
}

fn stage(
  outcome: Result(value, error.Error),
  stage: Int,
) -> Result(value, Failure) {
  result.map_error(outcome, fn(cause) { Operation(stage, cause) })
}

fn check(valid: Bool, stage: Int) -> Result(Nil, Failure) {
  use <- bool.guard(valid, Ok(Nil))
  Error(Invalid(stage))
}

pub fn benchmark_rejects_incorrect_body_and_completion_test() -> Nil {
  let correct =
    verify_body(
      source: body.from_bytes_with_trailers(<<90, 90>>, trailers),
      expected: 2,
      seen: 0,
    )
  assert correct == Ok(Nil)
  let cases = [
    #(body.from_bytes_with_trailers(<<90>>, trailers), 2),
    #(body.from_bytes_with_trailers(<<90, 90, 90>>, trailers), 2),
    #(
      body.from_bytes_with_trailers(
        <<"private-benchmark-marker":utf8>>,
        trailers,
      ),
      24,
    ),
    #(body.from_bytes(<<90, 90>>), 2),
  ]
  list.each(cases, fn(pair) {
    let #(source, expected) = pair
    let rejected = result.is_error(verify_body(source:, expected:, seen: 0))
    body.cancel(source)
    assert rejected
  })
}

pub fn benchmark_input_limits_are_finite_test() -> Nil {
  list.each(
    [
      #(0, 1, 1),
      #(4, 1, 1),
      #(1, 0, 1),
      #(1, 1001, 1),
      #(1, 1, -1),
      #(1, 1, 1_048_577),
    ],
    fn(arguments) {
      let #(protocol, requests, bytes) = arguments
      assert run(protocol:, requests:, payload_bytes: bytes)
        == Error(Invalid(1))
    },
  )
}

pub fn sequential_responses_return_server_admission_on_every_protocol_test() -> Nil {
  // Cross the default server's 64-slot capacity using one connection.
  // A completed response must return its reservation before capacity accumulates.
  let outcomes =
    list.map([1, 2, 3], fn(protocol) {
      let completed =
        run(protocol:, requests: 65, payload_bytes: 1024)
        |> result.map(fn(sample) {
          sample.server_completed == 65 && sample.server_rejected == 0
        })
        |> result.unwrap(False)
      #(protocol, completed)
    })
  assert outcomes == [#(1, True), #(2, True), #(3, True)]
}

pub fn benchmark_all_public_protocols_complete_streaming_and_trailers_test() -> Nil {
  list.each([1, 2, 3], fn(protocol) {
    let outcome = run(protocol:, requests: 3, payload_bytes: 16_385)
    let #(observed, stage) = case outcome {
      Ok(sample) -> #(
        sample.server_completed == 3
          && sample.server_rejected == 0
          && list.length(sample.latencies) == 3
          && sample.elapsed_microseconds > 0
          && list.all(sample.latencies, fn(latency) {
          latency.headers_microseconds >= 0
          && latency.complete_microseconds >= latency.headers_microseconds
        }),
        0,
      )
      Error(Operation(stage, _)) | Error(Invalid(stage)) -> #(False, stage)
      Error(UnexpectedResponse(_, _)) -> #(False, 8)
      Error(CleanupFailed(_, _)) -> #(False, 21)
    }
    assert #(protocol, observed, stage) == #(protocol, True, 0)
  })
}

pub fn known_empty_and_streamed_sources_keep_trailers_on_every_protocol_test() -> Nil {
  list.each([1, 2, 3], fn(protocol) {
    list.each([#(0, False), #(0, True), #(16_385, True)], fn(source) {
      let #(bytes, streaming) = source
      let outcome =
        run_source(protocol:, requests: 2, payload_bytes: bytes, streaming:)
      let observed =
        outcome
        |> result.map(fn(sample) {
          sample.server_completed == 2 && sample.server_rejected == 0
        })
        |> result.unwrap(False)
      assert #(protocol, bytes, streaming, observed)
        == #(protocol, bytes, streaming, True)
    })
  })
}
