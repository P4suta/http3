import gleam/bit_array
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleeunit/should
import http3/client
import http3/failure as runtime_failure
import http3/server
import http3/transport
import http3_test_support

const concurrent_connections = 32

const sequential_requests = 1200

type ClientTrace {
  ClientTrace(
    total: Int,
    succeeded: Int,
    failures: List(#(Int, BurstFailureCause)),
    unexpected_responses: List(#(Int, Int, Int)),
  )
}

type BurstServerPhase {
  BurstAccept
  BurstReadBody
  BurstRespond
}

type BurstFailureCause {
  BurstResolutionFailure
  BurstSocketFailure(runtime_failure.SocketOperation)
  BurstTlsFailure(runtime_failure.Origin)
  BurstQuicFailure(runtime_failure.Origin, Option(Int))
  BurstHttp3Failure(runtime_failure.Origin, Option(Int))
  BurstTimeoutFailure(runtime_failure.TimeoutPhase)
  BurstCancellationFailure
  BurstClosedFailure(runtime_failure.Origin, Option(Int))
  BurstLimitFailure(runtime_failure.Resource, Int)
  BurstOverloadFailure(runtime_failure.Resource)
  BurstPublicContractFailure
}

type BurstServerFailure {
  BurstServerFailure(
    completed: Int,
    remaining: Int,
    phase: BurstServerPhase,
    cause: BurstFailureCause,
  )
}

type BurstTrace {
  BurstTrace(
    server: Result(Nil, BurstServerFailure),
    drain: Result(server.DrainResult, BurstFailureCause),
    stop: Result(server.StopResult, BurstFailureCause),
    clients: ClientTrace,
  )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn drains_bursty_concurrent_handshakes_over_real_udp_test() -> Nil {
  http3_test_support.with_qlog_directory_expect(
    run_bursty_handshake_fixture,
    concurrent_connections * 2,
  )
}

fn run_bursty_handshake_fixture(qlog_directory: String) -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let qlog = transport.qlog(qlog_directory) |> should.be_ok
  let server_configuration =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_qlog(qlog)
  let server_configuration =
    server.with_timeout(server_configuration, 10_000) |> should.be_ok
  let listener = server.start(server_configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let client_configuration =
    client.new()
    |> client.with_ca_certificate(ca_certificate)
    |> should.be_ok
    |> client.with_qlog(qlog)
    |> client.with_timeout(10_000)
    |> should.be_ok
  let tasks =
    int.range(
      from: 0,
      to: concurrent_connections,
      with: [],
      run: fn(tasks, index) {
        let task =
          http3_test_support.start_task(fn() {
            let outbound =
              request.new()
              |> request.set_host("localhost")
              |> request.set_port(port)
              |> request.set_path("/burst")
              |> request.set_body(<<>>)
            #(index, client.send(client_configuration, outbound))
          })
        [task, ..tasks]
      },
    )
  let server_result = serve_requests(listener, concurrent_connections)
  let drain_result =
    server.graceful_stop(listener) |> trace_burst_server_outcome
  let client_results = list.map(tasks, http3_test_support.await_task)
  let stop_result = server.stop(listener) |> trace_burst_server_outcome
  let trace =
    BurstTrace(
      server: server_result,
      drain: drain_result,
      stop: stop_result,
      clients: summarize_client_results(client_results),
    )
  assert trace
    == BurstTrace(
      server: Ok(Nil),
      drain: Ok(server.Drained),
      stop: Ok(server.AlreadyStopped),
      clients: ClientTrace(
        total: concurrent_connections,
        succeeded: concurrent_connections,
        failures: [],
        unexpected_responses: [],
      ),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retires_completed_requests_on_one_reused_connection_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let server_configuration =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_timeout(10_000)
    |> should.be_ok
  let listener = server.start(server_configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let ready = http3_test_support.new_signal()
  let hold_connection = http3_test_support.new_signal()
  let client_task =
    http3_test_support.start_task(fn() {
      let configuration =
        client.new()
        |> client.with_ca_certificate(ca_certificate)
        |> should.be_ok
        |> client.with_timeout(10_000)
        |> should.be_ok
      let connection =
        client.connect(configuration, "localhost", port) |> should.be_ok
      assert send_reused_requests(
          connection: connection,
          port: port,
          remaining: sequential_requests,
        )
        == Ok(True)
      let client_resources =
        client.resource_state_stats(connection) |> should.be_ok
      http3_test_support.checkpoint(ready)
      http3_test_support.checkpoint(hold_connection)
      #(client_resources, client.close(connection))
    })

  let last_request =
    serve_reused_requests(listener, sequential_requests) |> should.be_ok
  http3_test_support.release_signal(ready)
  let #(
    active,
    retained_terminals,
    core_handles,
    runtime_handles,
    transport_streams,
    protocol_inputs,
    transactions,
    push_transactions,
    blocked_streams,
  ) = await_bounded_request_state(last_request, 200)

  assert active <= 16
  assert retained_terminals <= 1024
  assert core_handles <= 16
  assert runtime_handles <= 16
  assert transport_streams <= 16
  assert protocol_inputs <= 8
  assert transactions <= 16
  assert push_transactions == 0
  assert blocked_streams == 0
  assert server.cancel(last_request) == Ok(server.AlreadyCompleted)

  http3_test_support.release_signal(hold_connection)
  let #(client_resources, client_close) =
    http3_test_support.await_task(client_task)
  let #(
    client_active,
    client_terminals,
    client_core_handles,
    client_runtime_handles,
    client_transport_streams,
    client_protocol_inputs,
    client_transactions,
    client_push_transactions,
    client_blocked_streams,
  ) = client_resources
  assert client_active <= 16
  assert client_terminals <= 1024
  assert client_core_handles <= 16
  assert client_runtime_handles <= 16
  assert client_transport_streams <= 16
  assert client_protocol_inputs <= 8
  assert client_transactions <= 16
  assert client_push_transactions == 0
  assert client_blocked_streams == 0
  assert client_close == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

fn send_reused_requests(
  connection connection: client.Connection,
  port port: Int,
  remaining remaining: Int,
) -> Result(Bool, client.Error) {
  case remaining {
    0 -> Ok(True)
    _ -> {
      let outbound =
        request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_path("/retirement")
        |> request.set_body(Nil)
      use stream <- result.try(client.open_stream(connection, outbound))
      use _ <- result.try(client.finish(stream))
      use valid <- result.try(collect_empty_response(stream, False))
      case valid {
        False -> Ok(False)
        True ->
          send_reused_requests(
            connection: connection,
            port: port,
            remaining: remaining - 1,
          )
      }
    }
  }
}

fn collect_empty_response(
  stream: client.Stream,
  valid_status: Bool,
) -> Result(Bool, client.Error) {
  use event <- result.try(client.next_event(stream))
  case event {
    client.InformationalResponse(_, _) ->
      collect_empty_response(stream, valid_status)
    client.Response(status, _) -> collect_empty_response(stream, status == 204)
    client.Data(bytes) ->
      collect_empty_response(stream, valid_status && bytes == <<>>)
    client.Trailers(_) -> collect_empty_response(stream, valid_status)
    client.End -> Ok(valid_status)
  }
}

fn serve_reused_requests(
  listener: server.Listener,
  remaining: Int,
) -> Result(server.Request, server.Error) {
  use incoming <- result.try(server.accept(listener))
  use _ <- result.try(server.read_body(incoming))
  use _ <- result.try(server.respond(incoming, 204, [], <<>>))
  case remaining {
    1 -> Ok(incoming)
    _ -> serve_reused_requests(listener, remaining - 1)
  }
}

fn await_bounded_request_state(
  request: server.Request,
  attempts: Int,
) -> #(Int, Int, Int, Int, Int, Int, Int, Int, Int) {
  let stats = server.request_state_stats(request) |> should.be_ok
  let #(
    active,
    _,
    core_handles,
    runtime_handles,
    transport_streams,
    protocol_inputs,
    transactions,
    push_transactions,
    blocked_streams,
  ) = stats
  case
    {
      active <= 16
      && core_handles <= 16
      && runtime_handles <= 16
      && transport_streams <= 16
      && protocol_inputs <= 8
      && transactions <= 16
      && push_transactions == 0
      && blocked_streams == 0
    }
    || attempts <= 0
  {
    True -> stats
    False -> {
      http3_test_support.pause_milliseconds(10)
      await_bounded_request_state(request, attempts - 1)
    }
  }
}

fn summarize_client_results(
  results: List(#(Int, Result(response.Response(BitArray), client.Error))),
) -> ClientTrace {
  summarize_client_result_entries(
    results: results,
    total: 0,
    succeeded: 0,
    failures: [],
    unexpected: [],
  )
}

fn summarize_client_result_entries(
  results results: List(
    #(Int, Result(response.Response(BitArray), client.Error)),
  ),
  total total: Int,
  succeeded succeeded: Int,
  failures failures: List(#(Int, BurstFailureCause)),
  unexpected unexpected: List(#(Int, Int, Int)),
) -> ClientTrace {
  case results {
    [] ->
      ClientTrace(
        total:,
        succeeded:,
        failures: list.reverse(failures),
        unexpected_responses: list.reverse(unexpected),
      )
    [#(index, Error(failure)), ..rest] ->
      summarize_client_result_entries(
        results: rest,
        total: total + 1,
        succeeded: succeeded,
        failures: [#(index, client_burst_failure(failure)), ..failures],
        unexpected: unexpected,
      )
    [#(_, Ok(response)), ..rest]
      if response.status == 204 && response.body == <<>>
    ->
      summarize_client_result_entries(
        results: rest,
        total: total + 1,
        succeeded: succeeded + 1,
        failures: failures,
        unexpected: unexpected,
      )
    [#(index, Ok(response)), ..rest] ->
      summarize_client_result_entries(
        results: rest,
        total: total + 1,
        succeeded: succeeded,
        failures: failures,
        unexpected: [
          #(index, response.status, bit_array.byte_size(response.body)),
          ..unexpected
        ],
      )
  }
}

fn serve_requests(
  listener: server.Listener,
  remaining: Int,
) -> Result(Nil, BurstServerFailure) {
  case remaining {
    0 -> Ok(Nil)
    _ -> {
      let completed = concurrent_connections - remaining
      use incoming <- result.try(trace_burst_server_operation(
        outcome: server.accept(listener),
        completed:,
        remaining:,
        phase: BurstAccept,
      ))
      use _ <- result.try(trace_burst_server_operation(
        outcome: server.read_body(incoming),
        completed:,
        remaining:,
        phase: BurstReadBody,
      ))
      use _ <- result.try(trace_burst_server_operation(
        outcome: server.respond(incoming, 204, [], <<>>),
        completed:,
        remaining:,
        phase: BurstRespond,
      ))
      serve_requests(listener, remaining - 1)
    }
  }
}

fn trace_burst_server_operation(
  outcome outcome: Result(value, server.Error),
  completed completed: Int,
  remaining remaining: Int,
  phase phase: BurstServerPhase,
) -> Result(value, BurstServerFailure) {
  result.map_error(outcome, fn(error) {
    BurstServerFailure(
      completed:,
      remaining:,
      phase:,
      cause: server_burst_failure(error),
    )
  })
}

fn client_burst_failure(error: client.Error) -> BurstFailureCause {
  case error {
    client.Failure(failure) -> burst_runtime_failure(failure)
    _ -> BurstPublicContractFailure
  }
}

fn server_burst_failure(error: server.Error) -> BurstFailureCause {
  case error {
    server.Failure(failure) -> burst_runtime_failure(failure)
    _ -> BurstPublicContractFailure
  }
}

fn trace_burst_server_outcome(
  outcome: Result(value, server.Error),
) -> Result(value, BurstFailureCause) {
  result.map_error(outcome, server_burst_failure)
}

fn burst_runtime_failure(
  failure: runtime_failure.Failure,
) -> BurstFailureCause {
  case failure {
    runtime_failure.Resolution -> BurstResolutionFailure
    runtime_failure.Socket(operation) -> BurstSocketFailure(operation)
    runtime_failure.Tls(origin) -> BurstTlsFailure(origin)
    runtime_failure.Quic(origin, code) -> BurstQuicFailure(origin, code)
    runtime_failure.Http3(origin, code) -> BurstHttp3Failure(origin, code)
    runtime_failure.Timeout(phase) -> BurstTimeoutFailure(phase)
    runtime_failure.Cancelled -> BurstCancellationFailure
    runtime_failure.Closed(origin, code) -> BurstClosedFailure(origin, code)
    runtime_failure.Limit(resource, maximum) ->
      BurstLimitFailure(resource, maximum)
    runtime_failure.Overload(resource) -> BurstOverloadFailure(resource)
  }
}
