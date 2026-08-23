//// Reproducible local load, soak, and benchmark harness.
////
//// This module intentionally exercises only the public HTTP/3 client and
//// server APIs. Run it through the fixed `mise` tasks documented in
//// `benchmarks/README.md`.

import gleam/bit_array
import gleam/bool
import gleam/http
import gleam/http/request
import gleam/int
import gleam/list
import gleam/string
import http3/client
import http3/server
import http3_test_support

const operation_timeout_milliseconds = 60_000

type Task(value)

type Configuration {
  Configuration(
    mode: String,
    trials: Int,
    concurrency: Int,
    requests_per_worker: Int,
    payload_bytes: Int,
  )
}

type Metrics {
  Metrics(processes: Int, memory_bytes: Int, mailbox_messages: Int)
}

type WorkloadError {
  ClientConnectFailed(client.Error)
  ClientOpenStreamFailed(client.Error)
  ClientSendFailed(client.Error)
  ClientFinishFailed(client.Error)
  ClientReceiveFailed(client.Error)
  ClientCloseFailed(client.Error)
  ClientWorkloadAndCloseFailed(WorkloadError, client.Error)
  ClientClosedUnexpectedly
  ResponseMismatch
  ServerAcceptFailed(server.Error)
  ServerReadFailed(server.Error)
  ServerRespondFailed(server.Error)
  RequestMismatch
}

@external(erlang, "http3_benchmark_ffi", "arguments")
fn arguments() -> List(String)

@external(erlang, "http3_benchmark_ffi", "start_task")
fn start_task(run: fn() -> value) -> Task(value)

@external(erlang, "http3_benchmark_ffi", "await_task")
fn await_task(task: Task(value)) -> value

@external(erlang, "http3_benchmark_ffi", "monotonic_microseconds")
fn monotonic_microseconds() -> Int

@external(erlang, "http3_benchmark_ffi", "runtime_metrics")
fn runtime_metrics() -> #(Int, Int, Int)

@external(erlang, "http3_benchmark_ffi", "await_cleanup_metrics")
fn await_cleanup_metrics(maximum_processes: Int) -> #(Int, Int, Int)

@external(erlang, "http3_benchmark_ffi", "write_line")
fn write_line(line: String) -> Nil

@external(erlang, "http3_benchmark_ffi", "fail")
fn fail(reason: reason) -> value

pub fn main() -> Nil {
  let configuration = parse_configuration(arguments())
  [
    "mode,iteration,warmup,concurrency,requests_per_worker,total_requests,",
    "payload_bytes,elapsed_microseconds,requests_per_second,",
    "processes_before,processes_after,memory_before_bytes,",
    "memory_after_bytes,mailbox_messages_before,mailbox_messages_after",
  ]
  |> string.join("")
  |> write_line
  run_iterations(
    configuration: configuration,
    iteration: 1,
    remaining: 1,
    warmup: True,
  )
  run_iterations(
    configuration: configuration,
    iteration: 1,
    remaining: configuration.trials,
    warmup: False,
  )
}

fn parse_configuration(arguments: List(String)) -> Configuration {
  case arguments {
    [] | ["benchmark"] -> Configuration("benchmark", 5, 4, 100, 1024)
    ["load"] -> Configuration("load", 3, 32, 100, 16_384)
    ["soak"] -> Configuration("soak", 1, 8, 10_000, 1024)
    [mode, trials, concurrency, requests_per_worker, payload_bytes] -> {
      let configuration =
        Configuration(
          mode: mode,
          trials: parse_positive("trials", trials),
          concurrency: parse_positive("concurrency", concurrency),
          requests_per_worker: parse_positive(
            "requests_per_worker",
            requests_per_worker,
          ),
          payload_bytes: parse_positive("payload_bytes", payload_bytes),
        )
      validate_configuration(configuration)
    }
    _ ->
      [
        "usage: http3_benchmark ",
        "[benchmark|load|soak [trials concurrency requests payload_bytes]]",
      ]
      |> string.join("")
      |> fail
  }
}

fn validate_configuration(configuration: Configuration) -> Configuration {
  case
    list.contains(["benchmark", "load", "soak"], configuration.mode),
    configuration.trials <= 20,
    configuration.concurrency <= 128,
    configuration.requests_per_worker <= 100_000,
    configuration.payload_bytes <= 1_048_576
  {
    True, True, True, True, True -> configuration
    _, _, _, _, _ ->
      [
        "mode must be benchmark, load, or soak; maxima are 20 trials, ",
        "128 workers, 100000 requests per worker, and 1048576 bytes",
      ]
      |> string.join("")
      |> fail
  }
}

fn parse_positive(name: String, value: String) -> Int {
  case int.parse(value) {
    Ok(parsed) if parsed > 0 -> parsed
    _ -> fail(name <> " must be a positive integer")
  }
}

fn run_iterations(
  configuration configuration: Configuration,
  iteration iteration: Int,
  remaining remaining: Int,
  warmup warmup: Bool,
) -> Nil {
  use <- bool.guard(when: remaining <= 0, return: Nil)
  run_trial(configuration: configuration, iteration: iteration, warmup: warmup)
  run_iterations(
    configuration: configuration,
    iteration: iteration + 1,
    remaining: remaining - 1,
    warmup: warmup,
  )
}

fn run_trial(
  configuration configuration: Configuration,
  iteration iteration: Int,
  warmup warmup: Bool,
) -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let server_configuration =
    configure_server(
      certificate: certificate,
      private_key: private_key,
      payload_bytes: configuration.payload_bytes,
    )
  let listener = server.start(server_configuration) |> must("start listener")
  let port = server.port(listener) |> must("read listener port")
  let client_configuration =
    configure_client(ca_certificate, configuration.payload_bytes)
  let payload = http3_test_support.repeated_bytes(configuration.payload_bytes)
  let Metrics(processes_before, memory_before, messages_before) = metrics()
  let started = monotonic_microseconds()
  let tasks =
    start_clients(
      count: configuration.concurrency,
      configuration: client_configuration,
      port: port,
      requests: configuration.requests_per_worker,
      payload: payload,
    )
  let total_requests =
    configuration.concurrency * configuration.requests_per_worker
  let server_result =
    serve_requests(
      listener: listener,
      remaining: total_requests,
      payload: payload,
    )

  // Stopping before awaiting failed workers guarantees that an unexpected
  // server failure releases every blocked connection and stream operation.
  let #(checked_server_result, client_results, stop_result) = case
    server_result
  {
    Ok(Nil) -> #(Ok(Nil), await_clients(tasks), server.stop(listener))
    Error(server_error) -> {
      let stop_result = server.stop(listener)
      #(Error(server_error), await_clients(tasks), stop_result)
    }
  }
  case checked_server_result, client_results, stop_result {
    Ok(Nil), Ok(Nil), Ok(server.Stopped) -> Nil
    _, _, _ ->
      fail(#("workload cleanup", server_result, client_results, stop_result))
  }

  let elapsed = monotonic_microseconds() - started
  let #(processes_after, memory_after, messages_after) =
    await_cleanup_metrics(processes_before)
  let requests_per_second = case elapsed > 0 {
    True -> total_requests * 1_000_000 / elapsed
    False -> 0
  }
  write_result(
    configuration: configuration,
    iteration: iteration,
    warmup: warmup,
    total_requests: total_requests,
    elapsed: elapsed,
    requests_per_second: requests_per_second,
    processes_before: processes_before,
    processes_after: processes_after,
    memory_before: memory_before,
    memory_after: memory_after,
    messages_before: messages_before,
    messages_after: messages_after,
  )
}

fn configure_server(
  certificate certificate: BitArray,
  private_key private_key: BitArray,
  payload_bytes payload_bytes: Int,
) -> server.Configuration {
  let buffer_limit = payload_bytes + 65_536
  server.new(certificate, private_key)
  |> must("configure listener credentials")
  |> server.with_timeout(operation_timeout_milliseconds)
  |> must("configure listener timeout")
  |> server.with_request_body_limit(buffer_limit)
  |> must("configure listener request limit")
  |> server.with_response_body_limit(buffer_limit)
  |> must("configure listener response limit")
  |> server.with_stream_buffer_limit(buffer_limit)
  |> must("configure listener stream buffer")
}

fn configure_client(
  ca_certificate: BitArray,
  payload_bytes: Int,
) -> client.Client {
  client.new()
  |> client.with_ca_certificate(ca_certificate)
  |> must("configure client CA")
  |> client.with_timeout(operation_timeout_milliseconds)
  |> must("configure client timeout")
  |> client.with_stream_buffer_limit(payload_bytes + 65_536)
  |> must("configure client stream buffer")
}

fn start_clients(
  count count: Int,
  configuration configuration: client.Client,
  port port: Int,
  requests requests: Int,
  payload payload: BitArray,
) -> List(Task(Result(Nil, WorkloadError))) {
  int.range(from: 0, to: count, with: [], run: fn(tasks, _) {
    let task =
      start_task(fn() {
        run_client(
          configuration: configuration,
          port: port,
          requests: requests,
          payload: payload,
        )
      })
    [task, ..tasks]
  })
}

fn await_clients(
  tasks: List(Task(Result(Nil, WorkloadError))),
) -> Result(Nil, WorkloadError) {
  case tasks {
    [] -> Ok(Nil)
    [task, ..rest] ->
      case await_task(task) {
        Ok(Nil) -> await_clients(rest)
        Error(error) -> Error(error)
      }
  }
}

fn run_client(
  configuration configuration: client.Client,
  port port: Int,
  requests requests: Int,
  payload payload: BitArray,
) -> Result(Nil, WorkloadError) {
  case client.connect(configuration, "localhost", port) {
    Error(error) -> Error(ClientConnectFailed(error))
    Ok(connection) -> {
      let workload =
        send_requests(
          connection: connection,
          port: port,
          remaining: requests,
          payload: payload,
        )
      let close_result = client.close(connection)
      case workload, close_result {
        Ok(Nil), Ok(client.Closed) -> Ok(Nil)
        Ok(Nil), Ok(client.AlreadyClosed) -> Error(ClientClosedUnexpectedly)
        Ok(Nil), Error(error) -> Error(ClientCloseFailed(error))
        Error(workload_error), Ok(client.Closed) -> Error(workload_error)
        Error(workload_error), Ok(client.AlreadyClosed) -> Error(workload_error)
        Error(workload_error), Error(close_error) ->
          Error(ClientWorkloadAndCloseFailed(workload_error, close_error))
      }
    }
  }
}

fn send_requests(
  connection connection: client.Connection,
  port port: Int,
  remaining remaining: Int,
  payload payload: BitArray,
) -> Result(Nil, WorkloadError) {
  use <- bool.guard(when: remaining <= 0, return: Ok(Nil))
  case send_request(connection: connection, port: port, payload: payload) {
    Ok(Nil) ->
      send_requests(
        connection: connection,
        port: port,
        remaining: remaining - 1,
        payload: payload,
      )
    Error(error) -> Error(error)
  }
}

fn send_request(
  connection connection: client.Connection,
  port port: Int,
  payload payload: BitArray,
) -> Result(Nil, WorkloadError) {
  let outbound =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path("/benchmark")
    |> request.set_method(http.Post)
    |> request.set_header(
      "content-length",
      int.to_string(bit_array.byte_size(payload)),
    )
    |> request.set_body(Nil)
  case client.open_stream(connection, outbound) {
    Error(error) -> Error(ClientOpenStreamFailed(error))
    Ok(stream) ->
      case client.send_chunk(stream, payload) {
        Error(error) -> Error(ClientSendFailed(error))
        Ok(Nil) ->
          case client.finish(stream) {
            Error(error) -> Error(ClientFinishFailed(error))
            Ok(Nil) ->
              collect_response(
                stream: stream,
                status: 0,
                chunks: [],
                payload: payload,
              )
          }
      }
  }
}

fn collect_response(
  stream stream: client.Stream,
  status status: Int,
  chunks chunks: List(BitArray),
  payload payload: BitArray,
) -> Result(Nil, WorkloadError) {
  case client.next_event(stream) {
    Error(error) -> Error(ClientReceiveFailed(error))
    Ok(client.InformationalResponse(_, _)) ->
      collect_response(
        stream: stream,
        status: status,
        chunks: chunks,
        payload: payload,
      )
    Ok(client.Response(new_status, _)) ->
      collect_response(
        stream: stream,
        status: new_status,
        chunks: chunks,
        payload: payload,
      )
    Ok(client.Data(chunk)) ->
      collect_response(
        stream: stream,
        status: status,
        chunks: [chunk, ..chunks],
        payload: payload,
      )
    Ok(client.Trailers(_)) ->
      collect_response(
        stream: stream,
        status: status,
        chunks: chunks,
        payload: payload,
      )
    Ok(client.End) -> {
      let body = bit_array.concat(list.reverse(chunks))
      case status == 200 && body == payload {
        True -> Ok(Nil)
        False -> Error(ResponseMismatch)
      }
    }
  }
}

fn serve_requests(
  listener listener: server.Listener,
  remaining remaining: Int,
  payload payload: BitArray,
) -> Result(Nil, WorkloadError) {
  use <- bool.guard(when: remaining <= 0, return: Ok(Nil))
  case server.accept(listener) {
    Error(error) -> Error(ServerAcceptFailed(error))
    Ok(incoming) ->
      case server.read_body(incoming) {
        Error(error) -> Error(ServerReadFailed(error))
        Ok(body) if body != payload -> Error(RequestMismatch)
        Ok(_) ->
          case server.respond(incoming, 200, [], payload) {
            Error(error) -> Error(ServerRespondFailed(error))
            Ok(Nil) ->
              serve_requests(
                listener: listener,
                remaining: remaining - 1,
                payload: payload,
              )
          }
      }
  }
}

fn metrics() -> Metrics {
  let #(processes, memory_bytes, mailbox_messages) = runtime_metrics()
  Metrics(processes, memory_bytes, mailbox_messages)
}

fn write_result(
  configuration configuration: Configuration,
  iteration iteration: Int,
  warmup warmup: Bool,
  total_requests total_requests: Int,
  elapsed elapsed: Int,
  requests_per_second requests_per_second: Int,
  processes_before processes_before: Int,
  processes_after processes_after: Int,
  memory_before memory_before: Int,
  memory_after memory_after: Int,
  messages_before messages_before: Int,
  messages_after messages_after: Int,
) -> Nil {
  [
    configuration.mode,
    int.to_string(iteration),
    bool.to_string(warmup),
    int.to_string(configuration.concurrency),
    int.to_string(configuration.requests_per_worker),
    int.to_string(total_requests),
    int.to_string(configuration.payload_bytes),
    int.to_string(elapsed),
    int.to_string(requests_per_second),
    int.to_string(processes_before),
    int.to_string(processes_after),
    int.to_string(memory_before),
    int.to_string(memory_after),
    int.to_string(messages_before),
    int.to_string(messages_after),
  ]
  |> string.join(",")
  |> write_line
}

fn must(result: Result(value, error), operation: String) -> value {
  case result {
    Ok(value) -> value
    Error(error) -> fail(#(operation, error))
  }
}
