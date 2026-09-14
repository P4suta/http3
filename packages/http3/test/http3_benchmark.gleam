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
import gleam/result
import gleam/string
import http3/client
import http3/server
import http3/transport
import http3_test_support

const operation_timeout_milliseconds = 60_000

const trial_timeout_microseconds = 900_000_000

const connection_barrier_timeout_microseconds = 65_000_000

type Task(value)

type ProgressTrace

type ConnectionBarrier

type CompletionLatch

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
  Metrics(
    processes: Int,
    memory_bytes: Int,
    mailbox_messages: Int,
    ports: Int,
    network_ports: Int,
    sockets: Int,
  )
}

type DiagnosticMetrics {
  DiagnosticMetrics(
    runtime_milliseconds: Int,
    reductions: Int,
    context_switches: Int,
    garbage_collections: Int,
    garbage_collected_words: Int,
    io_input_bytes: Int,
    io_output_bytes: Int,
    run_queue: Int,
  )
}

type ResourceState {
  ResourceState(
    active: Int,
    retained_terminals: Int,
    core_handles: Int,
    runtime_handles: Int,
    transport_streams: Int,
    protocol_inputs: Int,
    transactions: Int,
    push_transactions: Int,
    blocked_streams: Int,
  )
}

type ClientTransportDiagnostics {
  ClientTransportDiagnostics(
    initial_smoothed_rtt_microseconds: Int,
    final_smoothed_rtt_microseconds: Int,
    initial_congestion_window: Int,
    final_congestion_window: Int,
    packets_received: Int,
    packets_sent: Int,
    retransmissions: Int,
    batch_flushes: Int,
    packets_coalesced: Int,
    in_recovery: Int,
    congested: Int,
  )
}

type DiagnosticRange {
  DiagnosticRange(minimum: Int, total: Int, maximum: Int)
}

type DiagnosticAccumulator {
  DiagnosticAccumulator(
    count: Int,
    initial_rtt: DiagnosticRange,
    final_rtt: DiagnosticRange,
    initial_window: DiagnosticRange,
    final_window: DiagnosticRange,
    retransmissions: Int,
    maximum_retransmissions: Int,
    packets_received: Int,
    packets_sent: Int,
    batch_flushes: Int,
    packets_coalesced: Int,
    in_recovery: Int,
    congested: Int,
  )
}

type TransportDiagnosticSummary {
  TransportDiagnosticSummary(
    initial_rtt_min: Int,
    initial_rtt_average: Int,
    initial_rtt_max: Int,
    final_rtt_min: Int,
    final_rtt_average: Int,
    final_rtt_max: Int,
    initial_window_min: Int,
    initial_window_average: Int,
    initial_window_max: Int,
    final_window_min: Int,
    final_window_average: Int,
    final_window_max: Int,
    retransmissions: Int,
    maximum_retransmissions: Int,
    packets_received: Int,
    packets_sent: Int,
    batch_flushes: Int,
    packets_coalesced: Int,
    in_recovery: Int,
    congested: Int,
  )
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
  ClientResourceStatsFailed(client.Error)
  ClientResourcesUnbounded(ResourceState)
  ClientConnectionBarrierFailed
  ClientCompletionLatchFailed
  ClientPathStatsFailed(transport.Error)
  ClientConnectionStatsFailed(transport.Error)
  ResponseMismatch
  ServerAcceptFailed(server.Error)
  ServerReadFailed(server.Error)
  ServerRespondFailed(server.Error)
  ServerResourceStatsFailed(server.Error)
  ServerResourcesUnbounded(ResourceState)
  RequestMismatch
  TrialDeadlineExceeded
}

@external(erlang, "http3_benchmark_ffi", "arguments")
fn arguments() -> List(String)

@external(erlang, "http3_benchmark_ffi", "qlog_directory")
fn qlog_directory() -> String

@external(erlang, "http3_benchmark_ffi", "start_task")
fn start_task(run: fn() -> value, deadline_microseconds: Int) -> Task(value)

@external(erlang, "http3_benchmark_ffi", "await_task")
fn await_task(task: Task(value)) -> value

@external(erlang, "http3_benchmark_ffi", "monotonic_microseconds")
fn monotonic_microseconds() -> Int

@external(erlang, "http3_benchmark_ffi", "runtime_metrics")
fn runtime_metrics() -> #(Int, Int, Int, Int, Int, Int)

@external(erlang, "http3_benchmark_ffi", "diagnostic_metrics")
fn raw_diagnostic_metrics() -> #(Int, Int, Int, Int, Int, Int, Int, Int)

@external(erlang, "http3_benchmark_barrier_ffi", "start_connection_barrier")
fn start_connection_barrier(
  workers: Int,
  deadline_microseconds: Int,
) -> ConnectionBarrier

@external(erlang, "http3_benchmark_barrier_ffi", "arrive_connection_barrier")
fn arrive_connection_barrier(barrier: ConnectionBarrier, worker: Int) -> Bool

@external(erlang, "http3_benchmark_barrier_ffi", "await_connection_barrier")
fn await_connection_barrier(barrier: ConnectionBarrier) -> Bool

@external(erlang, "http3_benchmark_barrier_ffi", "fail_connection_barrier")
fn fail_connection_barrier(barrier: ConnectionBarrier) -> Nil

@external(erlang, "http3_benchmark_barrier_ffi", "stop_connection_barrier")
fn stop_connection_barrier(barrier: ConnectionBarrier) -> Nil

@external(erlang, "http3_benchmark_barrier_ffi", "start_completion_latch")
fn start_completion_latch(
  workers: Int,
  deadline_microseconds: Int,
) -> CompletionLatch

@external(erlang, "http3_benchmark_barrier_ffi", "await_completion_latch")
fn await_completion_latch(latch: CompletionLatch, worker: Int) -> Bool

@external(erlang, "http3_benchmark_barrier_ffi", "release_completion_latch")
fn release_completion_latch(latch: CompletionLatch) -> Bool

@external(erlang, "http3_benchmark_barrier_ffi", "fail_completion_latch")
fn fail_completion_latch(latch: CompletionLatch) -> Nil

@external(erlang, "http3_benchmark_barrier_ffi", "stop_completion_latch")
fn stop_completion_latch(latch: CompletionLatch) -> Nil

@external(erlang, "http3_benchmark_trace_ffi", "start_progress_trace")
fn start_progress_trace(
  mode: String,
  iteration: Int,
  warmup: Bool,
  workers: Int,
  requests_per_worker: Int,
) -> ProgressTrace

@external(erlang, "http3_benchmark_trace_ffi", "trace_client_progress")
fn trace_client_progress(
  trace: ProgressTrace,
  worker: Int,
  request: Int,
  phase: Int,
) -> Nil

@external(erlang, "http3_benchmark_trace_ffi", "trace_server_progress")
fn trace_server_progress(trace: ProgressTrace, completed: Int) -> Nil

@external(erlang, "http3_benchmark_trace_ffi", "stop_progress_trace")
fn stop_progress_trace(trace: ProgressTrace) -> Nil

@external(erlang, "http3_benchmark_trace_ffi", "progress_summary")
fn raw_progress_summary(
  workers: List(#(Int, Int, Int)),
  now_milliseconds: Int,
  stall_milliseconds: Int,
  requests_per_worker: Int,
) -> #(Int, Int, Int, Int, Int, Int, Int, Int)

@external(erlang, "http3_benchmark_trace_ffi", "progress_distribution")
fn raw_progress_distribution(
  workers: List(#(Int, Int, Int)),
  requests_per_worker: Int,
) -> #(Int, Int, Int, Int, Int)

@external(erlang, "http3_benchmark_ffi", "await_cleanup_metrics")
fn await_cleanup_metrics(
  maximum_processes: Int,
  maximum_ports: Int,
  maximum_network_ports: Int,
  maximum_sockets: Int,
) -> #(Int, Int, Int, Int, Int, Int)

@external(erlang, "http3_benchmark_ffi", "write_line")
fn write_line(line: String) -> Nil

@external(erlang, "http3_benchmark_ffi", "fail")
fn fail(reason: reason) -> value

pub fn main() -> Nil {
  let configuration = parse_configuration(arguments())
  csv_columns()
  |> string.join(",")
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

/// The single authoritative benchmark CSV schema, in emitted order.
@internal
pub fn csv_columns() -> List(String) {
  [
    "mode",
    "iteration",
    "warmup",
    "concurrency",
    "requests_per_worker",
    "total_requests",
    "payload_bytes",
    "elapsed_microseconds",
    "requests_per_second",
    "processes_before",
    "processes_after",
    "memory_before_bytes",
    "memory_after_bytes",
    "mailbox_messages_before",
    "mailbox_messages_after",
    "ports_before",
    "ports_after",
    "network_ports_before",
    "network_ports_after",
    "sockets_before",
    "sockets_after",
    "runtime_milliseconds",
    "reductions",
    "context_switches",
    "garbage_collections",
    "garbage_collected_words",
    "io_input_bytes",
    "io_output_bytes",
    "run_queue_before",
    "run_queue_after",
    "client_initial_smoothed_rtt_min_us",
    "client_initial_smoothed_rtt_avg_us",
    "client_initial_smoothed_rtt_max_us",
    "client_final_smoothed_rtt_min_us",
    "client_final_smoothed_rtt_avg_us",
    "client_final_smoothed_rtt_max_us",
    "client_initial_cwnd_min",
    "client_initial_cwnd_avg",
    "client_initial_cwnd_max",
    "client_final_cwnd_min",
    "client_final_cwnd_avg",
    "client_final_cwnd_max",
    "client_retransmissions_total",
    "client_retransmissions_max",
    "client_packets_received_total",
    "client_packets_sent_total",
    "client_batch_flushes_total",
    "client_packets_coalesced_total",
    "client_connections_in_recovery",
    "client_connections_congested",
  ]
}

/// Check a candidate row against the authoritative schema width.
@internal
pub fn csv_width_matches(fields: List(value)) -> Bool {
  list.length(fields) == list.length(csv_columns())
}

/// Run the manifest-owned workload used by the bounded OTP call-count gate.
@internal
pub fn profile_workload(
  measured_trials measured_trials: Int,
  concurrency concurrency: Int,
  requests_per_connection requests_per_connection: Int,
  payload_bytes payload_bytes: Int,
) -> Nil {
  let configuration =
    Configuration(
      mode: "benchmark",
      trials: measured_trials,
      concurrency: concurrency,
      requests_per_worker: requests_per_connection,
      payload_bytes: payload_bytes,
    )
    |> validate_configuration
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
  let client_configuration =
    configure_client(ca_certificate, configuration.payload_bytes)
  let payload = http3_test_support.repeated_bytes(configuration.payload_bytes)
  let priming_listener =
    server.start(server_configuration) |> must("start priming listener")
  let priming_port =
    server.port(priming_listener) |> must("read priming listener port")
  prime_runtime(client_configuration, priming_port)
  case server.stop(priming_listener) {
    Ok(server.Stopped) -> Nil
    Ok(server.AlreadyStopped) -> fail("priming listener already stopped")
    Error(error) -> fail(#("stop priming listener", error))
  }
  let Metrics(
    processes_before,
    memory_before,
    messages_before,
    ports_before,
    network_ports_before,
    sockets_before,
  ) = metrics()
  case network_ports_before == 0 && sockets_before == 0 {
    True -> Nil
    False ->
      fail(#(
        "primed network baseline retained sockets",
        network_ports_before,
        sockets_before,
      ))
  }
  let listener = server.start(server_configuration) |> must("start listener")
  let port = server.port(listener) |> must("read listener port")
  let progress =
    start_progress_trace(
      configuration.mode,
      iteration,
      warmup,
      configuration.concurrency,
      configuration.requests_per_worker,
    )
  let diagnostics_before = diagnostic_metrics()
  let started = monotonic_microseconds()
  let deadline = started + trial_timeout_microseconds
  let barrier =
    start_connection_barrier(
      configuration.concurrency,
      int.min(deadline, started + connection_barrier_timeout_microseconds),
    )
  let completion_latch =
    start_completion_latch(configuration.concurrency, deadline)
  let tasks =
    start_clients(
      count: configuration.concurrency,
      configuration: client_configuration,
      port: port,
      requests: configuration.requests_per_worker,
      payload: payload,
      deadline: deadline,
      progress: progress,
      barrier: barrier,
      completion_latch: completion_latch,
    )
  let total_requests =
    configuration.concurrency * configuration.requests_per_worker
  let server_result = case await_connection_barrier(barrier) {
    False -> Error(ClientConnectionBarrierFailed)
    True ->
      serve_requests(
        listener: listener,
        remaining: total_requests,
        payload: payload,
        deadline: deadline,
        progress: progress,
        completed: 0,
      )
  }

  // Keep every successful client connection alive until the final server-side
  // resource snapshot has completed. Otherwise a peer close can race that
  // snapshot after the last response has already reached the client.
  let coordinated_server_result = case server_result {
    Ok(Nil) ->
      case release_completion_latch(completion_latch) {
        True -> Ok(Nil)
        False -> Error(ClientCompletionLatchFailed)
      }
    Error(error) -> {
      fail_completion_latch(completion_latch)
      Error(error)
    }
  }

  // Stopping before awaiting failed workers guarantees that an unexpected
  // server failure releases every blocked connection and stream operation.
  let #(checked_server_result, client_results, stop_result) = case
    coordinated_server_result
  {
    Ok(Nil) -> #(Ok(Nil), await_clients(tasks), server.stop(listener))
    Error(server_error) -> {
      let stop_result = server.stop(listener)
      #(Error(server_error), await_clients(tasks), stop_result)
    }
  }
  stop_connection_barrier(barrier)
  stop_completion_latch(completion_latch)
  stop_progress_trace(progress)
  let client_diagnostics = case
    checked_server_result,
    client_results,
    stop_result
  {
    Ok(Nil), Ok(diagnostics), Ok(server.Stopped) -> diagnostics
    _, _, _ ->
      fail(#(
        "workload cleanup",
        coordinated_server_result,
        client_results,
        stop_result,
      ))
  }

  let elapsed = monotonic_microseconds() - started
  let diagnostics_after = diagnostic_metrics()
  let #(
    processes_after,
    memory_after,
    messages_after,
    ports_after,
    network_ports_after,
    sockets_after,
  ) =
    await_cleanup_metrics(
      processes_before,
      ports_before,
      network_ports_before,
      sockets_before,
    )
  case
    runtime_resources_converged(
      processes_before: processes_before,
      ports_before: ports_before,
      network_ports_before: network_ports_before,
      sockets_before: sockets_before,
      processes_after: processes_after,
      ports_after: ports_after,
      network_ports_after: network_ports_after,
      sockets_after: sockets_after,
    )
  {
    True -> Nil
    False ->
      fail(#(
        "runtime resources did not converge",
        #(processes_before, ports_before, network_ports_before, sockets_before),
        #(processes_after, ports_after, network_ports_after, sockets_after),
      ))
  }
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
    ports_before: ports_before,
    ports_after: ports_after,
    network_ports_before: network_ports_before,
    network_ports_after: network_ports_after,
    sockets_before: sockets_before,
    sockets_after: sockets_after,
    diagnostics_before: diagnostics_before,
    diagnostics_after: diagnostics_after,
    client_diagnostics: client_diagnostics,
  )
}

fn prime_runtime(configuration: client.Client, port: Int) -> Nil {
  let connection =
    client.connect(configuration, "localhost", port)
    |> must("prime client runtime")
  case client.close(connection) {
    Ok(client.Closed) | Ok(client.AlreadyClosed) -> Nil
    Error(error) -> fail(#("close priming connection", error))
  }
}

fn configure_server(
  certificate certificate: BitArray,
  private_key private_key: BitArray,
  payload_bytes payload_bytes: Int,
) -> server.Configuration {
  let buffer_limit = payload_bytes + 65_536
  let configuration =
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
  case qlog_directory() {
    "" -> configuration
    directory ->
      configuration
      |> server.with_qlog(transport.qlog(directory) |> must("configure qlog"))
  }
}

fn configure_client(
  ca_certificate: BitArray,
  payload_bytes: Int,
) -> client.Client {
  let configuration =
    client.new()
    |> client.with_ca_certificate(ca_certificate)
    |> must("configure client CA")
    |> client.with_timeout(operation_timeout_milliseconds)
    |> must("configure client timeout")
    |> client.with_stream_buffer_limit(payload_bytes + 65_536)
    |> must("configure client stream buffer")
  case qlog_directory() {
    "" -> configuration
    directory ->
      configuration
      |> client.with_qlog(transport.qlog(directory) |> must("configure qlog"))
  }
}

fn start_clients(
  count count: Int,
  configuration configuration: client.Client,
  port port: Int,
  requests requests: Int,
  payload payload: BitArray,
  deadline deadline: Int,
  progress progress: ProgressTrace,
  barrier barrier: ConnectionBarrier,
  completion_latch completion_latch: CompletionLatch,
) -> List(Task(Result(ClientTransportDiagnostics, WorkloadError))) {
  int.range(from: 0, to: count, with: [], run: fn(tasks, worker) {
    let task =
      start_task(
        fn() {
          run_client(
            configuration: configuration,
            port: port,
            requests: requests,
            payload: payload,
            progress: progress,
            worker: worker,
            barrier: barrier,
            completion_latch: completion_latch,
          )
        },
        deadline,
      )
    [task, ..tasks]
  })
}

fn await_clients(
  tasks: List(Task(Result(ClientTransportDiagnostics, WorkloadError))),
) -> Result(List(ClientTransportDiagnostics), WorkloadError) {
  case tasks {
    [] -> Ok([])
    [task, ..rest] ->
      case await_task(task) {
        Ok(diagnostics) ->
          await_clients(rest)
          |> result.map(fn(remaining) { [diagnostics, ..remaining] })
        Error(error) -> Error(error)
      }
  }
}

fn run_client(
  configuration configuration: client.Client,
  port port: Int,
  requests requests: Int,
  payload payload: BitArray,
  progress progress: ProgressTrace,
  worker worker: Int,
  barrier barrier: ConnectionBarrier,
  completion_latch completion_latch: CompletionLatch,
) -> Result(ClientTransportDiagnostics, WorkloadError) {
  case client.connect(configuration, "localhost", port) {
    Error(error) -> {
      fail_connection_barrier(barrier)
      fail_completion_latch(completion_latch)
      Error(ClientConnectFailed(error))
    }
    Ok(connection) -> {
      let workload =
        run_connected_client(
          connection: connection,
          port: port,
          requests: requests,
          payload: payload,
          progress: progress,
          worker: worker,
          barrier: barrier,
          completion_latch: completion_latch,
        )
      let close_result = client.close(connection)
      case workload, close_result {
        Ok(diagnostics), Ok(client.Closed) -> Ok(diagnostics)
        Ok(_), Ok(client.AlreadyClosed) -> Error(ClientClosedUnexpectedly)
        Ok(_), Error(error) -> Error(ClientCloseFailed(error))
        Error(workload_error), Ok(client.Closed) -> Error(workload_error)
        Error(workload_error), Ok(client.AlreadyClosed) -> Error(workload_error)
        Error(workload_error), Error(close_error) ->
          Error(ClientWorkloadAndCloseFailed(workload_error, close_error))
      }
    }
  }
}

fn run_connected_client(
  connection connection: client.Connection,
  port port: Int,
  requests requests: Int,
  payload payload: BitArray,
  progress progress: ProgressTrace,
  worker worker: Int,
  barrier barrier: ConnectionBarrier,
  completion_latch completion_latch: CompletionLatch,
) -> Result(ClientTransportDiagnostics, WorkloadError) {
  use <- bool.guard(
    when: !arrive_connection_barrier(barrier, worker),
    return: Error(ClientConnectionBarrierFailed),
  )
  use initial <- result.try(capture_initial_transport_diagnostics(connection))
  use Nil <- result.try(send_requests(
    connection: connection,
    port: port,
    remaining: requests,
    payload: payload,
    progress: progress,
    worker: worker,
    completed: 0,
  ))
  use Nil <- result.try(check_client_resources(connection))
  use diagnostics <- result.try(capture_final_transport_diagnostics(
    connection,
    initial,
  ))
  case await_completion_latch(completion_latch, worker) {
    True -> Ok(diagnostics)
    False -> Error(ClientCompletionLatchFailed)
  }
}

fn capture_initial_transport_diagnostics(
  connection: client.Connection,
) -> Result(#(Int, Int), WorkloadError) {
  case transport.path_stats(client.connection_transport(connection)) {
    Error(error) -> Error(ClientPathStatsFailed(error))
    Ok(transport.PathStats(smoothed, _, _, _, window, _, _, _)) ->
      Ok(#(smoothed, window))
  }
}

fn capture_final_transport_diagnostics(
  connection: client.Connection,
  initial: #(Int, Int),
) -> Result(ClientTransportDiagnostics, WorkloadError) {
  let connection = client.connection_transport(connection)
  use path <- result.try(
    transport.path_stats(connection)
    |> result.map_error(ClientPathStatsFailed),
  )
  use traffic <- result.try(
    transport.connection_stats(connection)
    |> result.map_error(ClientConnectionStatsFailed),
  )
  let #(initial_rtt, initial_window) = initial
  let transport.PathStats(
    final_rtt,
    _,
    _,
    _,
    final_window,
    _,
    recovery,
    congested,
  ) = path
  let transport.ConnectionStats(
    packets_received,
    packets_sent,
    _,
    _,
    _,
    retransmissions,
    batch_flushes,
    packets_coalesced,
  ) = traffic
  Ok(ClientTransportDiagnostics(
    initial_smoothed_rtt_microseconds: initial_rtt,
    final_smoothed_rtt_microseconds: final_rtt,
    initial_congestion_window: initial_window,
    final_congestion_window: final_window,
    packets_received: packets_received,
    packets_sent: packets_sent,
    retransmissions: retransmissions,
    batch_flushes: batch_flushes,
    packets_coalesced: packets_coalesced,
    in_recovery: bool_integer(recovery),
    congested: bool_integer(congested),
  ))
}

fn send_requests(
  connection connection: client.Connection,
  port port: Int,
  remaining remaining: Int,
  payload payload: BitArray,
  progress progress: ProgressTrace,
  worker worker: Int,
  completed completed: Int,
) -> Result(Nil, WorkloadError) {
  use <- bool.guard(when: remaining <= 0, return: Ok(Nil))
  let request_number = completed + 1
  trace_client_progress(progress, worker, request_number, 1)
  case
    send_request(
      connection: connection,
      port: port,
      payload: payload,
      progress: progress,
      worker: worker,
      request_number: request_number,
    )
  {
    Ok(Nil) -> {
      trace_client_progress(progress, worker, request_number, 4)
      send_requests(
        connection: connection,
        port: port,
        remaining: remaining - 1,
        payload: payload,
        progress: progress,
        worker: worker,
        completed: request_number,
      )
    }
    Error(error) -> Error(error)
  }
}

fn send_request(
  connection connection: client.Connection,
  port port: Int,
  payload payload: BitArray,
  progress progress: ProgressTrace,
  worker worker: Int,
  request_number request_number: Int,
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
            Ok(Nil) -> {
              trace_client_progress(progress, worker, request_number, 2)
              collect_response(
                stream: stream,
                status: 0,
                chunks: [],
                payload: payload,
                progress: progress,
                worker: worker,
                request_number: request_number,
              )
            }
          }
      }
  }
}

fn collect_response(
  stream stream: client.Stream,
  status status: Int,
  chunks chunks: List(BitArray),
  payload payload: BitArray,
  progress progress: ProgressTrace,
  worker worker: Int,
  request_number request_number: Int,
) -> Result(Nil, WorkloadError) {
  case client.next_event(stream) {
    Error(error) -> Error(ClientReceiveFailed(error))
    Ok(client.InformationalResponse(_, _)) ->
      collect_response(
        stream: stream,
        status: status,
        chunks: chunks,
        payload: payload,
        progress: progress,
        worker: worker,
        request_number: request_number,
      )
    Ok(client.Response(new_status, _)) -> {
      trace_client_progress(progress, worker, request_number, 3)
      collect_response(
        stream: stream,
        status: new_status,
        chunks: chunks,
        payload: payload,
        progress: progress,
        worker: worker,
        request_number: request_number,
      )
    }
    Ok(client.Data(chunk)) ->
      collect_response(
        stream: stream,
        status: status,
        chunks: [chunk, ..chunks],
        payload: payload,
        progress: progress,
        worker: worker,
        request_number: request_number,
      )
    Ok(client.Trailers(_)) ->
      collect_response(
        stream: stream,
        status: status,
        chunks: chunks,
        payload: payload,
        progress: progress,
        worker: worker,
        request_number: request_number,
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
  deadline deadline: Int,
  progress progress: ProgressTrace,
  completed completed: Int,
) -> Result(Nil, WorkloadError) {
  use <- bool.guard(when: remaining <= 0, return: Ok(Nil))
  case
    trial_deadline_expired(now: monotonic_microseconds(), deadline: deadline)
  {
    True -> Error(TrialDeadlineExceeded)
    False ->
      serve_request_before_deadline(
        listener: listener,
        remaining: remaining,
        payload: payload,
        deadline: deadline,
        progress: progress,
        completed: completed,
      )
  }
}

fn serve_request_before_deadline(
  listener listener: server.Listener,
  remaining remaining: Int,
  payload payload: BitArray,
  deadline deadline: Int,
  progress progress: ProgressTrace,
  completed completed: Int,
) -> Result(Nil, WorkloadError) {
  use incoming <- result.try(
    server.accept(listener) |> result.map_error(ServerAcceptFailed),
  )
  use body <- result.try(
    server.read_body(incoming) |> result.map_error(ServerReadFailed),
  )
  use <- bool.guard(when: body != payload, return: Error(RequestMismatch))
  use Nil <- result.try(
    server.respond(incoming, 200, [], payload)
    |> result.map_error(ServerRespondFailed),
  )
  let completed = completed + 1
  trace_server_progress(progress, completed)
  case remaining == 1 {
    True -> check_server_resources(incoming)
    False ->
      serve_requests(
        listener: listener,
        remaining: remaining - 1,
        payload: payload,
        deadline: deadline,
        progress: progress,
        completed: completed,
      )
  }
}

fn check_client_resources(
  connection: client.Connection,
) -> Result(Nil, WorkloadError) {
  case client.resource_state_stats(connection) {
    Error(error) -> Error(ClientResourceStatsFailed(error))
    Ok(resources) ->
      case resources_are_bounded(resources) {
        True -> Ok(Nil)
        False -> Error(ClientResourcesUnbounded(resource_state(resources)))
      }
  }
}

fn check_server_resources(
  request: server.Request,
) -> Result(Nil, WorkloadError) {
  case server.request_state_stats(request) {
    Error(error) -> Error(ServerResourceStatsFailed(error))
    Ok(resources) ->
      case resources_are_bounded(resources) {
        True -> Ok(Nil)
        False -> Error(ServerResourcesUnbounded(resource_state(resources)))
      }
  }
}

fn resource_state(
  resources: #(Int, Int, Int, Int, Int, Int, Int, Int, Int),
) -> ResourceState {
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
  ) = resources
  ResourceState(
    active: active,
    retained_terminals: retained_terminals,
    core_handles: core_handles,
    runtime_handles: runtime_handles,
    transport_streams: transport_streams,
    protocol_inputs: protocol_inputs,
    transactions: transactions,
    push_transactions: push_transactions,
    blocked_streams: blocked_streams,
  )
}

/// Verify every retained-resource layer against the fixed soak-test ceiling.
@internal
pub fn resources_are_bounded(
  resources: #(Int, Int, Int, Int, Int, Int, Int, Int, Int),
) -> Bool {
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
  ) = resources
  active <= 16
  && retained_terminals <= 1024
  && core_handles <= 16
  && runtime_handles <= 16
  && transport_streams <= 16
  && protocol_inputs <= 8
  && transactions <= 16
  && push_transactions == 0
  && blocked_streams == 0
}

/// Pure boundary used by the harness and its deterministic deadline tests.
@internal
pub fn trial_deadline_expired(now now: Int, deadline deadline: Int) -> Bool {
  now >= deadline
}

fn metrics() -> Metrics {
  let #(
    processes,
    memory_bytes,
    mailbox_messages,
    ports,
    network_ports,
    sockets,
  ) = runtime_metrics()
  Metrics(
    processes,
    memory_bytes,
    mailbox_messages,
    ports,
    network_ports,
    sockets,
  )
}

fn diagnostic_metrics() -> DiagnosticMetrics {
  let #(
    runtime_milliseconds,
    reductions,
    context_switches,
    garbage_collections,
    garbage_collected_words,
    io_input_bytes,
    io_output_bytes,
    run_queue,
  ) = raw_diagnostic_metrics()
  DiagnosticMetrics(
    runtime_milliseconds: runtime_milliseconds,
    reductions: reductions,
    context_switches: context_switches,
    garbage_collections: garbage_collections,
    garbage_collected_words: garbage_collected_words,
    io_input_bytes: io_input_bytes,
    io_output_bytes: io_output_bytes,
    run_queue: run_queue,
  )
}

/// Difference two cumulative diagnostic counters without emitting negatives.
@internal
pub fn diagnostic_counter_delta(before before: Int, after after: Int) -> Int {
  int.max(0, after - before)
}

/// Require every finite OTP resource inventory to return to its trial baseline.
@internal
pub fn runtime_resources_converged(
  processes_before processes_before: Int,
  ports_before ports_before: Int,
  network_ports_before network_ports_before: Int,
  sockets_before sockets_before: Int,
  processes_after processes_after: Int,
  ports_after ports_after: Int,
  network_ports_after network_ports_after: Int,
  sockets_after sockets_after: Int,
) -> Bool {
  processes_after <= processes_before
  && ports_after <= ports_before
  && network_ports_after <= network_ports_before
  && sockets_after <= sockets_before
}

/// Summarize payload-free per-worker progress for deterministic trace tests.
@internal
pub fn progress_summary(
  workers workers: List(#(Int, Int, Int)),
  now_milliseconds now_milliseconds: Int,
  stall_milliseconds stall_milliseconds: Int,
  requests_per_worker requests_per_worker: Int,
) -> #(Int, Int, Int, Int, Int, Int, Int, Int) {
  raw_progress_summary(
    workers,
    now_milliseconds,
    stall_milliseconds,
    requests_per_worker,
  )
}

/// Summarize completed-request percentiles and active workers without payloads.
@internal
pub fn progress_distribution(
  workers workers: List(#(Int, Int, Int)),
  requests_per_worker requests_per_worker: Int,
) -> #(Int, Int, Int, Int, Int) {
  raw_progress_distribution(workers, requests_per_worker)
}

/// Aggregate public transport counters from every workload connection.
@internal
pub fn summarize_transport_diagnostics(
  diagnostics: List(#(Int, Int, Int, Int, Int, Int, Int, Int, Int, Int, Int)),
) -> List(Int) {
  diagnostics
  |> transport_diagnostic_summary
  |> transport_diagnostic_summary_values
}

fn transport_diagnostic_summary(
  diagnostics: List(#(Int, Int, Int, Int, Int, Int, Int, Int, Int, Int, Int)),
) -> TransportDiagnosticSummary {
  case diagnostics {
    [] -> empty_transport_diagnostic_summary()
    [first, ..rest] -> {
      let #(
        initial_rtt,
        final_rtt,
        initial_window,
        final_window,
        received,
        sent,
        retransmissions,
        flushes,
        coalesced,
        recovery,
        congested,
      ) = first
      summarize_transport_diagnostics_loop(
        rest,
        DiagnosticAccumulator(
          count: 1,
          initial_rtt: DiagnosticRange(initial_rtt, initial_rtt, initial_rtt),
          final_rtt: DiagnosticRange(final_rtt, final_rtt, final_rtt),
          initial_window: DiagnosticRange(
            initial_window,
            initial_window,
            initial_window,
          ),
          final_window: DiagnosticRange(
            final_window,
            final_window,
            final_window,
          ),
          retransmissions: retransmissions,
          maximum_retransmissions: retransmissions,
          packets_received: received,
          packets_sent: sent,
          batch_flushes: flushes,
          packets_coalesced: coalesced,
          in_recovery: recovery,
          congested: congested,
        ),
      )
    }
  }
}

fn summarize_transport_diagnostics_loop(
  diagnostics: List(#(Int, Int, Int, Int, Int, Int, Int, Int, Int, Int, Int)),
  accumulator: DiagnosticAccumulator,
) -> TransportDiagnosticSummary {
  case diagnostics {
    [] -> diagnostic_accumulator_summary(accumulator)
    [
      #(
        initial_rtt,
        final_rtt,
        initial_window,
        final_window,
        received,
        sent,
        retransmissions,
        flushes,
        coalesced,
        recovery,
        congested,
      ),
      ..rest
    ] ->
      summarize_transport_diagnostics_loop(
        rest,
        DiagnosticAccumulator(
          count: accumulator.count + 1,
          initial_rtt: update_diagnostic_range(
            accumulator.initial_rtt,
            initial_rtt,
          ),
          final_rtt: update_diagnostic_range(accumulator.final_rtt, final_rtt),
          initial_window: update_diagnostic_range(
            accumulator.initial_window,
            initial_window,
          ),
          final_window: update_diagnostic_range(
            accumulator.final_window,
            final_window,
          ),
          retransmissions: accumulator.retransmissions + retransmissions,
          maximum_retransmissions: int.max(
            accumulator.maximum_retransmissions,
            retransmissions,
          ),
          packets_received: accumulator.packets_received + received,
          packets_sent: accumulator.packets_sent + sent,
          batch_flushes: accumulator.batch_flushes + flushes,
          packets_coalesced: accumulator.packets_coalesced + coalesced,
          in_recovery: accumulator.in_recovery + recovery,
          congested: accumulator.congested + congested,
        ),
      )
  }
}

fn update_diagnostic_range(
  range: DiagnosticRange,
  value: Int,
) -> DiagnosticRange {
  DiagnosticRange(
    minimum: int.min(range.minimum, value),
    total: range.total + value,
    maximum: int.max(range.maximum, value),
  )
}

fn diagnostic_accumulator_summary(
  accumulator: DiagnosticAccumulator,
) -> TransportDiagnosticSummary {
  let DiagnosticRange(initial_rtt_min, initial_rtt_total, initial_rtt_max) =
    accumulator.initial_rtt
  let DiagnosticRange(final_rtt_min, final_rtt_total, final_rtt_max) =
    accumulator.final_rtt
  let DiagnosticRange(
    initial_window_min,
    initial_window_total,
    initial_window_max,
  ) = accumulator.initial_window
  let DiagnosticRange(final_window_min, final_window_total, final_window_max) =
    accumulator.final_window
  TransportDiagnosticSummary(
    initial_rtt_min: initial_rtt_min,
    initial_rtt_average: initial_rtt_total / accumulator.count,
    initial_rtt_max: initial_rtt_max,
    final_rtt_min: final_rtt_min,
    final_rtt_average: final_rtt_total / accumulator.count,
    final_rtt_max: final_rtt_max,
    initial_window_min: initial_window_min,
    initial_window_average: initial_window_total / accumulator.count,
    initial_window_max: initial_window_max,
    final_window_min: final_window_min,
    final_window_average: final_window_total / accumulator.count,
    final_window_max: final_window_max,
    retransmissions: accumulator.retransmissions,
    maximum_retransmissions: accumulator.maximum_retransmissions,
    packets_received: accumulator.packets_received,
    packets_sent: accumulator.packets_sent,
    batch_flushes: accumulator.batch_flushes,
    packets_coalesced: accumulator.packets_coalesced,
    in_recovery: accumulator.in_recovery,
    congested: accumulator.congested,
  )
}

fn empty_transport_diagnostic_summary() -> TransportDiagnosticSummary {
  TransportDiagnosticSummary(
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
  )
}

fn transport_diagnostic_summary_values(
  summary: TransportDiagnosticSummary,
) -> List(Int) {
  [
    summary.initial_rtt_min,
    summary.initial_rtt_average,
    summary.initial_rtt_max,
    summary.final_rtt_min,
    summary.final_rtt_average,
    summary.final_rtt_max,
    summary.initial_window_min,
    summary.initial_window_average,
    summary.initial_window_max,
    summary.final_window_min,
    summary.final_window_average,
    summary.final_window_max,
    summary.retransmissions,
    summary.maximum_retransmissions,
    summary.packets_received,
    summary.packets_sent,
    summary.batch_flushes,
    summary.packets_coalesced,
    summary.in_recovery,
    summary.congested,
  ]
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
  ports_before ports_before: Int,
  ports_after ports_after: Int,
  network_ports_before network_ports_before: Int,
  network_ports_after network_ports_after: Int,
  sockets_before sockets_before: Int,
  sockets_after sockets_after: Int,
  diagnostics_before diagnostics_before: DiagnosticMetrics,
  diagnostics_after diagnostics_after: DiagnosticMetrics,
  client_diagnostics client_diagnostics: List(ClientTransportDiagnostics),
) -> Nil {
  let DiagnosticMetrics(
    runtime_milliseconds: runtime_before,
    reductions: reductions_before,
    context_switches: context_switches_before,
    garbage_collections: garbage_collections_before,
    garbage_collected_words: garbage_collected_words_before,
    io_input_bytes: io_input_before,
    io_output_bytes: io_output_before,
    run_queue: run_queue_before,
  ) = diagnostics_before
  let DiagnosticMetrics(
    runtime_milliseconds: runtime_after,
    reductions: reductions_after,
    context_switches: context_switches_after,
    garbage_collections: garbage_collections_after,
    garbage_collected_words: garbage_collected_words_after,
    io_input_bytes: io_input_after,
    io_output_bytes: io_output_after,
    run_queue: run_queue_after,
  ) = diagnostics_after
  let TransportDiagnosticSummary(
    initial_rtt_min: initial_rtt_min,
    initial_rtt_average: initial_rtt_average,
    initial_rtt_max: initial_rtt_max,
    final_rtt_min: final_rtt_min,
    final_rtt_average: final_rtt_average,
    final_rtt_max: final_rtt_max,
    initial_window_min: initial_window_min,
    initial_window_average: initial_window_average,
    initial_window_max: initial_window_max,
    final_window_min: final_window_min,
    final_window_average: final_window_average,
    final_window_max: final_window_max,
    retransmissions: retransmissions,
    maximum_retransmissions: maximum_retransmissions,
    packets_received: packets_received,
    packets_sent: packets_sent,
    batch_flushes: batch_flushes,
    packets_coalesced: packets_coalesced,
    in_recovery: in_recovery,
    congested: congested,
  ) =
    client_diagnostics
    |> list.map(client_transport_diagnostic_point)
    |> transport_diagnostic_summary
  let fields = [
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
    int.to_string(ports_before),
    int.to_string(ports_after),
    int.to_string(network_ports_before),
    int.to_string(network_ports_after),
    int.to_string(sockets_before),
    int.to_string(sockets_after),
    int.to_string(diagnostic_counter_delta(
      before: runtime_before,
      after: runtime_after,
    )),
    int.to_string(diagnostic_counter_delta(
      before: reductions_before,
      after: reductions_after,
    )),
    int.to_string(diagnostic_counter_delta(
      before: context_switches_before,
      after: context_switches_after,
    )),
    int.to_string(diagnostic_counter_delta(
      before: garbage_collections_before,
      after: garbage_collections_after,
    )),
    int.to_string(diagnostic_counter_delta(
      before: garbage_collected_words_before,
      after: garbage_collected_words_after,
    )),
    int.to_string(diagnostic_counter_delta(
      before: io_input_before,
      after: io_input_after,
    )),
    int.to_string(diagnostic_counter_delta(
      before: io_output_before,
      after: io_output_after,
    )),
    int.to_string(run_queue_before),
    int.to_string(run_queue_after),
    int.to_string(initial_rtt_min),
    int.to_string(initial_rtt_average),
    int.to_string(initial_rtt_max),
    int.to_string(final_rtt_min),
    int.to_string(final_rtt_average),
    int.to_string(final_rtt_max),
    int.to_string(initial_window_min),
    int.to_string(initial_window_average),
    int.to_string(initial_window_max),
    int.to_string(final_window_min),
    int.to_string(final_window_average),
    int.to_string(final_window_max),
    int.to_string(retransmissions),
    int.to_string(maximum_retransmissions),
    int.to_string(packets_received),
    int.to_string(packets_sent),
    int.to_string(batch_flushes),
    int.to_string(packets_coalesced),
    int.to_string(in_recovery),
    int.to_string(congested),
  ]
  write_csv_fields(fields)
}

fn write_csv_fields(fields: List(String)) -> Nil {
  case csv_width_matches(fields) {
    True -> fields |> string.join(",") |> write_line
    False ->
      fail(#(
        "benchmark CSV width mismatch",
        list.length(csv_columns()),
        list.length(fields),
      ))
  }
}

fn client_transport_diagnostic_point(
  diagnostics: ClientTransportDiagnostics,
) -> #(Int, Int, Int, Int, Int, Int, Int, Int, Int, Int, Int) {
  #(
    diagnostics.initial_smoothed_rtt_microseconds,
    diagnostics.final_smoothed_rtt_microseconds,
    diagnostics.initial_congestion_window,
    diagnostics.final_congestion_window,
    diagnostics.packets_received,
    diagnostics.packets_sent,
    diagnostics.retransmissions,
    diagnostics.batch_flushes,
    diagnostics.packets_coalesced,
    diagnostics.in_recovery,
    diagnostics.congested,
  )
}

fn bool_integer(value: Bool) -> Int {
  use <- bool.guard(when: value, return: 0)
  1
}

fn must(result: Result(value, error), operation: String) -> value {
  case result {
    Ok(value) -> value
    Error(error) -> fail(#(operation, error))
  }
}
