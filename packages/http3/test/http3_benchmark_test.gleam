import gleam/list
import http3_benchmark

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn benchmark_csv_schema_is_unique_and_runtime_width_checked_test() -> Nil {
  let columns = http3_benchmark.csv_columns()
  assert list.length(columns) == 50
  assert columns |> list.unique |> list.length == list.length(columns)
  assert http3_benchmark.csv_width_matches(list.repeat("", times: 50))
  assert !http3_benchmark.csv_width_matches(list.repeat("", times: 49))
  assert !http3_benchmark.csv_width_matches(list.repeat("", times: 51))
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn trial_deadline_is_inclusive_and_monotonic_test() -> Nil {
  assert !http3_benchmark.trial_deadline_expired(now: 999, deadline: 1000)
  assert http3_benchmark.trial_deadline_expired(now: 1000, deadline: 1000)
  assert http3_benchmark.trial_deadline_expired(now: 1001, deadline: 1000)
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn retained_resource_limits_are_inclusive_test() -> Nil {
  assert http3_benchmark.resources_are_bounded(#(
    16,
    1024,
    16,
    16,
    16,
    8,
    16,
    0,
    0,
  ))
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn every_retained_resource_limit_is_enforced_test() -> Nil {
  let limits = #(16, 1024, 16, 16, 16, 8, 16, 0, 0)
  let over_limit = [
    #(17, 1024, 16, 16, 16, 8, 16, 0, 0),
    #(16, 1025, 16, 16, 16, 8, 16, 0, 0),
    #(16, 1024, 17, 16, 16, 8, 16, 0, 0),
    #(16, 1024, 16, 17, 16, 8, 16, 0, 0),
    #(16, 1024, 16, 16, 17, 8, 16, 0, 0),
    #(16, 1024, 16, 16, 16, 9, 16, 0, 0),
    #(16, 1024, 16, 16, 16, 8, 17, 0, 0),
    #(16, 1024, 16, 16, 16, 8, 16, 1, 0),
    #(16, 1024, 16, 16, 16, 8, 16, 0, 1),
  ]
  assert http3_benchmark.resources_are_bounded(limits)
  assert over_limit
    |> list.all(fn(resources) {
      !http3_benchmark.resources_are_bounded(resources)
    })
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn diagnostic_counter_delta_clamps_runtime_resets_test() -> Nil {
  assert http3_benchmark.diagnostic_counter_delta(before: 100, after: 150) == 50
  assert http3_benchmark.diagnostic_counter_delta(before: 100, after: 100) == 0
  assert http3_benchmark.diagnostic_counter_delta(before: 150, after: 100) == 0
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn runtime_resource_convergence_checks_processes_ports_and_sockets_test() -> Nil {
  let converged = fn(processes_after, ports_after, network_after, sockets_after) {
    http3_benchmark.runtime_resources_converged(
      processes_before: 50,
      ports_before: 4,
      network_ports_before: 0,
      sockets_before: 2,
      processes_after: processes_after,
      ports_after: ports_after,
      network_ports_after: network_after,
      sockets_after: sockets_after,
    )
  }
  assert converged(49, 4, 0, 2)
  assert converged(40, 1, 0, 0)
  assert !converged(51, 4, 0, 2)
  assert !converged(50, 5, 0, 2)
  assert !converged(50, 4, 1, 2)
  assert !converged(50, 4, 0, 3)
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn progress_summary_distinguishes_slow_and_completed_workers_test() -> Nil {
  assert http3_benchmark.progress_summary(
      workers: [#(3, 1, 1000), #(5, 2, 9000), #(10, 4, 0)],
      now_milliseconds: 10_000,
      stall_milliseconds: 5000,
      requests_per_worker: 10,
    )
    == #(16, 2, 10, 1, 1, 0, 1, 1)
  assert http3_benchmark.progress_summary(
      workers: [],
      now_milliseconds: 10_000,
      stall_milliseconds: 5000,
      requests_per_worker: 10,
    )
    == #(0, 0, 0, 0, 0, 0, 0, 0)
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn progress_summary_uses_an_inclusive_stall_boundary_test() -> Nil {
  assert http3_benchmark.progress_summary(
      workers: [#(1, 1, 5000), #(1, 2, 5001), #(1, 3, 4999), #(1, 4, 0)],
      now_milliseconds: 10_000,
      stall_milliseconds: 5000,
      requests_per_worker: 1,
    )
    == #(1, 0, 1, 1, 1, 1, 1, 2)
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn progress_distribution_uses_nearest_rank_percentiles_test() -> Nil {
  assert http3_benchmark.progress_distribution(
      workers: [#(1, 1, 0), #(2, 4, 0), #(5, 4, 0), #(10, 4, 0)],
      requests_per_worker: 10,
    )
    == #(0, 2, 10, 10, 3)
  assert http3_benchmark.progress_distribution(
      workers: [],
      requests_per_worker: 10,
    )
    == #(0, 0, 0, 0, 0)
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn transport_diagnostic_summary_bounds_every_connection_test() -> Nil {
  assert http3_benchmark.summarize_transport_diagnostics([
      #(50, 20, 1000, 2000, 10, 20, 2, 3, 4, 1, 0),
      #(100, 40, 3000, 4000, 30, 40, 5, 6, 7, 0, 1),
    ])
    == [
      50,
      75,
      100,
      20,
      30,
      40,
      1000,
      2000,
      3000,
      2000,
      3000,
      4000,
      7,
      5,
      40,
      60,
      9,
      11,
      1,
      1,
    ]
  assert http3_benchmark.summarize_transport_diagnostics([])
    == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}
