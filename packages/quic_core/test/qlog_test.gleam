import gleam/erlang/process
import gleam/string
import gleeunit/should
import quic_core
import quic_core/diagnostics
import quic_core/internal/qlog

@external(erlang, "qlog_test_ffi", "with_directory")
fn with_directory(run: fn(String) -> value) -> value

@external(erlang, "qlog_test_ffi", "file_contains")
fn file_contains(directory: String, text: String) -> Bool

@external(erlang, "qlog_test_ffi", "files_are_rfc7464_sequences")
fn files_are_rfc7464_sequences(directory: String) -> Bool

@external(erlang, "qlog_test_ffi", "write_two_producer_interleaving")
fn write_two_producer_interleaving(writer: qlog.Writer) -> Result(Nil, Nil)

@external(erlang, "qlog_test_ffi", "file_event_times")
fn file_event_times(directory: String) -> Result(List(Int), Nil)

@external(erlang, "qlog_test_ffi", "fail_device_writer")
fn fail_device_writer(writer: qlog.Writer) -> Result(Nil, Nil)

@external(erlang, "qlog_test_ffi", "with_suspended_device_writer")
fn with_suspended_device_writer(
  writer: qlog.Writer,
  run: fn() -> value,
) -> Result(value, Nil)

@external(erlang, "qlog_test_ffi", "write_probe_file")
fn write_probe_file(directory: String) -> Bool

// The two environment overrides below mutate the process-global environment, so
// they rely on gleeunit running test modules sequentially; each restores every
// variable it touched before returning.
@external(erlang, "qlog_test_ffi", "with_tmpdir_override")
fn with_tmpdir_override(run: fn(String) -> value) -> value

@external(erlang, "qlog_test_ffi", "with_temp_override")
fn with_temp_override(run: fn(String) -> value) -> value

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn scratch_directory_follows_temporary_directory_environment_test() -> Nil {
  assert_scratch_directory_is_writable_under_root(with_tmpdir_override)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn scratch_directory_falls_back_to_temp_environment_test() -> Nil {
  assert_scratch_directory_is_writable_under_root(with_temp_override)
}

/// Assert the scratch directory sits under the root the override installed and
/// that a file can actually be written inside it.
fn assert_scratch_directory_is_writable_under_root(
  with_override: fn(fn(String) -> Nil) -> Nil,
) -> Nil {
  with_override(fn(temporary_root) {
    let directory =
      with_directory(fn(directory) {
        assert write_probe_file(directory)
        directory
      })
    assert string.starts_with(directory, temporary_root <> "/")
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn async_writer_is_bounded_and_revision_pinned_test() -> Nil {
  with_directory(fn(directory) {
    let writer = qlog.open(directory, qlog.Client, 1000, 1024) |> should.be_ok
    assert qlog.stats(writer) == Ok(qlog.Stats(0, 0, 0))

    qlog.connection_started(writer, 1000)
    qlog.path_updated(writer, 1001)
    write_events(writer, 20_000)
    let qlog.Stats(_, write_errors, queued) = qlog.stats(writer) |> should.be_ok
    assert write_errors == 0
    assert queued <= 1024
    qlog.close(writer) |> should.be_ok

    assert file_contains(directory, "draft-ietf-quic-qlog-main-schema-14")
    assert file_contains(directory, "urn:ietf:params:qlog:events:quic-13")
    assert file_contains(directory, "urn:ietf:params:qlog:events:http3-13")
    assert file_contains(directory, "urn:ietf:params:qlog:events:loglevel")
    assert file_contains(directory, "\"local\":{},\"remote\":{}")
    assert file_contains(directory, "\"new\":\"migration_complete\"")
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qlog_records_are_rfc7464_utf8_rs_json_lf_sequences_test() -> Nil {
  with_directory(fn(directory) {
    let writer = qlog.open(directory, qlog.Server, 1000, 8) |> should.be_ok
    qlog.connection_started(writer, 1000)
    qlog.connection_closed(writer, 1001)
    qlog.close(writer) |> should.be_ok

    assert files_are_rfc7464_sequences(directory)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn concurrent_producers_cannot_regress_admitted_event_time_test() -> Nil {
  with_directory(fn(directory) {
    let writer = qlog.open(directory, qlog.Client, 1000, 8) |> should.be_ok

    // The fixture deterministically admits producer A at 0, producer B at 2,
    // then A at 1 and B at 3. The writer owns the cross-producer watermark.
    write_two_producer_interleaving(writer) |> should.be_ok
    qlog.close(writer) |> should.be_ok

    assert file_event_times(directory) == Ok([0, 2, 2, 3])
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn public_diagnostics_writer_is_opaque_bounded_and_redacted_test() -> Nil {
  with_directory(fn(directory) {
    let writer =
      diagnostics.open(directory, diagnostics.Client, 1000, 64)
      |> should.be_ok
    diagnostics.connection_started(writer, 1000)
    diagnostics.datagram_received(writer, 1001, 1200)
    diagnostics.datagram_sent(writer, 1002, 1180)
    diagnostics.packet_received(writer, 1003, diagnostics.OneRtt, 1180)
    diagnostics.packet_sent(writer, 1004, diagnostics.OneRtt, 112)
    diagnostics.key_updated(writer, 1005, diagnostics.ClientOneRttSecret)
    diagnostics.key_discarded(writer, 1006, diagnostics.ClientHandshakeSecret)
    diagnostics.recovery_metrics(
      writer,
      1007,
      diagnostics.PathStats(1, 2, 1, 1, 12_000, 112, False, False),
    )
    diagnostics.congestion_state_updated(writer, 1008, diagnostics.SlowStart)
    diagnostics.congestion_state_updated_with_trigger(
      writer,
      1008,
      diagnostics.SlowStart,
      diagnostics.PersistentCongestion,
    )
    diagnostics.http3_parameters_set(writer, 1009, diagnostics.LocalInitiator)
    diagnostics.http3_stream_type_set(
      writer,
      1010,
      0,
      diagnostics.RequestStream,
    )
    diagnostics.http3_frame_created(
      writer,
      1011,
      0,
      diagnostics.HeadersFrame,
      32,
    )
    diagnostics.http3_frame_parsed(writer, 1012, 0, diagnostics.DataFrame, 12)
    let code = diagnostics.application_code(2206) |> should.be_ok
    assert diagnostics.application_code(-1)
      == Error(diagnostics.InvalidDiagnosticCode)
    assert diagnostics.application_code(2_147_483_648)
      == Error(diagnostics.InvalidDiagnosticCode)
    diagnostics.application_error(writer, 1013, code)
    diagnostics.migration_started(writer, 1014)
    diagnostics.migration_abandoned(writer, 1015)
    diagnostics.path_updated(writer, 1016)
    let diagnostics.Stats(dropped, errors, queued) =
      diagnostics.stats(writer) |> should.be_ok
    assert dropped == 0
    assert errors == 0
    assert queued <= 64
    diagnostics.connection_closed(writer, 1017)
    assert diagnostics.close(writer) == Ok(Nil)
    assert diagnostics.close(writer) == Ok(Nil)

    assert file_contains(directory, "draft-ietf-quic-qlog-main-schema-14")
    assert file_contains(directory, "\"name\":\"quic:packet_received\"")
    assert file_contains(directory, "\"name\":\"quic:packet_sent\"")
    assert file_contains(directory, "\"name\":\"quic:key_updated\"")
    assert file_contains(directory, "\"name\":\"quic:key_discarded\"")
    assert file_contains(
      directory,
      "\"name\":\"quic:recovery_metrics_updated\"",
    )
    assert file_contains(
      directory,
      "\"name\":\"quic:congestion_state_updated\"",
    )
    assert file_contains(
      directory,
      "\"new\":\"slow_start\",\"trigger\":\"persistent_congestion\"",
    )
    assert file_contains(directory, "\"name\":\"http3:parameters_set\"")
    assert file_contains(directory, "\"name\":\"http3:stream_type_set\"")
    assert file_contains(directory, "\"name\":\"http3:frame_created\"")
    assert file_contains(directory, "\"name\":\"http3:frame_parsed\"")
    assert file_contains(directory, "urn:ietf:params:qlog:events:loglevel")
    assert file_contains(
      directory,
      "\"name\":\"loglevel:error\",\"data\":{\"code\":2206}",
    )
    assert !file_contains(directory, "\"message\":")
    assert file_contains(directory, "\"new\":\"migration_started\"")
    assert file_contains(directory, "\"new\":\"migration_abandoned\"")
    assert !file_contains(directory, "1200-byte-payload")
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn application_sink_emits_only_typed_payload_free_metadata_test() -> Nil {
  with_directory(fn(directory) {
    let writer = qlog.open(directory, qlog.Server, 1000, 32) |> should.be_ok
    let sink = diagnostics.application_sink(writer)
    diagnostics.emit_http3_parameters_set(
      sink,
      1001,
      diagnostics.LocalInitiator,
    )
    diagnostics.emit_http3_stream_type_set(
      sink,
      1002,
      quic_core.StreamId(3),
      diagnostics.ControlStream,
    )
    diagnostics.emit_http3_frame_created(
      sink,
      1003,
      quic_core.StreamId(3),
      diagnostics.SettingsFrame,
      0,
    )
    diagnostics.emit_http3_frame_parsed(
      sink,
      1004,
      quic_core.StreamId(0),
      diagnostics.HeadersFrame,
      0,
    )
    let code = diagnostics.application_code(0x101) |> should.be_ok
    diagnostics.emit_application_error(sink, 1005, code)
    qlog.close(writer) |> should.be_ok

    assert file_contains(directory, "\"name\":\"http3:parameters_set\"")
    assert file_contains(directory, "\"name\":\"http3:stream_type_set\"")
    assert file_contains(directory, "\"name\":\"http3:frame_created\"")
    assert file_contains(directory, "\"name\":\"http3:frame_parsed\"")
    assert file_contains(
      directory,
      "\"name\":\"loglevel:error\",\"data\":{\"code\":257}",
    )
    assert !file_contains(directory, "\"message\":")
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn public_diagnostics_clock_is_non_negative_and_monotonic_test() -> Nil {
  let before = diagnostics.monotonic_milliseconds()
  process.sleep(1)
  let after = diagnostics.monotonic_milliseconds()

  assert before >= 0
  assert after >= before
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn configured_queue_limit_is_enforced_test() -> Nil {
  with_directory(fn(directory) {
    assert qlog.open(directory, qlog.Client, 1000, 0)
      == Error(qlog.InvalidLimit)
    let writer = qlog.open(directory, qlog.Client, 1000, 1) |> should.be_ok
    let finished = process.new_subject()
    spawn_event_writers(writer, finished, 256)
    await_event_writers(finished, 256)
    let qlog.Stats(dropped, write_errors, queued) =
      qlog.stats(writer) |> should.be_ok
    assert dropped > 0
    assert write_errors == 0
    assert queued <= 1
    qlog.close(writer) |> should.be_ok
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn queue_limit_includes_the_device_write_in_flight_test() -> Nil {
  with_directory(fn(directory) {
    let writer = qlog.open(directory, qlog.Client, 1000, 1) |> should.be_ok
    with_suspended_device_writer(writer, fn() {
      qlog.datagram_sent(writer, 1000, 1200)
      qlog.datagram_sent(writer, 1001, 1200)
      assert qlog.stats(writer) == Ok(qlog.Stats(1, 0, 1))
    })
    |> should.be_ok
    qlog.close(writer) |> should.be_ok
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn dropped_future_event_does_not_advance_time_watermark_test() -> Nil {
  with_directory(fn(directory) {
    let writer = qlog.open(directory, qlog.Client, 1000, 1) |> should.be_ok
    with_suspended_device_writer(writer, fn() {
      qlog.datagram_sent(writer, 1000, 1200)
      qlog.datagram_sent(writer, 2000, 1200)
      assert qlog.stats(writer) == Ok(qlog.Stats(1, 0, 1))
    })
    |> should.be_ok

    await_empty_queue(writer, 100) |> should.be_ok
    qlog.datagram_sent(writer, 1001, 1200)
    qlog.close(writer) |> should.be_ok

    assert file_event_times(directory) == Ok([0, 1])
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn writer_failure_is_counted_without_crashing_transport_test() -> Nil {
  with_directory(fn(directory) {
    let writer = qlog.open(directory, qlog.Server, 1000, 8) |> should.be_ok
    fail_device_writer(writer) |> should.be_ok
    let qlog.Stats(_, write_errors, queued) =
      await_write_failure(writer, 100) |> should.be_ok
    assert write_errors == 1
    assert queued == 0

    qlog.datagram_received(writer, 1001, 1200)
    let qlog.Stats(dropped, errors, _) = qlog.stats(writer) |> should.be_ok
    assert dropped == 1
    assert errors == 1
    assert qlog.close(writer) == Error(qlog.WriteFailed(3))
    assert qlog.close(writer) == Ok(Nil)
  })
}

fn await_write_failure(
  writer: qlog.Writer,
  remaining: Int,
) -> Result(qlog.Stats, Nil) {
  case qlog.stats(writer) {
    Ok(qlog.Stats(_, errors, _) as stats) if errors > 0 -> Ok(stats)
    _ if remaining > 0 -> {
      process.sleep(1)
      await_write_failure(writer, remaining - 1)
    }
    _ -> Error(Nil)
  }
}

fn await_empty_queue(writer: qlog.Writer, remaining: Int) -> Result(Nil, Nil) {
  case qlog.stats(writer) {
    Ok(qlog.Stats(_, _, 0)) -> Ok(Nil)
    _ if remaining > 0 -> {
      process.sleep(1)
      await_empty_queue(writer, remaining - 1)
    }
    _ -> Error(Nil)
  }
}

fn write_events(writer: qlog.Writer, remaining: Int) -> Nil {
  write_events_from(writer, 1, remaining)
}

fn write_events_from(writer: qlog.Writer, current: Int, last: Int) -> Nil {
  case current > last {
    True -> Nil
    False -> {
      qlog.datagram_sent(writer, 1000 + current, 1200)
      write_events_from(writer, current + 1, last)
    }
  }
}

fn spawn_event_writers(
  writer: qlog.Writer,
  finished: process.Subject(Nil),
  remaining: Int,
) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      process.spawn_unlinked(fn() {
        qlog.datagram_sent(writer, 1000, 1200)
        process.send(finished, Nil)
      })
      spawn_event_writers(writer, finished, remaining - 1)
    }
  }
}

fn await_event_writers(finished: process.Subject(Nil), remaining: Int) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      process.receive(finished, 5000) |> should.be_ok
      await_event_writers(finished, remaining - 1)
    }
  }
}
