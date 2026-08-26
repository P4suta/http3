import gleam/erlang/process
import gleam/string
import gleam_quic/internal/qlog
import gleeunit/should

@external(erlang, "qlog_test_ffi", "with_directory")
fn with_directory(run: fn(String) -> value) -> value

@external(erlang, "qlog_test_ffi", "file_contains")
fn file_contains(directory: String, text: String) -> Bool

@external(erlang, "qlog_test_ffi", "fail_device_writer")
fn fail_device_writer(writer: qlog.Writer) -> Result(Nil, Nil)

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

    write_events(writer, 20_000)
    let qlog.Stats(_, write_errors, queued) = qlog.stats(writer) |> should.be_ok
    assert write_errors == 0
    assert queued <= 1025
    qlog.close(writer) |> should.be_ok

    assert file_contains(directory, "draft-ietf-quic-qlog-main-schema-14")
    assert file_contains(directory, "urn:ietf:params:qlog:events:quic-13")
    assert file_contains(directory, "urn:ietf:params:qlog:events:http3-13")
  })
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
    assert queued <= 2
    qlog.close(writer) |> should.be_ok
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

fn write_events(writer: qlog.Writer, remaining: Int) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      qlog.datagram_sent(writer, 1000 + remaining, 1200)
      write_events(writer, remaining - 1)
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
