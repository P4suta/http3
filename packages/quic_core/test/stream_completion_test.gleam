import gleam/int
import gleam/option.{None, Some}
import quic_core/internal/stream_completion

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_send_terminal_cause_cannot_be_replaced_by_a_later_outcome_test() -> Nil {
  let history =
    stream_completion.new(2)
    |> stream_completion.record(0, stream_completion.Stopped(0x10c))
    |> stream_completion.record(0, stream_completion.Acknowledged)
    |> stream_completion.record(0, stream_completion.Reset(0x101))
  assert stream_completion.get(history, 0)
    == Some(stream_completion.Stopped(0x10c))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn terminal_history_evicts_old_evidence_without_inventing_success_test() -> Nil {
  let history =
    stream_completion.new(0)
    |> stream_completion.record(0, stream_completion.Stopped(0x10c))
    |> stream_completion.record(4, stream_completion.Acknowledged)
  assert stream_completion.get(history, 0) == None
  assert stream_completion.get(history, 4)
    == Some(stream_completion.Acknowledged)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn terminal_history_has_a_fixed_upper_bound_test() -> Nil {
  let history =
    int.range(1, 34, stream_completion.new(1_000_000), fn(history, identifier) {
      stream_completion.record(
        history,
        identifier,
        stream_completion.Acknowledged,
      )
    })
  assert stream_completion.get(history, 1) == None
  assert stream_completion.get(history, 2)
    == Some(stream_completion.Acknowledged)
  assert stream_completion.get(history, 33)
    == Some(stream_completion.Acknowledged)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completion_feed_reads_retained_events_once_in_causal_order_test() -> Nil {
  let history =
    stream_completion.new(4)
    |> stream_completion.record(4, stream_completion.Acknowledged)
    |> stream_completion.record(8, stream_completion.Stopped(0x10c))
    |> stream_completion.record(12, stream_completion.Reset(0x101))
  assert stream_completion.after(history, 0)
    == Ok([
      stream_completion.Event(1, 4, stream_completion.Acknowledged),
      stream_completion.Event(2, 8, stream_completion.Stopped(0x10c)),
      stream_completion.Event(3, 12, stream_completion.Reset(0x101)),
    ])
  assert stream_completion.after(history, 2)
    == Ok([stream_completion.Event(3, 12, stream_completion.Reset(0x101))])
  assert stream_completion.after(history, 3) == Ok([])
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completion_feed_reports_eviction_and_future_cursor_without_skipping_test() -> Nil {
  let history =
    stream_completion.new(2)
    |> stream_completion.record(4, stream_completion.Acknowledged)
    |> stream_completion.record(8, stream_completion.Acknowledged)
    |> stream_completion.record(12, stream_completion.Acknowledged)
  assert stream_completion.after(history, 0)
    == Error(stream_completion.HistoryOverflow(2))
  assert stream_completion.after(history, 4)
    == Error(stream_completion.CursorAhead(3))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completion_publication_uses_a_strict_absolute_deadline_test() -> Nil {
  assert stream_completion.publication_allowed(99, 100)
  assert !stream_completion.publication_allowed(100, 100)
  assert !stream_completion.publication_allowed(101, 100)
}
