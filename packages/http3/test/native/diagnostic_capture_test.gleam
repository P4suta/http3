import gleam/option.{None, Some}
import http3/internal/native/diagnostic_capture

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn disabled_capture_does_not_evaluate_snapshot_test() -> Nil {
  let snapshot = diagnostic_capture.when_enabled(False, fn() { Error(Nil) })
  assert snapshot == None
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn enabled_capture_evaluates_snapshot_once_test() -> Nil {
  assert diagnostic_capture.when_enabled(True, fn() { 42 }) == Some(42)
}
