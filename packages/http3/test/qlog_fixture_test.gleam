//// Pins the qlog scratch-directory fixture to the temporary directory
//// reported by the environment rather than a hard-coded "/tmp".

import gleam/string
import http3_test_support

@external(erlang, "http3_test_ffi", "write_probe_file")
fn write_probe_file(directory: String) -> Bool

// The two environment overrides below mutate the process-global environment, so
// they rely on gleeunit running test modules sequentially; each restores every
// variable it touched before returning.
@external(erlang, "http3_test_ffi", "with_tmpdir_override")
fn with_tmpdir_override(run: fn(String) -> value) -> value

@external(erlang, "http3_test_ffi", "with_temp_override")
fn with_temp_override(run: fn(String) -> value) -> value

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qlog_directory_follows_temporary_directory_environment_test() -> Nil {
  assert_qlog_directory_is_writable_under_root(with_tmpdir_override)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qlog_directory_falls_back_to_temp_environment_test() -> Nil {
  assert_qlog_directory_is_writable_under_root(with_temp_override)
}

/// Assert the qlog fixture directory sits under the root the override
/// installed and that a file can actually be written inside it.
fn assert_qlog_directory_is_writable_under_root(
  with_override: fn(fn(String) -> Nil) -> Nil,
) -> Nil {
  with_override(fn(temporary_root) {
    let #(directory, _traces) =
      http3_test_support.with_qlog_directory(fn(directory) {
        assert write_probe_file(directory)
        directory
      })
    assert string.starts_with(directory, temporary_root <> "/")
  })
}
