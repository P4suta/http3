//// Pins the qlog scratch-directory fixture to the temporary directory
//// reported by the environment rather than a hard-coded "/tmp".

import gleam/string

@external(erlang, "http3_test_ffi", "with_tmpdir_override")
fn with_tmpdir_override(run: fn(String) -> value) -> value

@external(erlang, "http3_test_ffi", "with_qlog_directory")
fn with_qlog_directory(run: fn(String) -> result) -> #(result, Int)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qlog_directory_follows_temporary_directory_environment_test() -> Nil {
  with_tmpdir_override(fn(temporary_root) {
    let #(directory, _traces) = with_qlog_directory(fn(directory) { directory })
    assert string.starts_with(directory, temporary_root <> "/")
  })
}
