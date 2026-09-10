import http3/internal/native/error_code

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn maps_registered_and_unknown_application_errors_test() -> Nil {
  assert error_code.encode(error_code.NoError) == 0x100
  assert error_code.encode(error_code.DatagramError) == 0x33
  assert error_code.decode(0x200) == error_code.QpackDecompressionFailed
  let unknown = error_code.decode(0xdead)
  assert unknown == error_code.ReservedOrUnknown(0xdead)
  assert error_code.effective(unknown) == error_code.NoError
}
