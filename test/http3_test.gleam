import gleeunit
import http3

pub fn main() -> Nil {
  gleeunit.main()
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn quic_backend_is_available_test() -> Nil {
  assert http3.is_supported()
}
