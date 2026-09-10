import gleeunit
import gleeunit/should
import http

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn http3_capability_is_observable_test() -> Nil {
  http.supports_http3()
  |> should.be_true()
}
