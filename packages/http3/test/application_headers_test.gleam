import http3/internal/application_headers

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn exact_cookie_lines_are_joined_at_the_application_boundary_test() -> Nil {
  assert application_headers.combine_cookie_fields([
      #("x-before", "1"),
      #("cookie", "a=1"),
      #("set-cookie", "one=1"),
      #("x-middle", "2"),
      #("cookie", "b=2"),
      #("set-cookie", "two=2"),
      #("cookie", "c=3"),
    ])
    == [
      #("x-before", "1"),
      #("cookie", "a=1; b=2; c=3"),
      #("set-cookie", "one=1"),
      #("x-middle", "2"),
      #("set-cookie", "two=2"),
    ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn cookie_combination_is_exact_and_never_combines_set_cookie_test() -> Nil {
  assert application_headers.combine_cookie_fields([
      #("Cookie", "not-valid-inbound"),
      #("set-cookie", "a=1"),
      #("set-cookie", "b=2"),
    ])
    == [
      #("Cookie", "not-valid-inbound"),
      #("set-cookie", "a=1"),
      #("set-cookie", "b=2"),
    ]
}
