import gleeunit

@external(erlang, "http_cookie_store_test", "expiry_and_last_access_control_eviction")
fn expiry_and_last_access_control_eviction() -> Nil

@external(erlang, "http_cookie_store_test", "close_removes_session_state")
fn close_removes_session_state() -> Nil

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn expired_first_then_least_recently_accessed_eviction_test() -> Nil {
  expiry_and_last_access_control_eviction()
}

pub fn client_close_removes_session_cookie_state_test() -> Nil {
  close_removes_session_state()
}
