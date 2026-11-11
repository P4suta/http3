import http3_idle_wakeup

// nolint: unused_exports -- EUnit discovers public test functions by suffix.
pub fn cold_client_startup_does_not_consume_request_accept_deadline_test() -> Nil {
  http3_idle_wakeup.delayed_startup_regression()
}

// nolint: unused_exports -- EUnit discovers public test functions by suffix.
@external(erlang, "http3_idle_wakeup_ffi", "ownership_regression_test")
pub fn idle_observer_follows_the_live_owner_after_setup_parent_exit_test() -> Nil
