import gleeunit
import http/internal/http2/flow_control

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn data_consumption_is_bounded_by_available_credit_test() -> Nil {
  let assert Ok(window) = flow_control.new(10)
  let assert Ok(window) = flow_control.consume(window, 4)
  assert flow_control.available(window) == 6
  let assert Ok(window) = flow_control.consume(window, 6)
  assert flow_control.available(window) == 0
  assert flow_control.consume(window, 1)
    == Error(flow_control.FlowControlExceeded)
}

pub fn window_update_requires_a_nonzero_31_bit_increment_test() -> Nil {
  let assert Ok(window) = flow_control.new(10)
  assert flow_control.increase(window, 0)
    == Error(flow_control.InvalidIncrement)
  assert flow_control.increase(window, 2_147_483_648)
    == Error(flow_control.InvalidIncrement)

  let assert Ok(maximum) = flow_control.new(2_147_483_647)
  assert flow_control.increase(maximum, 1) == Error(flow_control.WindowOverflow)
}

pub fn initial_window_reduction_can_block_then_update_recovers_test() -> Nil {
  let assert Ok(window) = flow_control.new(20)
  let assert Ok(window) = flow_control.consume(window, 15)
  let assert Ok(window) = flow_control.apply_initial_window_size(window, 20, 10)
  assert flow_control.available(window) == -5
  let assert Ok(unchanged) = flow_control.consume(window, 0)
  assert flow_control.available(unchanged) == -5
  assert flow_control.consume(window, 1)
    == Error(flow_control.FlowControlExceeded)

  let assert Ok(window) = flow_control.increase(window, 8)
  assert flow_control.available(window) == 3
  let assert Ok(window) = flow_control.consume(window, 3)
  assert flow_control.available(window) == 0
}

pub fn invalid_limits_and_consumption_are_typed_test() -> Nil {
  assert flow_control.new(-1) == Error(flow_control.InvalidLimit)
  assert flow_control.new(2_147_483_648) == Error(flow_control.InvalidLimit)
  let assert Ok(window) = flow_control.new(10)
  assert flow_control.consume(window, -1)
    == Error(flow_control.InvalidConsumption)
  assert flow_control.apply_initial_window_size(window, -1, 10)
    == Error(flow_control.InvalidLimit)
}
