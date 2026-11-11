import gleeunit
import http/error
import http/resource

@external(erlang, "http_server_contract_test_ffi", "resource_primitive_failures_are_typed")
fn resource_primitive_failures_are_typed() -> Bool

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn primitive_failures_refuse_without_losing_capacity_test() -> Nil {
  assert resource_primitive_failures_are_typed()
}

pub fn controller_grants_before_growth_and_recovers_every_lease_test() -> Nil {
  let assert Ok(limits) = resource.limits(maximum_workers: 2, memory_bytes: 100)
  let controller = resource.start(limits)
  let assert Ok(first) = resource.acquire(controller, memory_bytes: 60)

  let assert Error(memory_failure) =
    resource.acquire(controller, memory_bytes: 50)
  assert error.kind(memory_failure) == error.Resource(error.Memory)

  let assert Ok(second) = resource.acquire(controller, memory_bytes: 40)
  let assert Error(worker_failure) =
    resource.acquire(controller, memory_bytes: 0)
  assert error.kind(worker_failure) == error.Resource(error.RequestWorkers)
  assert resource.snapshot(controller)
    == resource.Snapshot(
      active_workers: 2,
      memory_bytes: 100,
      maximum_workers: 2,
      maximum_memory_bytes: 100,
    )

  let assert Error(growth_failure) = resource.resize(second, memory_bytes: 41)
  assert error.kind(growth_failure) == error.Resource(error.Memory)
  assert resource.snapshot(controller).memory_bytes == 100

  resource.release(first)
  resource.release(first)
  let assert Ok(second) = resource.resize(second, memory_bytes: 75)
  assert resource.snapshot(controller).memory_bytes == 75
  resource.release(second)
  assert resource.snapshot(controller).active_workers == 0
  assert resource.snapshot(controller).memory_bytes == 0
}

pub fn closed_controller_refuses_new_work_but_releases_existing_work_test() -> Nil {
  let controller = resource.start(resource.default_limits())
  let assert Ok(lease) = resource.acquire(controller, memory_bytes: 1)

  resource.stop(controller)
  let assert Error(failure) = resource.acquire(controller, memory_bytes: 1)
  assert error.kind(failure) == error.Service

  resource.release(lease)
  assert resource.snapshot(controller).active_workers == 0
}
