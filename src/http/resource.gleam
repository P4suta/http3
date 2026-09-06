//// Atomic grant-before-growth resource accounting for request workers.

import http/error

const maximum_limit = 2_147_483_647

type ControllerHandle

type LeaseHandle

/// Finite worker and aggregate memory limits.
pub opaque type Limits {
  Limits(maximum_workers: Int, memory_bytes: Int)
}

/// A shared resource controller.
pub opaque type Controller {
  Controller(handle: ControllerHandle, limits: Limits)
}

/// One idempotently releasable worker reservation.
pub opaque type Lease {
  Lease(controller: ControllerHandle, handle: LeaseHandle)
}

/// Current bounded controller usage.
pub type Snapshot {
  Snapshot(
    active_workers: Int,
    memory_bytes: Int,
    maximum_workers: Int,
    maximum_memory_bytes: Int,
  )
}

@external(erlang, "http_server_ffi", "new_resource_controller")
fn new_controller(maximum_workers: Int, memory_bytes: Int) -> ControllerHandle

@external(erlang, "http_server_ffi", "resource_acquire")
fn raw_acquire(
  controller: ControllerHandle,
  memory_bytes: Int,
) -> Result(LeaseHandle, Int)

@external(erlang, "http_server_ffi", "resource_resize")
fn raw_resize(
  controller: ControllerHandle,
  lease: LeaseHandle,
  memory_bytes: Int,
) -> Result(Nil, Int)

@external(erlang, "http_server_ffi", "resource_release")
fn raw_release(controller: ControllerHandle, lease: LeaseHandle) -> Nil

@external(erlang, "http_server_ffi", "resource_snapshot")
fn raw_snapshot(controller: ControllerHandle) -> #(Int, Int)

@external(erlang, "http_server_ffi", "resource_stop")
fn raw_stop(controller: ControllerHandle) -> Nil

/// Conservative defaults for one protocol-neutral server.
pub fn default_limits() -> Limits {
  Limits(maximum_workers: 64, memory_bytes: 67_108_864)
}

/// Validate finite worker and aggregate memory limits.
pub fn limits(
  maximum_workers maximum_workers: Int,
  memory_bytes memory_bytes: Int,
) -> Result(Limits, error.Error) {
  case
    maximum_workers > 0
    && maximum_workers <= maximum_limit
    && memory_bytes > 0
    && memory_bytes <= maximum_limit
  {
    True -> Ok(Limits(maximum_workers:, memory_bytes:))
    False -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Return the configured worker limit.
pub fn maximum_workers(limits: Limits) -> Int {
  limits.maximum_workers
}

/// Return the configured aggregate memory limit.
pub fn maximum_memory_bytes(limits: Limits) -> Int {
  limits.memory_bytes
}

/// Allocate one shared controller.
pub fn start(limits: Limits) -> Controller {
  Controller(
    handle: new_controller(limits.maximum_workers, limits.memory_bytes),
    limits:,
  )
}

/// Acquire one worker and its initial memory grant before starting work.
pub fn acquire(
  controller: Controller,
  memory_bytes memory_bytes: Int,
) -> Result(Lease, error.Error) {
  case memory_bytes < 0 || memory_bytes > maximum_limit {
    True -> Error(error.new(error.Policy(error.SecurityPolicy)))
    False ->
      case raw_acquire(controller.handle, memory_bytes) {
        Ok(handle) -> Ok(Lease(controller.handle, handle))
        Error(code) -> Error(resource_error(code))
      }
  }
}

/// Resize one live grant atomically. Failed growth leaves the old grant
/// unchanged.
pub fn resize(
  lease: Lease,
  memory_bytes memory_bytes: Int,
) -> Result(Lease, error.Error) {
  case memory_bytes < 0 || memory_bytes > maximum_limit {
    True -> Error(error.new(error.Policy(error.SecurityPolicy)))
    False ->
      case raw_resize(lease.controller, lease.handle, memory_bytes) {
        Ok(Nil) -> Ok(lease)
        Error(code) -> Error(resource_error(code))
      }
  }
}

/// Release a grant. Repeated calls are harmless.
pub fn release(lease: Lease) -> Nil {
  raw_release(lease.controller, lease.handle)
}

/// Inspect current usage without exposing runtime handles.
pub fn snapshot(controller: Controller) -> Snapshot {
  let #(active_workers, memory_bytes) = raw_snapshot(controller.handle)
  Snapshot(
    active_workers:,
    memory_bytes:,
    maximum_workers: controller.limits.maximum_workers,
    maximum_memory_bytes: controller.limits.memory_bytes,
  )
}

/// Refuse future grants. Existing leases remain releasable.
pub fn stop(controller: Controller) -> Nil {
  raw_stop(controller.handle)
}

fn resource_error(code: Int) -> error.Error {
  case code {
    1 -> error.new(error.Resource(error.RequestWorkers))
    2 -> error.new(error.Resource(error.Memory))
    _ -> error.new(error.Service)
  }
}
