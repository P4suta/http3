//// Typed persistence adapters for bounded client policy state.

import gleam/bool
import http/error

/// The explicit network-isolation partition supplied to every callback.
pub type Partition {
  Partition(top_level_site: String, profile: String)
}

/// One persisted cookie with a lifetime relative to adapter load or put.
pub type CookieRecord {
  CookieRecord(
    key: String,
    name: String,
    value: String,
    domain: String,
    path: String,
    host_only: Bool,
    secure: Bool,
    expires_in_milliseconds: Int,
  )
}

/// One complete persisted response-cache entry.
pub type CacheRecord {
  CacheRecord(
    key: String,
    status: Int,
    headers: List(#(String, String)),
    bytes: BitArray,
    trailers: List(#(String, String)),
    expires_in_milliseconds: Int,
  )
}

/// One persisted Strict-Transport-Security entry.
pub type HstsRecord {
  HstsRecord(
    key: String,
    host: String,
    include_subdomains: Bool,
    expires_in_milliseconds: Int,
  )
}

/// One persisted authenticated HTTP/3 discovery entry.
pub type AltSvcRecord {
  AltSvcRecord(
    key: String,
    origin_host: String,
    origin_port: Int,
    alternative_port: Int,
    expires_in_milliseconds: Int,
  )
}

/// A typed load/upsert/remove adapter with one hard callback deadline.
pub opaque type Adapter(record) {
  Adapter(
    load: fn(Partition, Int) -> Result(List(record), Nil),
    put: fn(Partition, record, Int) -> Result(Nil, Nil),
    remove: fn(Partition, String, Int) -> Result(Nil, Nil),
    timeout_milliseconds: Int,
  )
}

/// Construct an adapter after validating its finite deadline.
pub fn new(
  load: fn(Partition, Int) -> Result(List(record), Nil),
  put: fn(Partition, record, Int) -> Result(Nil, Nil),
  remove: fn(Partition, String, Int) -> Result(Nil, Nil),
  timeout_milliseconds: Int,
) -> Result(Adapter(record), error.Error) {
  use <- bool.guard(
    when: timeout_milliseconds <= 0 || timeout_milliseconds > 2_147_483_647,
    return: Error(error.new(error.Policy(error.SecurityPolicy))),
  )
  Ok(Adapter(load, put, remove, timeout_milliseconds))
}

/// Return the hard deadline applied to every adapter callback.
pub fn timeout_milliseconds(adapter: Adapter(record)) -> Int {
  adapter.timeout_milliseconds
}

/// Invoke the configured load callback. The client wraps this in supervision.
pub fn load(
  adapter adapter: Adapter(record),
  partition partition: Partition,
) -> Result(List(record), Nil) {
  adapter.load(partition, adapter.timeout_milliseconds)
}

/// Invoke the configured upsert callback. The client wraps this in supervision.
pub fn put(
  adapter adapter: Adapter(record),
  partition partition: Partition,
  record record: record,
) -> Result(Nil, Nil) {
  adapter.put(partition, record, adapter.timeout_milliseconds)
}

/// Invoke the configured removal callback. The client wraps this in supervision.
pub fn remove(
  adapter adapter: Adapter(record),
  partition partition: Partition,
  key key: String,
) -> Result(Nil, Nil) {
  adapter.remove(partition, key, adapter.timeout_milliseconds)
}
