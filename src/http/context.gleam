//// Typed, protocol-neutral metadata for one server request.

import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{type Option}
import gleam/string
import http/error

const maximum_deadline_milliseconds = 3_600_000

/// The negotiated HTTP protocol.
pub type Protocol {
  Http1
  Http2
  Http3
}

/// A validated transport endpoint.
pub type Endpoint {
  Endpoint(host: String, port: Int)
}

/// Authenticated TLS identity metadata, or an explicitly cleartext transport.
///
/// Certificate bytes and backend terms are deliberately absent. Fingerprints
/// are expected to be stable, redacted identifiers produced by the transport
/// adapter.
pub type TlsIdentity {
  CleartextIdentity
  TlsIdentity(
    service_identity: String,
    peer_certificate_fingerprint: Option(String),
  )
}

/// Whether this request used TLS early data.
pub type EarlyData {
  EarlyDataDisabled
  EarlyDataAccepted
  EarlyDataRejected
}

type KeyToken

type Attributes

type CancelHandle

@internal
pub type CancelSubscription

/// Package-internal cancellation lifecycle counters used by qualification
/// tests and developer diagnostics. No request metadata or payload is stored.
@internal
pub type CancellationSnapshot {
  CancellationSnapshot(
    cancelled: Bool,
    broker_stopped: Bool,
    active_subscriptions: Int,
    notifications: Int,
    explicit_unsubscriptions: Int,
    abandoned_subscriptions: Int,
  )
}

/// An opaque, identity-based key for one application value type.
///
/// A value inserted with a `Key(value)` can only be read through that same
/// key, so heterogeneous context extensions retain their Gleam type.
pub opaque type Key(value) {
  Key(token: KeyToken)
}

/// Immutable request metadata plus a shared cancellation signal.
pub opaque type Context {
  Context(
    protocol: Protocol,
    peer_endpoint: Endpoint,
    local_endpoint: Endpoint,
    deadline_milliseconds: Int,
    tls_identity: TlsIdentity,
    early_data: EarlyData,
    extended_connect_protocol: Option(String),
    attributes: Attributes,
    cancellation: CancelHandle,
  )
}

@external(erlang, "http_server_ffi", "new_context_key")
fn new_key_token() -> KeyToken

@external(erlang, "http_server_ffi", "new_context_attributes")
fn new_attributes() -> Attributes

@external(erlang, "http_server_ffi", "put_context_attribute")
fn put_attribute(
  attributes: Attributes,
  key: KeyToken,
  value: value,
) -> Attributes

@external(erlang, "http_server_ffi", "get_context_attribute")
fn get_attribute(attributes: Attributes, key: KeyToken) -> Option(value)

@external(erlang, "http_server_ffi", "new_cancel_handle")
fn new_cancel_handle() -> CancelHandle

@external(erlang, "http_server_ffi", "mark_cancelled")
fn mark_cancelled(handle: CancelHandle) -> Bool

@external(erlang, "http_server_ffi", "is_cancelled")
fn cancel_handle_is_cancelled(handle: CancelHandle) -> Bool

@external(erlang, "http_server_ffi", "subscribe_cancel_handle")
fn subscribe_cancel_handle(
  handle: CancelHandle,
  subscriber: Subject(Nil),
) -> CancelSubscription

@external(erlang, "http_server_ffi", "unsubscribe_cancel_handle")
fn unsubscribe_cancel_handle(subscription: CancelSubscription) -> Nil

@external(erlang, "http_server_ffi", "cancel_handle_snapshot")
fn cancel_handle_snapshot(
  handle: CancelHandle,
) -> #(Int, Int, Int, Int, Int, Int)

@external(erlang, "http_server_ffi", "monotonic_millisecond")
fn monotonic_millisecond() -> Int

/// Construct metadata for a protocol adapter after validating finite values.
pub fn new(
  protocol protocol: Protocol,
  peer_endpoint peer_endpoint: Endpoint,
  local_endpoint local_endpoint: Endpoint,
  within_milliseconds within_milliseconds: Int,
  tls_identity tls_identity: TlsIdentity,
  early_data early_data: EarlyData,
) -> Result(Context, error.Error) {
  case
    valid_endpoint(peer_endpoint)
    && valid_endpoint(local_endpoint)
    && valid_identity(tls_identity)
    && within_milliseconds > 0
    && within_milliseconds <= maximum_deadline_milliseconds
  {
    False -> Error(error.new(error.Policy(error.SecurityPolicy)))
    True ->
      Ok(Context(
        protocol:,
        peer_endpoint:,
        local_endpoint:,
        deadline_milliseconds: monotonic_millisecond() + within_milliseconds,
        tls_identity:,
        early_data:,
        extended_connect_protocol: option.None,
        attributes: new_attributes(),
        cancellation: new_cancel_handle(),
      ))
  }
}

/// Create a fresh typed extension key.
pub fn key() -> Key(value) {
  Key(new_key_token())
}

/// Return a context with one typed application value inserted.
pub fn put(context: Context, key: Key(value), value: value) -> Context {
  Context(
    ..context,
    attributes: put_attribute(context.attributes, key.token, value),
  )
}

/// Read a typed application value through the exact key that inserted it.
pub fn get(context: Context, key: Key(value)) -> Option(value) {
  get_attribute(context.attributes, key.token)
}

/// Return the negotiated protocol.
pub fn protocol(context: Context) -> Protocol {
  context.protocol
}

/// Return the validated peer endpoint.
pub fn peer_endpoint(context: Context) -> Endpoint {
  context.peer_endpoint
}

/// Return the local endpoint that received the request.
pub fn local_endpoint(context: Context) -> Endpoint {
  context.local_endpoint
}

/// Return authenticated, redacted TLS identity metadata.
pub fn tls_identity(context: Context) -> TlsIdentity {
  context.tls_identity
}

/// Return the early-data decision for this request.
pub fn early_data(context: Context) -> EarlyData {
  context.early_data
}

/// Attach one already negotiated HTTP/2 or HTTP/3 Extended CONNECT token.
///
/// Protocol adapters call this after validating `:protocol`. HTTP/1 and
/// malformed HTTP token values fail closed, so application-created contexts
/// cannot misrepresent an Upgrade request as Extended CONNECT.
pub fn with_extended_connect_protocol(
  context: Context,
  protocol: String,
) -> Result(Context, error.Error) {
  case context.protocol != Http1 && valid_token(protocol) {
    True ->
      Ok(Context(..context, extended_connect_protocol: option.Some(protocol)))
    False -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Return the validated Extended CONNECT `:protocol`, when present.
pub fn extended_connect_protocol(context: Context) -> Option(String) {
  context.extended_connect_protocol
}

/// Return the remaining request deadline, clamped at zero.
pub fn remaining_milliseconds(context: Context) -> Int {
  largest(0, context.deadline_milliseconds - monotonic_millisecond())
}

/// Signal cancellation to the handler and body cursors. Repeated calls are
/// harmless.
pub fn cancel(context: Context) -> Nil {
  let _first = mark_cancelled(context.cancellation)
  Nil
}

/// Return whether the request has been cancelled.
pub fn is_cancelled(context: Context) -> Bool {
  cancel_handle_is_cancelled(context.cancellation)
}

/// Register one event-driven, one-shot cancellation signal.
///
/// This is an internal adapter contract. The subscription is supervised by a
/// finite broker owned by the request context, and must be removed when the
/// adapter stops waiting. A context that was already cancelled signals the
/// subject before this function returns.
@internal
pub fn subscribe_cancellation(
  context: Context,
  subscriber: Subject(Nil),
) -> CancelSubscription {
  subscribe_cancel_handle(context.cancellation, subscriber)
}

/// Remove an internal cancellation subscription and drain its private signal.
@internal
pub fn unsubscribe_cancellation(subscription: CancelSubscription) -> Nil {
  unsubscribe_cancel_handle(subscription)
}

/// Inspect payload-free internal cancellation lifecycle counters.
@internal
pub fn cancellation_snapshot(context: Context) -> CancellationSnapshot {
  let #(
    cancelled,
    broker_stopped,
    active,
    notifications,
    unsubscribed,
    abandoned,
  ) = cancel_handle_snapshot(context.cancellation)
  CancellationSnapshot(
    cancelled: cancelled == 1,
    broker_stopped: broker_stopped == 1,
    active_subscriptions: active,
    notifications:,
    explicit_unsubscriptions: unsubscribed,
    abandoned_subscriptions: abandoned,
  )
}

fn valid_endpoint(endpoint: Endpoint) -> Bool {
  let Endpoint(host, port) = endpoint
  !string.is_empty(host) && port > 0 && port <= 65_535
}

fn valid_identity(identity: TlsIdentity) -> Bool {
  case identity {
    CleartextIdentity -> True
    TlsIdentity(service_identity, peer_certificate_fingerprint) ->
      !string.is_empty(service_identity)
      && case peer_certificate_fingerprint {
        option.None -> True
        option.Some(fingerprint) -> !string.is_empty(fingerprint)
      }
  }
}

fn valid_token(value: String) -> Bool {
  !string.is_empty(value)
  && list.all(string.to_utf_codepoints(value), fn(character) {
    token_character(string.utf_codepoint_to_int(character))
  })
}

fn token_character(character: Int) -> Bool {
  character >= 48
  && character <= 57
  || character >= 65
  && character <= 90
  || character >= 97
  && character <= 122
  || list.contains(
    [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126],
    character,
  )
}

fn largest(first: Int, second: Int) -> Int {
  case first > second {
    True -> first
    False -> second
  }
}
