import gleam/bool
import gleam/erlang/process
import gleam/option.{None, Some}
import gleeunit
import http/context
import http/error

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn context_exposes_typed_transport_metadata_and_opaque_values_test() -> Nil {
  let peer = context.Endpoint("203.0.113.8", 443)
  let local = context.Endpoint("192.0.2.4", 8443)
  let identity =
    context.TlsIdentity(
      service_identity: "api.example",
      peer_certificate_fingerprint: Some("sha256:peer"),
    )
  let assert Ok(value) =
    context.new(
      context.Http2,
      peer,
      local,
      within_milliseconds: 1000,
      tls_identity: identity,
      early_data: context.EarlyDataRejected,
    )
  let string_key: context.Key(String) = context.key()
  let integer_key: context.Key(Int) = context.key()
  let value =
    value
    |> context.put(string_key, "tenant-a")
    |> context.put(integer_key, 42)

  assert context.protocol(value) == context.Http2
  assert context.peer_endpoint(value) == peer
  assert context.local_endpoint(value) == local
  assert context.tls_identity(value) == identity
  assert context.early_data(value) == context.EarlyDataRejected
  assert context.extended_connect_protocol(value) == None
  let assert Ok(value) =
    context.with_extended_connect_protocol(value, "websocket")
  assert context.extended_connect_protocol(value) == Some("websocket")
  assert context.get(value, string_key) == Some("tenant-a")
  assert context.get(value, integer_key) == Some(42)
  let missing: context.Key(String) = context.key()
  assert context.get(value, missing) == None
  assert context.remaining_milliseconds(value) > 0
  assert context.remaining_milliseconds(value) <= 1000
  assert !context.is_cancelled(value)

  context.cancel(value)
  context.cancel(value)
  assert context.is_cancelled(value)
}

pub fn extended_connect_context_rejects_h1_and_invalid_tokens_test() -> Nil {
  let assert Ok(h1) =
    context.new(
      context.Http1,
      context.Endpoint("peer", 80),
      context.Endpoint("local", 8080),
      within_milliseconds: 1000,
      tls_identity: context.CleartextIdentity,
      early_data: context.EarlyDataDisabled,
    )
  let assert Error(h1_error) =
    context.with_extended_connect_protocol(h1, "websocket")
  assert error.kind(h1_error) == error.Policy(error.SecurityPolicy)

  let assert Ok(h2) =
    context.new(
      context.Http2,
      context.Endpoint("peer", 443),
      context.Endpoint("local", 8443),
      within_milliseconds: 1000,
      tls_identity: context.CleartextIdentity,
      early_data: context.EarlyDataDisabled,
    )
  let assert Error(token_error) =
    context.with_extended_connect_protocol(h2, "not a token")
  assert error.kind(token_error) == error.Policy(error.SecurityPolicy)
}

pub fn context_rejects_invalid_endpoint_and_deadline_before_work_test() -> Nil {
  let result =
    context.new(
      context.Http1,
      context.Endpoint("peer", 0),
      context.Endpoint("local", 80),
      within_milliseconds: 0,
      tls_identity: context.CleartextIdentity,
      early_data: context.EarlyDataDisabled,
    )

  let assert Error(failure) = result
  assert error.kind(failure) == error.Policy(error.SecurityPolicy)
}

pub fn cancellation_subscription_is_one_shot_and_idempotent_test() -> Nil {
  let value = cancellable_context()
  let cancelled = process.new_subject()
  let subscription = context.subscribe_cancellation(value, cancelled)

  context.cancel(value)
  context.cancel(value)

  assert process.receive(cancelled, within: 1000) == Ok(Nil)
  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert await_broker_stopped(value, 100)
    == context.CancellationSnapshot(
      cancelled: True,
      broker_stopped: True,
      active_subscriptions: 0,
      notifications: 1,
      explicit_unsubscriptions: 0,
      abandoned_subscriptions: 0,
    )
  context.unsubscribe_cancellation(subscription)
}

pub fn cancellation_subscription_can_be_removed_without_a_mailbox_residue_test() -> Nil {
  let value = cancellable_context()
  let cancelled = process.new_subject()
  let subscription = context.subscribe_cancellation(value, cancelled)

  context.unsubscribe_cancellation(subscription)
  context.cancel(value)

  assert process.receive(cancelled, within: 20) == Error(Nil)
  assert await_broker_stopped(value, 100)
    == context.CancellationSnapshot(
      cancelled: True,
      broker_stopped: True,
      active_subscriptions: 0,
      notifications: 0,
      explicit_unsubscriptions: 1,
      abandoned_subscriptions: 0,
    )
}

pub fn subscription_after_cancellation_is_signalled_immediately_once_test() -> Nil {
  let value = cancellable_context()
  let cancelled = process.new_subject()
  context.cancel(value)

  let subscription = context.subscribe_cancellation(value, cancelled)

  assert process.receive(cancelled, within: 1000) == Ok(Nil)
  assert process.receive(cancelled, within: 0) == Error(Nil)
  context.unsubscribe_cancellation(subscription)
  let snapshot = await_broker_stopped(value, 100)
  assert snapshot.cancelled
  assert snapshot.broker_stopped
  assert snapshot.active_subscriptions == 0
  assert snapshot.notifications == 1
}

pub fn cancellation_broker_reclaims_an_abandoned_subscriber_test() -> Nil {
  let value = cancellable_context()
  let subscribed = process.new_subject()
  let subscriber =
    process.spawn_unlinked(fn() {
      let cancelled = process.new_subject()
      let _subscription = context.subscribe_cancellation(value, cancelled)
      process.send(subscribed, Nil)
      process.sleep_forever()
    })
  assert process.receive(subscribed, within: 1000) == Ok(Nil)
  assert context.cancellation_snapshot(value).active_subscriptions == 1

  process.kill(subscriber)

  assert await_broker_stopped(value, 100)
    == context.CancellationSnapshot(
      cancelled: False,
      broker_stopped: True,
      active_subscriptions: 0,
      notifications: 0,
      explicit_unsubscriptions: 0,
      abandoned_subscriptions: 1,
    )
}

pub fn cancellation_broker_stops_when_its_context_owner_exits_test() -> Nil {
  let created = process.new_subject()
  let owner =
    process.spawn_unlinked(fn() {
      process.send(created, cancellable_context())
      process.sleep_forever()
    })
  let assert Ok(value) = process.receive(created, within: 1000)

  process.kill(owner)

  let snapshot = await_broker_stopped(value, 100)
  assert !snapshot.cancelled
  assert snapshot.broker_stopped
  assert snapshot.active_subscriptions == 0
}

pub fn concurrent_cancel_and_subscribe_delivers_exactly_once_250_times_test() -> Nil {
  repeat_cancel_subscribe_race(250)
}

fn cancellable_context() -> context.Context {
  let assert Ok(value) =
    context.new(
      context.Http2,
      context.Endpoint("peer", 443),
      context.Endpoint("local", 8443),
      within_milliseconds: 1000,
      tls_identity: context.CleartextIdentity,
      early_data: context.EarlyDataDisabled,
    )
  value
}

fn repeat_cancel_subscribe_race(remaining: Int) -> Nil {
  use <- bool.guard(when: remaining <= 0, return: Nil)
  let value = cancellable_context()
  let cancelled = process.new_subject()
  let _canceller = process.spawn_unlinked(fn() { context.cancel(value) })
  let subscription = context.subscribe_cancellation(value, cancelled)

  assert process.receive(cancelled, within: 1000) == Ok(Nil)
  assert process.receive(cancelled, within: 0) == Error(Nil)
  let snapshot = await_broker_stopped(value, 100)
  assert snapshot.cancelled
  assert snapshot.broker_stopped
  assert snapshot.active_subscriptions == 0
  assert snapshot.notifications == 1
  context.unsubscribe_cancellation(subscription)
  repeat_cancel_subscribe_race(remaining - 1)
}

fn await_broker_stopped(
  value: context.Context,
  remaining_milliseconds: Int,
) -> context.CancellationSnapshot {
  let snapshot = context.cancellation_snapshot(value)
  case snapshot.broker_stopped || remaining_milliseconds <= 0 {
    True -> snapshot
    False -> {
      process.sleep(1)
      await_broker_stopped(value, remaining_milliseconds - 1)
    }
  }
}
