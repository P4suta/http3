import gleam/erlang/process
import gleam/list
import gleam/string
import gleeunit/should
import http3/internal/process_label

const input_derived_sentinel = "localhost-127.0.0.1-443-cid-stream-sni-cert"

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn every_http3_actor_role_has_one_fixed_process_label_test() -> Nil {
  let roles = process_label.all()
  let labels = list.map(roles, process_label.name)

  labels
  |> should.equal([
    "http3.client",
    "http3.listener",
    "http3.connect_candidate",
  ])
  labels |> list.unique |> list.length |> should.equal(list.length(labels))
  labels
  |> list.all(fn(label) {
    !string.contains(label, input_derived_sentinel)
    && !string.contains(label, "localhost")
    && !string.contains(label, "127.0.0.1")
    && !string.contains(label, "443")
    && !string.contains(label, "cid")
    && !string.contains(label, "stream")
    && !string.contains(label, "sni")
    && !string.contains(label, "cert")
  })
  |> should.be_true

  list.each(roles, assert_role_is_acquired_in_calling_process)
}

fn assert_role_is_acquired_in_calling_process(role: process_label.Role) -> Nil {
  let reply = process.new_subject()
  let _worker =
    process.spawn_unlinked(fn() {
      process_label.set(role)
      process.send(reply, process_label.current())
    })
  process.receive(reply, within: 1000)
  |> should.equal(Ok(process_label.name(role)))
}
