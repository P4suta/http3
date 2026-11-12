import gleam/erlang/process
import gleeunit
import gleeunit/should
import http/client
import http/error

pub fn main() -> Nil {
  gleeunit.main()
}

type FollowerEvent {
  FollowerBegan(client.Http3DialRole)
  FollowerBeginFailed(error.Error)
  FollowerFinished(Result(Nil, error.Error))
}

fn start_broker_client() -> client.Client {
  let config =
    client.with_pool_limits(
      client.defaults(),
      client.PoolLimits(
        maximum_connections: 1,
        maximum_connections_per_origin: 1,
        idle_milliseconds: 30_000,
      ),
    )
    |> should.be_ok
  client.start(config) |> should.be_ok
}

fn start_follower(
  running running: client.Client,
  timeout_milliseconds timeout_milliseconds: Int,
  events events: process.Subject(FollowerEvent),
) -> process.Pid {
  process.spawn_unlinked(fn() {
    case client.http3_dial_probe_begin(running, timeout_milliseconds) {
      Error(failure) -> process.send(events, FollowerBeginFailed(failure))
      Ok(probe) -> {
        process.send(events, FollowerBegan(client.http3_dial_probe_role(probe)))
        process.send(
          events,
          FollowerFinished(client.http3_dial_probe_await(probe)),
        )
      }
    }
  })
}

fn assert_open_broker_empty(running: client.Client) -> Nil {
  assert client.http3_dial_census(running) == client.Http3DialCensus(0, 0)
  assert client.lifecycle_pool_counts(running) == #(0, 0)
}

pub fn same_key_slot_one_waiter_joins_single_dial_test() -> Nil {
  let running = start_broker_client()
  let leader = client.http3_dial_probe_begin(running, 2000) |> should.be_ok
  assert client.http3_dial_probe_role(leader) == client.Http3DialLeaderRole

  let first_events = process.new_subject()
  let second_events = process.new_subject()
  let _first_follower =
    start_follower(
      running: running,
      timeout_milliseconds: 2000,
      events: first_events,
    )
  let _second_follower =
    start_follower(
      running: running,
      timeout_milliseconds: 2000,
      events: second_events,
    )
  assert process.receive(first_events, within: 1000)
    == Ok(FollowerBegan(client.Http3DialWaitingRole))
  assert process.receive(second_events, within: 1000)
    == Ok(FollowerBegan(client.Http3DialWaitingRole))
  assert client.http3_dial_census(running) == client.Http3DialCensus(1, 2)

  assert client.http3_dial_probe_settle(leader, True, 1000) == Ok(Nil)
  assert process.receive(first_events, within: 1000)
    == Ok(FollowerFinished(Ok(Nil)))
  assert process.receive(second_events, within: 1000)
    == Ok(FollowerFinished(Ok(Nil)))
  assert_open_broker_empty(running)
  assert client.close(running) == Ok(Nil)
}

pub fn dial_failure_wakes_every_waiter_and_releases_reservation_test() -> Nil {
  let running = start_broker_client()
  let leader = client.http3_dial_probe_begin(running, 2000) |> should.be_ok
  let events = process.new_subject()
  let _follower =
    start_follower(running: running, timeout_milliseconds: 2000, events: events)
  assert process.receive(events, within: 1000)
    == Ok(FollowerBegan(client.Http3DialWaitingRole))

  assert client.http3_dial_probe_settle(leader, False, 1000) == Ok(Nil)
  let failure =
    case process.receive(events, within: 1000) |> should.be_ok {
      FollowerFinished(Error(failure)) -> Ok(failure)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert error.kind(failure) == error.Service
  assert_open_broker_empty(running)
  assert client.close(running) == Ok(Nil)
}

pub fn dial_leader_exit_wakes_waiter_without_leaking_capacity_test() -> Nil {
  let running = start_broker_client()
  let leader_ready = process.new_subject()
  let leader =
    process.spawn_unlinked(fn() {
      let hold_leader = process.new_subject()
      case client.http3_dial_probe_begin(running, 2000) {
        Error(failure) ->
          process.send(leader_ready, FollowerBeginFailed(failure))
        Ok(probe) -> {
          process.send(
            leader_ready,
            FollowerBegan(client.http3_dial_probe_role(probe)),
          )
          process.receive_forever(hold_leader)
        }
      }
    })
  assert process.receive(leader_ready, within: 1000)
    == Ok(FollowerBegan(client.Http3DialLeaderRole))

  let events = process.new_subject()
  let _follower =
    start_follower(running: running, timeout_milliseconds: 2000, events: events)
  assert process.receive(events, within: 1000)
    == Ok(FollowerBegan(client.Http3DialWaitingRole))
  process.kill(leader)

  let failure =
    case process.receive(events, within: 1000) |> should.be_ok {
      FollowerFinished(Error(failure)) -> Ok(failure)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert error.kind(failure) == error.Service
  assert_open_broker_empty(running)
  assert client.close(running) == Ok(Nil)
}

pub fn waiter_absolute_deadline_removes_only_that_waiter_test() -> Nil {
  let running = start_broker_client()
  let leader = client.http3_dial_probe_begin(running, 30_000) |> should.be_ok
  let events = process.new_subject()
  let _follower =
    start_follower(
      running: running,
      timeout_milliseconds: 30_000,
      events: events,
    )
  assert process.receive(events, within: 1000)
    == Ok(FollowerBegan(client.Http3DialWaitingRole))

  assert client.http3_dial_probe_expire_waiters(leader, 60_000, 1000) == Ok(Nil)
  assert client.http3_dial_census(running) == client.Http3DialCensus(1, 0)
  let failure =
    case process.receive(events, within: 1000) |> should.be_ok {
      FollowerFinished(Error(failure)) -> Ok(failure)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert error.kind(failure) == error.Cancelled
  assert client.http3_dial_probe_settle(leader, False, 1000) == Ok(Nil)
  assert_open_broker_empty(running)
  assert client.close(running) == Ok(Nil)
}

pub fn drain_wakes_waiter_and_reclaims_dial_test() -> Nil {
  let running = start_broker_client()
  let _leader = client.http3_dial_probe_begin(running, 2000) |> should.be_ok
  let events = process.new_subject()
  let _follower =
    start_follower(running: running, timeout_milliseconds: 2000, events: events)
  assert process.receive(events, within: 1000)
    == Ok(FollowerBegan(client.Http3DialWaitingRole))

  assert client.drain(running) == Ok(Nil)
  let failure =
    case process.receive(events, within: 1000) |> should.be_ok {
      FollowerFinished(Error(failure)) -> Ok(failure)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert error.kind(failure) == error.Cancelled
  assert_open_broker_empty(running)
  assert client.close(running) == Ok(Nil)
}

pub fn close_wakes_waiter_and_terminal_census_is_empty_test() -> Nil {
  let running = start_broker_client()
  let _leader = client.http3_dial_probe_begin(running, 2000) |> should.be_ok
  let events = process.new_subject()
  let _follower =
    start_follower(running: running, timeout_milliseconds: 2000, events: events)
  assert process.receive(events, within: 1000)
    == Ok(FollowerBegan(client.Http3DialWaitingRole))

  assert client.close(running) == Ok(Nil)
  let failure =
    case process.receive(events, within: 1000) |> should.be_ok {
      FollowerFinished(Error(failure)) -> Ok(failure)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert error.kind(failure) == error.Cancelled
  assert client.http3_dial_census(running) == client.Http3DialCensus(0, 0)
}
