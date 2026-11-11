import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleeunit/should
import http/body
import http/client
import http/context
import http/diagnostics
import http/error
import http/server as http_server
import http3/server
import http_test_support

type StreamOpenProbe {
  StreamOpenProbe(
    commands: process.Subject(StreamOpenProbeCommand),
    pid: process.Pid,
  )
}

type StreamOpenProbeCommand {
  NextStreamOpen(reply: process.Subject(Result(Bool, Nil)))
  StopStreamOpenProbe(reply: process.Subject(Nil))
}

pub fn main() -> Nil {
  pooled_http3_goaway_refusal_reroutes_one_nonreplayable_body_test()
  pooled_http3_goaway_reroute_to_tcp_omits_alt_used_test()
}

pub fn pooled_http3_goaway_refusal_reroutes_one_nonreplayable_body_test() -> Nil {
  let observed = process.new_subject()
  let reporter =
    diagnostics.start(512, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
    |> should.be_ok
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let primary_configuration =
    server.new(certificate, private_key) |> should.be_ok
  let alternate_configuration =
    server.new(certificate, private_key) |> should.be_ok
  let primary = server.start(primary_configuration) |> should.be_ok
  let alternate = server.start(alternate_configuration) |> should.be_ok
  let primary_port = server.port(primary) |> should.be_ok
  let alternate_port = server.port(alternate) |> should.be_ok
  let opened = process.new_subject()
  let probe_decisions = process.new_subject()
  let primary_stages = process.new_subject()
  let replacement_h3_alt_used = process.new_subject()
  let pulls = process.new_subject()
  let cancelled = process.new_subject()
  let stream_open_probe = start_stream_open_probe()
  let primary_task =
    http_test_support.start_task(fn() {
      result.map(server.accept(primary), fn(incoming) {
        {
          process.send(primary_stages, "accepted")
          let responded =
            server.respond(
              incoming,
              200,
              [
                #(
                  "alt-svc",
                  "h3=\":" <> int.to_string(alternate_port) <> "\"; ma=60",
                ),
              ],
              <<"first":utf8>>,
            )
            == Ok(Nil)
          process.send(primary_stages, case responded {
            True -> "responded"
            False -> "respond_failed"
          })
          responded
        }
      })
      |> result.unwrap(False)
    })
  let alternate_task =
    http_test_support.start_task(fn() {
      result.map(server.accept(alternate), fn(incoming) {
        {
          process.send(
            replacement_h3_alt_used,
            list.key_find(server.headers(incoming), "alt-used"),
          )
          server.next_event(incoming) == Ok(server.End)
          && server.respond(incoming, 200, [], <<"rerouted":utf8>>) == Ok(Nil)
        }
      })
      |> result.unwrap(False)
    })
  let configuration =
    client.with_pool_limits(client.defaults(), client.PoolLimits(1, 1, 3000))
    |> should.be_ok
  let configuration =
    client.with_timeouts(
      configuration,
      client.Timeouts(1000, 2000, 2000, 3000, 3000, 5000),
    )
    |> should.be_ok
  let running =
    configuration
    |> client.without_retries
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, _, _) {
      Ok([client.HttpsRecord(["h3"], primary_port, True, 60_000)])
    })
    |> client.with_http3_stream_open_refusal_probe(fn() {
      process.send(opened, Nil)
      let decision = next_stream_open_decision(stream_open_probe)
      process.send(probe_decisions, decision)
      decision
    })
    |> client.with_diagnostics(reporter)
    |> client.start
    |> should.be_ok
  let first =
    client.exchange(
      running,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(primary_port)
        |> request.set_body(body.empty()),
    )
  let first_outcome = case first {
    Error(failure) -> Error(error.kind(failure))
    Ok(exchange) ->
      body.read_all(client.response(exchange).body, 5)
      |> result.map(fn(contents) {
        #(client.selected_protocol(exchange), contents)
      })
      |> result.map_error(error.kind)
  }
  let first_open = process.receive(opened, within: 1000)
  let first_probe_decision = process.receive(probe_decisions, within: 1000)
  let primary_accepted = process.receive(primary_stages, within: 1000)
  let primary_responded = process.receive(primary_stages, within: 1000)
  let pooled_before_refusal = client.lifecycle_pool_counts(running)
  let nonreplayable =
    body.from_pull(
      body.pull(fn(_) {
        process.send(pulls, Nil)
        Ok(body.PullEnd([]))
      }),
      None,
      None,
      fn() { process.send(cancelled, Nil) },
    )
    |> should.be_ok
  let second =
    client.exchange(
      running,
      request.new()
        |> request.set_method(http.Put)
        |> request.set_host("localhost")
        |> request.set_port(primary_port)
        |> request.set_body(nonreplayable),
    )
  let second_outcome = case second {
    Error(failure) -> Error(error.kind(failure))
    Ok(exchange) ->
      body.read_all(client.response(exchange).body, 8)
      |> result.map(fn(contents) {
        #(client.selected_protocol(exchange), contents)
      })
      |> result.map_error(error.kind)
  }
  let refusal_open = process.receive(opened, within: 1000)
  let refusal_probe_decision = process.receive(probe_decisions, within: 1000)
  let replacement_open = process.receive(opened, within: 1000)
  let replacement_probe_decision =
    process.receive(probe_decisions, within: 1000)
  let replacement_alt_used =
    process.receive(replacement_h3_alt_used, within: 1000)
  let no_extra_open = process.receive(opened, within: 0)
  let first_pull = process.receive(pulls, within: 1000)
  let no_second_pull = process.receive(pulls, within: 0)
  let source_cancelled = process.receive(cancelled, within: 1000)
  let no_second_cancel = process.receive(cancelled, within: 0)
  let pooled_after_reroute = client.lifecycle_pool_counts(running)
  let closed = client.close(running)
  let primary_stopped = server.stop(primary)
  let alternate_stopped = server.stop(alternate)
  let primary_done = http_test_support.await_task(primary_task)
  let alternate_done = http_test_support.await_task(alternate_task)
  let probe_stopped = stop_stream_open_probe(stream_open_probe)
  let reporter_stopped = diagnostics.stop(reporter)
  let stages = collect_client_stages(observed, [])

  assert_first_outcome(first_outcome)
  assert second_outcome == Ok(#(client.Http3, #(<<"rerouted":utf8>>, [])))
  assert first_open == Ok(Nil)
  assert first_probe_decision == Ok(Ok(False))
  assert primary_accepted == Ok("accepted")
  assert primary_responded == Ok("responded")
  assert refusal_open == Ok(Nil)
  assert refusal_probe_decision == Ok(Ok(True))
  assert replacement_open == Ok(Nil)
  assert replacement_probe_decision == Ok(Ok(False))
  assert replacement_alt_used
    == Ok(Ok("localhost:" <> int.to_string(alternate_port)))
  assert no_extra_open == Error(Nil)
  assert pooled_before_refusal == #(1, 1)
  assert pooled_after_reroute == #(1, 1)
  assert first_pull == Ok(Nil)
  assert no_second_pull == Error(Nil)
  assert source_cancelled == Ok(Nil)
  assert no_second_cancel == Error(Nil)
  assert closed == Ok(Nil)
  assert result.is_ok(primary_stopped)
  assert result.is_ok(alternate_stopped)
  assert primary_done
  assert alternate_done
  assert probe_stopped
  assert reporter_stopped == Ok(Nil)
  assert_goaway_reroute_trace(stages)
}

pub fn pooled_http3_goaway_reroute_to_tcp_omits_alt_used_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let primary_configuration =
    server.new(certificate, private_key) |> should.be_ok
  let primary = server.start(primary_configuration) |> should.be_ok
  let primary_port = server.port(primary) |> should.be_ok
  let #(dead_alternate, alternate_port) =
    http_test_support.start_exclusive_udp_port_guard()
  let primary_task =
    http_test_support.start_task(fn() {
      result.map(server.accept(primary), fn(incoming) {
        server.respond(
          incoming,
          200,
          [
            #(
              "alt-svc",
              "h3=\":" <> int.to_string(alternate_port) <> "\"; ma=60",
            ),
          ],
          <<"first":utf8>>,
        )
        == Ok(Nil)
      })
      |> result.unwrap(False)
    })
  let opened = process.new_subject()
  let probe_decisions = process.new_subject()
  let stream_open_probe = start_stream_open_probe()
  let configuration =
    client.with_pool_limits(client.defaults(), client.PoolLimits(1, 1, 3000))
    |> should.be_ok
  let configuration =
    client.with_timeouts(
      configuration,
      client.Timeouts(1000, 2000, 2000, 3000, 3000, 10_000),
    )
    |> should.be_ok
  let running =
    configuration
    |> client.without_retries
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, _, _) {
      Ok([client.HttpsRecord(["h3"], primary_port, True, 60_000)])
    })
    |> client.with_http3_stream_open_refusal_probe(fn() {
      process.send(opened, Nil)
      let decision = next_stream_open_decision(stream_open_probe)
      process.send(probe_decisions, decision)
      decision
    })
    |> client.start
    |> should.be_ok
  let first =
    client.exchange(
      running,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(primary_port)
        |> request.set_body(body.empty()),
    )
  let first_outcome = case first {
    Error(failure) -> Error(error.kind(failure))
    Ok(exchange) ->
      body.read_all(client.response(exchange).body, 5)
      |> result.map(fn(contents) {
        #(client.selected_protocol(exchange), contents)
      })
      |> result.map_error(error.kind)
  }
  let first_open = process.receive(opened, within: 1000)
  let first_probe_decision = process.receive(probe_decisions, within: 1000)
  let pooled_before_refusal = client.lifecycle_pool_counts(running)

  let tcp_alt_used = process.new_subject()
  let tcp_body_received = process.new_subject()
  let handler = fn(outgoing: request.Request(body.Body), _) {
    process.send(tcp_alt_used, request.get_header(outgoing, "alt-used"))
    let received = body.read_all(outgoing.body, 1) == Ok(#(<<>>, []))
    process.send(tcp_body_received, received)
    Ok(response.Response(
      status: 200,
      headers: [],
      body: body.from_text("tcp-fallback"),
    ))
  }
  let executor =
    http_server.start(http_server.defaults(), handler) |> should.be_ok
  let tcp_listener =
    http_server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      primary_port,
      http_server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
    |> should.be_ok
  let pulls = process.new_subject()
  let cancelled = process.new_subject()
  let nonreplayable =
    body.from_pull(
      body.pull(fn(_) {
        process.send(pulls, Nil)
        Ok(body.PullEnd([]))
      }),
      None,
      None,
      fn() { process.send(cancelled, Nil) },
    )
    |> should.be_ok
  let second =
    client.exchange(
      running,
      request.new()
        |> request.set_method(http.Put)
        |> request.set_host("localhost")
        |> request.set_port(primary_port)
        |> request.set_body(nonreplayable),
    )
  let second_outcome = case second {
    Error(failure) -> Error(error.kind(failure))
    Ok(exchange) ->
      body.read_all(client.response(exchange).body, 12)
      |> result.map(fn(contents) {
        #(client.selected_protocol(exchange), contents)
      })
      |> result.map_error(error.kind)
  }
  let refusal_open = process.receive(opened, within: 1000)
  let refusal_probe_decision = process.receive(probe_decisions, within: 1000)
  let no_replacement_h3_open = process.receive(opened, within: 0)
  let no_replacement_h3_probe = process.receive(probe_decisions, within: 0)
  let observed_tcp_alt_used = process.receive(tcp_alt_used, within: 1000)
  let observed_tcp_body = process.receive(tcp_body_received, within: 1000)
  let first_pull = process.receive(pulls, within: 1000)
  let no_second_pull = process.receive(pulls, within: 0)
  let source_cancelled = process.receive(cancelled, within: 1000)
  let no_second_cancel = process.receive(cancelled, within: 0)
  let closed = client.close(running)
  let tcp_drained = http_server.drain_listener(tcp_listener)
  let tcp_stopped = http_server.stop_listener(tcp_listener)
  let executor_stopped = http_server.stop(executor)
  let primary_stopped = server.stop(primary)
  http_test_support.stop_exclusive_udp_port_guard(dead_alternate)
  let primary_done = http_test_support.await_task(primary_task)
  let probe_stopped = stop_stream_open_probe(stream_open_probe)

  assert_first_outcome(first_outcome)
  assert second_outcome == Ok(#(client.Http2, #(<<"tcp-fallback":utf8>>, [])))
  assert first_open == Ok(Nil)
  assert first_probe_decision == Ok(Ok(False))
  assert pooled_before_refusal == #(1, 1)
  assert refusal_open == Ok(Nil)
  assert refusal_probe_decision == Ok(Ok(True))
  assert no_replacement_h3_open == Error(Nil)
  assert no_replacement_h3_probe == Error(Nil)
  assert observed_tcp_alt_used == Ok(Error(Nil))
  assert observed_tcp_body == Ok(True)
  assert first_pull == Ok(Nil)
  assert no_second_pull == Error(Nil)
  assert source_cancelled == Ok(Nil)
  assert no_second_cancel == Error(Nil)
  assert closed == Ok(Nil)
  assert tcp_drained == Ok(Nil)
  assert tcp_stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
  assert result.is_ok(primary_stopped)
  assert primary_done
  assert probe_stopped
}

fn start_stream_open_probe() -> StreamOpenProbe {
  let ready = process.new_subject()
  let pid =
    process.spawn_unlinked(fn() {
      let commands = process.new_subject()
      process.send(ready, commands)
      stream_open_probe_loop(commands, 0)
    })
  let commands = process.receive(ready, within: 1000) |> should.be_ok
  StreamOpenProbe(commands, pid)
}

fn stream_open_probe_loop(
  commands: process.Subject(StreamOpenProbeCommand),
  opens: Int,
) -> Nil {
  case process.receive(commands, within: 10_000) {
    Error(Nil) -> Nil
    Ok(NextStreamOpen(reply)) -> {
      process.send(reply, Ok(opens == 1))
      stream_open_probe_loop(commands, opens + 1)
    }
    Ok(StopStreamOpenProbe(reply)) -> process.send(reply, Nil)
  }
}

fn next_stream_open_decision(probe: StreamOpenProbe) -> Result(Bool, Nil) {
  let reply = process.new_subject()
  process.send(probe.commands, NextStreamOpen(reply))
  case process.receive(reply, within: 1000) {
    Ok(decision) -> decision
    Error(Nil) -> Error(Nil)
  }
}

fn stop_stream_open_probe(probe: StreamOpenProbe) -> Bool {
  let monitor = process.monitor(probe.pid)
  let reply = process.new_subject()
  process.send(probe.commands, StopStreamOpenProbe(reply))
  let acknowledged = process.receive(reply, within: 1000) == Ok(Nil)
  let stopped =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: 1000)
    == Ok(Nil)
  acknowledged && stopped
}

fn assert_first_outcome(
  outcome: Result(
    #(client.Protocol, #(BitArray, body.Headers)),
    error.ErrorKind,
  ),
) -> Nil {
  case outcome {
    Ok(#(client.Http3, #(<<"first":utf8>>, []))) -> Nil
    Ok(#(client.Http1, _)) ->
      should.be_ok(Error("first outcome selected HTTP/1"))
    Ok(#(client.Http2, _)) ->
      should.be_ok(Error("first outcome selected HTTP/2"))
    Ok(#(client.Http3, _)) ->
      should.be_ok(Error("first HTTP/3 response mismatched"))
    Error(error.Dns) -> should.be_ok(Error("first outcome failed: dns"))
    Error(error.ConnectFailed) ->
      should.be_ok(Error("first outcome failed: connect"))
    Error(error.Tls) -> should.be_ok(Error("first outcome failed: tls"))
    Error(error.Timeout(error.DnsLookup)) ->
      should.be_ok(Error("first outcome failed: dns timeout"))
    Error(error.Timeout(error.Connect)) ->
      should.be_ok(Error("first outcome failed: connect timeout"))
    Error(error.Timeout(error.TlsHandshake)) ->
      should.be_ok(Error("first outcome failed: tls timeout"))
    Error(error.Timeout(error.Operation)) ->
      should.be_ok(Error("first outcome failed: operation timeout"))
    Error(error.Timeout(error.Idle)) ->
      should.be_ok(Error("first outcome failed: idle timeout"))
    Error(error.Timeout(error.Total)) ->
      should.be_ok(Error("first outcome failed: total timeout"))
    Error(error.Protocol(error.Http1)) ->
      should.be_ok(Error("first outcome failed: HTTP/1"))
    Error(error.Protocol(error.Http2)) ->
      should.be_ok(Error("first outcome failed: HTTP/2"))
    Error(error.Protocol(error.Http3)) ->
      should.be_ok(Error("first outcome failed: HTTP/3"))
    Error(error.Protocol(error.Quic)) ->
      should.be_ok(Error("first outcome failed: QUIC"))
    Error(error.Policy(_)) ->
      should.be_ok(Error("first outcome failed: policy"))
    Error(error.Body(_)) -> should.be_ok(Error("first outcome failed: body"))
    Error(error.Resource(_)) ->
      should.be_ok(Error("first outcome failed: resource"))
    Error(error.Cancelled) ->
      should.be_ok(Error("first outcome failed: cancelled"))
    Error(error.Service) -> should.be_ok(Error("first outcome failed: service"))
  }
}

fn collect_client_stages(
  observed: process.Subject(diagnostics.Observation),
  reversed: List(#(Int, Int, diagnostics.ClientStage)),
) -> List(#(Int, Int, diagnostics.ClientStage)) {
  case process.receive(observed, within: 0) {
    Error(Nil) ->
      reversed
      |> list.reverse
      |> list.sort(fn(first, second) { int.compare(first.0, second.0) })
    Ok(record) -> {
      let reversed = case record.event {
        diagnostics.ClientObserved(request_id, _, stage) -> [
          #(record.sequence, diagnostics.request_id_value(request_id), stage),
          ..reversed
        ]
        _ -> reversed
      }
      collect_client_stages(observed, reversed)
    }
  }
}

fn assert_goaway_reroute_trace(
  stages: List(#(Int, Int, diagnostics.ClientStage)),
) -> Nil {
  let starts =
    list.filter_map(stages, fn(entry) {
      case entry.2 {
        diagnostics.AttemptStarted(attempt) -> Ok(#(entry.0, entry.1, attempt))
        _ -> Error(Nil)
      }
    })
  let #(
    first_request,
    old_started,
    second_request,
    old_attempt,
    new_started,
    rerouted_request,
    new_attempt,
  ) =
    case starts {
      [
        #(_, first_request, _),
        #(old_started, second_request, old_attempt),
        #(new_started, rerouted_request, new_attempt),
      ] ->
        Ok(#(
          first_request,
          old_started,
          second_request,
          old_attempt,
          new_started,
          rerouted_request,
          new_attempt,
        ))
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert first_request != second_request
  assert second_request == rerouted_request
  assert old_attempt != new_attempt

  let old_finished =
    matching_sequences(stages, fn(request_id, stage) {
      request_id == second_request
      && case stage {
        diagnostics.AttemptFinished(attempt, None, Error(failure)) ->
          attempt == old_attempt
          && error.kind(failure) == error.Protocol(error.Http3)
        _ -> False
      }
    })
  let old_released =
    matching_sequences(stages, fn(request_id, stage) {
      request_id == second_request
      && case stage {
        diagnostics.AttemptReleased(attempt, None, Ok(Nil)) ->
          attempt == old_attempt
        _ -> False
      }
    })
  let old_protocol =
    matching_sequences(stages, fn(request_id, stage) {
      request_id == second_request
      && case stage {
        diagnostics.PhaseStarted(
          attempt,
          diagnostics.ProtocolSelection(context.Http3),
        ) -> attempt == old_attempt
        _ -> False
      }
    })
  let old_finished =
    case old_finished {
      [old_finished] -> Ok(old_finished)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let old_released =
    case old_released {
      [old_released] -> Ok(old_released)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert old_protocol == []
  assert old_started < old_finished
  assert old_finished < old_released
  assert old_released < new_started

  let new_protocol =
    matching_sequences(stages, fn(request_id, stage) {
      request_id == second_request
      && case stage {
        diagnostics.PhaseFinished(
          attempt,
          diagnostics.ProtocolSelection(context.Http3),
          Ok(Nil),
        ) -> attempt == new_attempt
        _ -> False
      }
    })
  let headers =
    matching_sequences(stages, fn(request_id, stage) {
      request_id == second_request
      && case stage {
        diagnostics.ResponseHeaders(attempt, context.Http3, 200) ->
          attempt == new_attempt
        _ -> False
      }
    })
  let new_finished =
    matching_sequences(stages, fn(request_id, stage) {
      request_id == second_request
      && case stage {
        diagnostics.AttemptFinished(attempt, Some(context.Http3), Ok(Nil)) ->
          attempt == new_attempt
        _ -> False
      }
    })
  let new_released =
    matching_sequences(stages, fn(request_id, stage) {
      request_id == second_request
      && case stage {
        diagnostics.AttemptReleased(attempt, Some(context.Http3), Ok(Nil)) ->
          attempt == new_attempt
        _ -> False
      }
    })
  let read_finished =
    matching_sequences(stages, fn(request_id, stage) {
      request_id == second_request
      && case stage {
        diagnostics.ResponseReadFinished(attempt, context.Http3) ->
          attempt == new_attempt
        _ -> False
      }
    })
  let exchange_finished =
    matching_sequences(stages, fn(request_id, stage) {
      request_id == second_request
      && stage == diagnostics.ExchangeFinished(Ok(Nil))
    })
  let new_protocol =
    case new_protocol {
      [new_protocol] -> Ok(new_protocol)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let headers =
    case headers {
      [headers] -> Ok(headers)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let new_finished =
    case new_finished {
      [new_finished] -> Ok(new_finished)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let new_released =
    case new_released {
      [new_released] -> Ok(new_released)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let read_finished =
    case read_finished {
      [read_finished] -> Ok(read_finished)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let exchange_finished =
    case exchange_finished {
      [exchange_finished] -> Ok(exchange_finished)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert new_started < new_protocol
  assert new_protocol < headers
  assert headers < new_finished
  assert new_finished < new_released
  assert headers < read_finished
  assert new_released < exchange_finished
  assert read_finished < exchange_finished
}

fn matching_sequences(
  stages: List(#(Int, Int, diagnostics.ClientStage)),
  matches: fn(Int, diagnostics.ClientStage) -> Bool,
) -> List(Int) {
  list.filter_map(stages, fn(entry) {
    case matches(entry.1, entry.2) {
      True -> Ok(entry.0)
      False -> Error(Nil)
    }
  })
}
