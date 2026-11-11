import gleam/bit_array
import gleam/bool
import gleam/http/request
import gleam/list
import gleam/result
import gleeunit/should
import http3/client
import http3/config
import http3/internal/clock
import http3/server
import http3_test_support

type Observation {
  Observation(
    same_actor_while_live: Bool,
    distinct_actor_at_same_endpoint: Bool,
    first: server.Request,
    second: server.Request,
    distinct: server.Request,
  )
}

pub type SameConnectionContract {
  StableActorIdentity
  SameActorMismatch
  DistinctActorMismatch
  RetainedSameActorMismatch
  RetainedDistinctActorMismatch
}

// One finite fixture distinguishes actor identity from endpoint equality and actor liveness.
// Together the three observations reject implementations that return a constant, compare peer endpoints, or query a live process.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn same_connection_uses_stable_actor_identity_test() -> Nil {
  assert observe_same_connection_identity() == StableActorIdentity
}

pub fn observe_same_connection_identity() -> SameConnectionContract {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key) |> should.be_ok
  let configuration = server.with_address_family(configuration, config.Ipv4)
  let configuration = server.with_timeout(configuration, 5000) |> should.be_ok
  let listener = server.start(configuration) |> should.be_ok
  let origin_port = server.port(listener) |> should.be_ok

  let observation =
    http3_test_support.with_shared_endpoint_proxy(
      origin_port,
      ca_certificate,
      fn(endpoint_port, ca_certificate) {
        observe_identities(
          listener: listener,
          origin_port: origin_port,
          endpoint_port: endpoint_port,
          ca_certificate: ca_certificate,
        )
      },
    )

  let Observation(
    same_actor_while_live,
    distinct_actor_at_same_endpoint,
    first,
    second,
    distinct,
  ) = observation
  assert server.stop(listener) == Ok(server.Stopped)
  case
    same_actor_while_live,
    distinct_actor_at_same_endpoint,
    server.same_connection(first: first, second: second),
    server.same_connection(first: first, second: distinct)
  {
    True, True, True, False -> StableActorIdentity
    False, _, _, _ -> SameActorMismatch
    True, False, _, _ -> DistinctActorMismatch
    True, True, False, _ -> RetainedSameActorMismatch
    True, True, True, True -> RetainedDistinctActorMismatch
  }
}

fn observe_identities(
  listener listener: server.Listener,
  origin_port origin_port: Int,
  endpoint_port endpoint_port: Int,
  ca_certificate ca_certificate: BitArray,
) -> Observation {
  let configured = client_configuration(ca_certificate)
  let first_connection =
    client.connect_to(configured, "localhost", origin_port, endpoint_port)
    |> should.be_ok
  let first_stream =
    client.open_stream(
      first_connection,
      streaming_request(origin_port, "/identity-first"),
    )
    |> should.be_ok
  client.finish(first_stream) |> should.be_ok
  let second_stream =
    client.open_stream(
      first_connection,
      streaming_request(origin_port, "/identity-second"),
    )
    |> should.be_ok
  client.finish(second_stream) |> should.be_ok

  let first = server.accept(listener) |> should.be_ok
  let second = server.accept(listener) |> should.be_ok
  let same_actor_while_live =
    server.same_connection(first: first, second: second)
  server.respond(first, 200, [], <<"first":utf8>>) |> should.be_ok
  server.respond(second, 200, [], <<"second":utf8>>) |> should.be_ok
  assert receive_response(first_stream, []) == <<"first":utf8>>
  assert receive_response(second_stream, []) == <<"second":utf8>>
  server.await_response_completion(first) |> should.be_ok
  server.await_response_completion(second) |> should.be_ok
  let first_endpoint = server.peer_endpoint(first) |> should.be_ok
  assert client.close(first_connection) == Ok(client.Closed)
  await_connection_retirement(first, clock.monotonic_milliseconds() + 2000)

  // The first physical connection is fully retired before the proxy switches clients.
  // Its validated endpoint was captured only as a Boolean test fact;
  // the opaque retained requests remain safe identity values.
  let distinct_connection =
    client.connect_to(configured, "localhost", origin_port, endpoint_port)
    |> should.be_ok
  let distinct_stream =
    client.open_stream(
      distinct_connection,
      streaming_request(origin_port, "/identity-distinct"),
    )
    |> should.be_ok
  client.finish(distinct_stream) |> should.be_ok
  let distinct = server.accept(listener) |> should.be_ok
  let distinct_endpoint = server.peer_endpoint(distinct) |> should.be_ok
  let distinct_actor_at_same_endpoint =
    first_endpoint == distinct_endpoint
    && !server.same_connection(first: first, second: distinct)
  server.respond(distinct, 200, [], <<"distinct":utf8>>) |> should.be_ok
  assert receive_response(distinct_stream, []) == <<"distinct":utf8>>
  server.await_response_completion(distinct) |> should.be_ok

  assert client.close(distinct_connection) == Ok(client.Closed)
  await_connection_retirement(distinct, clock.monotonic_milliseconds() + 2000)
  Observation(
    same_actor_while_live,
    distinct_actor_at_same_endpoint,
    first,
    second,
    distinct,
  )
}

fn await_connection_retirement(
  request: server.Request,
  deadline_milliseconds: Int,
) -> Nil {
  use <- bool.guard(
    when: result.is_error(server.peer_endpoint(request)),
    return: Nil,
  )
  assert clock.monotonic_milliseconds() < deadline_milliseconds
  http3_test_support.pause_milliseconds(1)
  await_connection_retirement(request, deadline_milliseconds)
}

fn client_configuration(ca_certificate: BitArray) -> client.Client {
  client.new()
  |> client.with_address_family(config.Ipv4)
  |> client.with_timeout(5000)
  |> should.be_ok
  |> client.with_ca_certificate(ca_certificate)
  |> should.be_ok
}

fn streaming_request(port: Int, path: String) -> request.Request(Nil) {
  request.new()
  |> request.set_host("localhost")
  |> request.set_port(port)
  |> request.set_path(path)
  |> request.set_body(Nil)
}

fn receive_response(stream: client.Stream, chunks: List(BitArray)) -> BitArray {
  case client.next_event(stream) |> should.be_ok {
    client.InformationalResponse(_, _) -> receive_response(stream, chunks)
    client.Response(status, _) -> {
      assert status == 200
      receive_response(stream, chunks)
    }
    client.Data(chunk) -> receive_response(stream, [chunk, ..chunks])
    client.Trailers(_) -> receive_response(stream, chunks)
    client.End -> bit_array.concat(list.reverse(chunks))
  }
}
