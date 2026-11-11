import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/option.{None, Some}
import http/body
import http/error
import http/internal/http1/exchange
import http/internal/transport
import http_test_support

pub fn expired_authenticated_handoff_retains_total_timeout_test() -> Nil {
  rejected_handoff(http.Https, error.Timeout(error.Total))
}

pub fn invalid_scheme_handoff_retains_security_classification_test() -> Nil {
  rejected_handoff(http.Http, error.Policy(error.SecurityPolicy))
}

fn rejected_handoff(scheme: http.Scheme, expected: error.ErrorKind) -> Nil {
  let #(certificate, key, ca) = http_test_support.server_credentials()
  let events = process.new_subject()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 10_000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let peer =
    http_test_support.start_task(fn() {
      let assert Ok(socket) = transport.accept(listener, 10_000)
      let assert Ok(ready) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          key,
          [<<"http/1.1">>],
          10_000,
        )
      let transport.TlsReady(socket, _, _) = ready
      let empty = case transport.read(socket, 1, 10_000) {
        Ok(transport.ReadEnd(_)) | Error(transport.Closed) -> True
        _ -> False
      }
      let _closed = transport.close(socket)
      empty
    })
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 10_000, 10_000)
  let assert Ok(secured) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca],
      [<<"http/1.1">>],
      10_000,
    )
  let transport.TlsReady(socket, selected, _) = secured
  let authenticated = selected == <<"http/1.1">>
  assert authenticated
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        process.send(events, 1)
        Ok(body.PullEnd([]))
      }),
      None,
      None,
      fn() { process.send(events, 2) },
    )
  let outgoing =
    request.Request(
      method: http.Post,
      headers: [],
      body: source,
      scheme:,
      host: "localhost",
      port: Some(port),
      path: "/",
      query: None,
    )
  let outcome =
    exchange.run_presecured(
      outgoing,
      socket,
      fn() { process.send(events, 3) },
      exchange.defaults(),
      transport.monotonic_millisecond() - 1,
    )
  let correct_failure = case outcome {
    Error(failure) -> error.kind(failure) == expected
    Ok(incoming) -> {
      body.cancel(incoming.body)
      False
    }
  }
  let empty = http_test_support.await_task(peer)
  let _stopped = transport.stop(listener)
  assert empty
  assert process.receive(events, within: 0) == Ok(3)
  assert process.receive(events, within: 0) == Error(Nil)
  body.cancel(source)
  assert process.receive(events, within: 0) == Ok(2)
  assert correct_failure
}
