//// Explicit application policy over the existing public HTTP primitives.
//// This fixture does not assert automatic server-wide RFC enforcement.

import gleam/bit_array
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleeunit/should
import http/body
import http/client
import http/compression
import http/context
import http/error
import http/internal/dictionary_policy
import http/server
import http_test_support

pub fn explicit_dictionary_policy_over_verified_http1_test() -> Nil {
  assert exchange_cases(protocol: 1)
}

pub fn explicit_dictionary_policy_over_verified_http2_test() -> Nil {
  assert exchange_cases(protocol: 2)
}

pub fn explicit_dictionary_policy_over_verified_http3_test() -> Nil {
  assert exchange_cases(protocol: 3)
}

type Observation {
  Observation(Int, Result(Nil, compression.Error), Bool, Bool)
}

fn exchange_cases(protocol protocol: Int) -> Bool {
  let observed = process.new_subject()
  let released = process.new_subject()
  let selected = dictionary()
  let handler = fn(incoming: request.Request(body.Body), metadata) {
    let id =
      incoming.path |> string.drop_start(1) |> int.parse |> result.unwrap(-1)
    let #(candidate, now, coding) = selection(id:, selected:)
    let fields =
      list.filter_map(incoming.headers, fn(field) {
        case field {
          #(name, value) if name == "available-dictionary" -> Ok(value)
          _ -> Error(Nil)
        }
      })
    let input = body.read_all(incoming.body, 2048)
    let encoded = case input {
      Ok(#(bytes, [])) ->
        public_composition(
          selected: candidate,
          fields:,
          now:,
          coding:,
          input: bytes,
        )
      _ -> Error(compression.InvalidEncoding)
    }
    let internal =
      dictionary_policy.encode(
        coding:,
        input: payload(),
        dictionary: candidate,
        available_dictionary: fields,
        now:,
        limits: compression.defaults(),
      )
    let expected_protocol = case protocol {
      1 -> context.Http1
      2 -> context.Http2
      _ -> context.Http3
    }
    process.send(
      observed,
      Observation(
        id,
        classify(encoded),
        encoded == internal,
        context.protocol(metadata) == expected_protocol
          && context.tls_identity(metadata)
          == context.TlsIdentity("localhost", None),
      ),
    )
    let #(status, headers, bytes) =
      encoded
      |> result.map(fn(bytes) {
        #(200, [#("content-encoding", coding_name(coding))], bytes)
      })
      |> result.unwrap(#(409, [], <<>>))
    use outgoing <- result.try(
      body.from_pull(
        bytes_pull(bytes),
        Some(bit_array.byte_size(bytes)),
        None,
        fn() {
          // Disposal of an active incoming stream also cancels its exchange.
          // Wait until response transfer owns terminal cleanup before doing it.
          let cleanup = body.cancel_within(incoming.body, 1000)
          process.send(released, #(id, cleanup == Ok(Nil)))
        },
      ),
    )
    Ok(response.Response(status, headers, outgoing))
  }
  let outcome = {
    use running <- scoped(server.start(server.defaults(), handler), server.stop)
    let #(certificate, key, ca) = http_test_support.server_credentials()
    use listener <- scoped(
      listen(running:, protocol:, certificate:, key:),
      server.stop_listener,
    )
    let context.Endpoint(_, port) = server.listener_endpoint(listener)
    let config =
      client.defaults()
      |> client.with_ca_certificates([ca])
      |> client.without_retries
    let config = case protocol {
      3 ->
        client.with_https_record_resolver(config, fn(_, port, _) {
          Ok([client.HttpsRecord(["h3"], port, True, 60_000)])
        })
      _ -> client.without_protocol_discovery(config)
    }
    use connection <- scoped(client.start(config), client.close)
    run_cases(
      connection:,
      port:,
      protocol:,
      selected:,
      observed:,
      released:,
      remaining: [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7],
    )
  }
  outcome
  && process.receive(released, within: 0) == Error(Nil)
  && process.receive(observed, within: 0) == Error(Nil)
}

fn scoped(
  resource: Result(resource, error.Error),
  close: fn(resource) -> Result(Nil, error.Error),
  work: fn(resource) -> Bool,
) -> Bool {
  resource
  |> result.map(fn(resource) {
    let outcome = work(resource)
    let cleanup = close(resource)
    outcome && cleanup == Ok(Nil)
  })
  |> result.unwrap(False)
}

fn run_cases(
  connection connection: client.Client,
  port port: Int,
  protocol protocol: Int,
  selected selected: compression.Dictionary,
  observed observed: process.Subject(Observation),
  released released: process.Subject(#(Int, Bool)),
  remaining remaining: List(Int),
) -> Bool {
  case remaining {
    [] -> True
    [id, ..rest] -> {
      let field = advertisement(selected.hash)
      let fields = case id {
        1 -> [advertisement(other_hash())]
        2 -> []
        3 -> [field, field]
        _ -> [field]
      }
      let outgoing =
        request.new()
        |> request.set_method(http.Post)
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_path("/" <> int.to_string(id))
        |> request.set_body(body.from_bytes(payload()))
      let outgoing =
        request.Request(..outgoing, headers: [
          #("dictionary-id", "\"same-opaque-id\""),
          ..list.map(fields, fn(value) { #("available-dictionary", value) })
        ])
      let expected = case id {
        1 | 5 -> Error(compression.DictionaryMismatch)
        2 -> Error(compression.DictionaryRequired)
        3 -> Error(compression.InvalidDictionary)
        4 -> Error(compression.NoMatchingDictionary)
        _ -> Ok(Nil)
      }
      let received =
        client.exchange(connection, outgoing)
        |> result.map(fn(exchange) {
          check_response(exchange:, selected:, id:, expected:, protocol:)
        })
        |> result.unwrap(False)
      let observation = process.receive(observed, within: 2000)
      let released_now = process.receive(released, within: 2000)
      let passed =
        received
        && observation == Ok(Observation(id, expected, True, True))
        && released_now == Ok(#(id, True))
      passed
      && run_cases(
        connection:,
        port:,
        protocol:,
        selected:,
        observed:,
        released:,
        remaining: rest,
      )
    }
  }
}

fn check_response(
  exchange exchange: client.Exchange,
  selected selected: compression.Dictionary,
  id id: Int,
  expected expected: Result(Nil, compression.Error),
  protocol protocol: Int,
) -> Bool {
  let received = client.response(exchange)
  let bytes = body.read_all(received.body, 4096) |> should.be_ok
  let cleanup = body.cancel_within(received.body, 1000)
  let #(candidate, _, coding) = selection(id:, selected:)
  let valid = case expected, bytes {
    Ok(Nil), #(encoded, []) ->
      received.status == 200
      && list.contains(received.headers, #(
        "content-encoding",
        coding_name(coding),
      ))
      && compression.decode(
        coding:,
        input: encoded,
        dictionary: Some(candidate.content),
        limits: compression.defaults(),
      )
      == Ok(payload())
    Error(reason), #(<<>>, []) ->
      received.status == 409
      && expected == Error(reason)
      && !list.any(received.headers, fn(field) { field.0 == "content-encoding" })
    _, _ -> False
  }
  let actual_protocol = case client.selected_protocol(exchange) {
    client.Http1 -> 1
    client.Http2 -> 2
    client.Http3 -> 3
  }
  assert valid
  assert cleanup == Ok(Nil)
  assert actual_protocol == protocol
  True
}

fn public_composition(
  selected selected: compression.Dictionary,
  fields fields: List(String),
  now now: Int,
  coding coding: compression.Coding,
  input input: BitArray,
) -> Result(BitArray, compression.Error) {
  use advertised <- result.try(case fields {
    [] -> Error(compression.DictionaryRequired)
    [value] -> compression.parse_available_dictionary(value)
    _ -> Error(compression.InvalidDictionary)
  })
  use _ <- result.try(
    case selected.fetched_at <= now && now < selected.fresh_until {
      True -> Ok(Nil)
      False -> Error(compression.NoMatchingDictionary)
    },
  )
  use actual <- result.try(compression.dictionary_hash(
    selected.content,
    compression.defaults(),
  ))
  use _ <- result.try(case actual == advertised && actual == selected.hash {
    True -> Ok(Nil)
    False -> Error(compression.DictionaryMismatch)
  })
  compression.encode(
    coding:,
    input:,
    dictionary: Some(selected.content),
    limits: compression.defaults(),
  )
}

fn selection(
  id id: Int,
  selected selected: compression.Dictionary,
) -> #(compression.Dictionary, Int, compression.Coding) {
  let candidate = case id {
    5 ->
      compression.Dictionary(
        ..selected,
        content: bit_array.from_string("replacement bytes"),
      )
    6 -> compression.Dictionary(..selected, identifier: "different-hint")
    _ -> selected
  }
  #(
    candidate,
    case id {
      4 -> 200
      _ -> 150
    },
    case id {
      7 -> compression.DictionaryZstandard
      _ -> compression.DictionaryBrotli
    },
  )
}

fn dictionary() -> compression.Dictionary {
  let content = bit_array.from_string("bounded original dictionary")
  let assert Ok(hash) =
    compression.dictionary_hash(content, compression.defaults())
  compression.Dictionary(
    compression.IsolationKey("site", "profile"),
    "https://localhost",
    "/*",
    [],
    "same-opaque-id",
    compression.Raw,
    content,
    hash,
    200,
    100,
    2048,
  )
}

fn other_hash() -> BitArray {
  let assert Ok(value) =
    compression.dictionary_hash(
      bit_array.from_string("different"),
      compression.defaults(),
    )
  value
}

fn advertisement(hash: BitArray) -> String {
  let assert Ok(value) = compression.serialize_available_dictionary(hash)
  value
}

fn classify(
  value: Result(BitArray, compression.Error),
) -> Result(Nil, compression.Error) {
  result.map(value, fn(_) { Nil })
}

fn payload() -> BitArray {
  bit_array.from_string("bounded representation")
}

fn bytes_pull(bytes: BitArray) -> body.Pull {
  body.pull(fn(_) {
    case bytes {
      <<>> -> Ok(body.PullEnd([]))
      _ -> Ok(body.PullData(bytes, bytes_pull(<<>>)))
    }
  })
}

fn coding_name(coding: compression.Coding) -> String {
  case coding {
    compression.DictionaryZstandard -> "dcz"
    _ -> "dcb"
  }
}

fn listen(
  running running: server.Server,
  protocol protocol: Int,
  certificate certificate: BitArray,
  key key: BitArray,
) -> Result(server.Listener, error.Error) {
  case protocol {
    1 ->
      server.listen_http1_tls(
        running,
        <<127, 0, 0, 1>>,
        0,
        server.http1_defaults(),
        certificate,
        key,
        "localhost",
      )
    2 ->
      server.listen_http2_tls(
        running,
        <<127, 0, 0, 1>>,
        0,
        server.http2_defaults(),
        certificate,
        key,
        "localhost",
      )
    _ -> {
      use config <- result.try(server.http3_defaults(
        certificate,
        key,
        "localhost",
      ))
      server.listen_http3(running, <<127, 0, 0, 1>>, 0, config)
    }
  }
}
