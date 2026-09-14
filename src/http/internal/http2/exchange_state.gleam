//// Pure bounded assembly of one HTTP/2 client response stream.

import gleam/bit_array
import gleam/http/response.{type Response, Response}
import gleam/list
import gleam/result
import http/body
import http/internal/http2/connection
import http/internal/http2/header_codec
import http/internal/http2/header_semantics
import http/internal/http2/message

/// Receive-window credit that must be returned after retaining DATA.
pub type Credit {
  Credit(stream_id: Int, octets: Int)
}

/// Progress after consuming one ordered connection-action batch.
pub type Outcome {
  Waiting(state: State, credits: List(Credit))
  Complete(state: State, response: Response(body.Body), credits: List(Credit))
}

/// Bounded response sequencing or peer-abort failure.
pub type Error {
  InvalidLimits
  UnexpectedStream(expected: Int, received: Int)
  UnexpectedHeaders
  DataBeforeFinalHeaders
  DataAfterCompletion
  BodyTooLarge(maximum: Int)
  TooManyInformational(maximum: Int)
  StreamReset(error_code: Int)
  StreamRefused
  MessageFailure(message.Error)
}

type Phase {
  AwaitingFinal
  Receiving(Response(Nil))
  Finished(Response(body.Body))
}

/// Opaque state retaining at most the configured response-body bytes.
pub opaque type State {
  State(
    stream_id: Int,
    maximum_body_bytes: Int,
    maximum_informational: Int,
    informational_received: Int,
    body_bytes_received: Int,
    reversed_body: List(BitArray),
    phase: Phase,
  )
}

/// Construct an empty response accumulator for one client stream.
pub fn new(
  stream_id stream_id: Int,
  maximum_body_bytes maximum_body_bytes: Int,
  maximum_informational maximum_informational: Int,
) -> Result(State, Error) {
  case
    stream_id > 0
    && stream_id % 2 == 1
    && maximum_body_bytes >= 0
    && maximum_informational >= 0
  {
    False -> Error(InvalidLimits)
    True ->
      Ok(State(
        stream_id:,
        maximum_body_bytes:,
        maximum_informational:,
        informational_received: 0,
        body_bytes_received: 0,
        reversed_body: [],
        phase: AwaitingFinal,
      ))
  }
}

/// Consume ordered connection actions transactionally.
pub fn accept(
  state: State,
  actions: List(connection.Action),
) -> Result(Outcome, Error) {
  use #(state, reversed_credits) <- result.try(
    accept_actions(state, actions, []),
  )
  let credits = list.reverse(reversed_credits)
  case state.phase {
    Finished(incoming) -> Ok(Complete(state, incoming, credits))
    AwaitingFinal | Receiving(_) -> Ok(Waiting(state, credits))
  }
}

fn accept_actions(
  state: State,
  actions: List(connection.Action),
  reversed_credits: List(Credit),
) -> Result(#(State, List(Credit)), Error) {
  case actions {
    [] -> Ok(#(state, reversed_credits))
    [action, ..rest] -> {
      use #(state, credit) <- result.try(accept_action(state, action))
      let reversed_credits = reverse_prepend(credit, reversed_credits)
      accept_actions(state, rest, reversed_credits)
    }
  }
}

fn accept_action(
  state: State,
  action: connection.Action,
) -> Result(#(State, List(Credit)), Error) {
  case action {
    connection.HeadersReceived(section) ->
      accept_headers(state, section)
      |> result.map(fn(state) { #(state, []) })
    connection.DataReceived(stream_id, bytes, end_stream, controlled) -> {
      use _ <- result.try(require_stream(state, stream_id))
      use state <- result.try(accept_data(state, bytes, end_stream))
      let credits = case controlled > 0 {
        True -> [Credit(stream_id: stream_id, octets: controlled)]
        False -> []
      }
      Ok(#(state, credits))
    }
    connection.StreamReset(stream_id, error_code) -> {
      use _ <- result.try(require_stream(state, stream_id))
      Error(StreamReset(error_code: error_code))
    }
    connection.PeerGoAway(last_stream_id, _, _) ->
      case last_stream_id < state.stream_id {
        True -> Error(StreamRefused)
        False -> Ok(#(state, []))
      }
    connection.SendSettingsAcknowledgement
    | connection.PeerSettingsChanged(_)
    | connection.SettingsAcknowledged
    | connection.SendPingAcknowledgement(_)
    | connection.PingAcknowledged(_)
    | connection.ConnectionWindowIncreased(_)
    | connection.StreamWindowIncreased(_, _)
    | connection.LegacyPriorityReceived(_, _, _, _)
    | connection.OriginsReceived(_)
    | connection.PriorityUpdated(_, _)
    | connection.IgnoredUnknownFrame(_) -> Ok(#(state, []))
  }
}

fn accept_headers(
  state: State,
  section: header_codec.HeaderSection,
) -> Result(State, Error) {
  let header_codec.HeaderSection(stream_id, end_stream, validated, _) = section
  use _ <- result.try(require_stream(state, stream_id))
  let header_semantics.Validated(control, _, _) = validated
  case control, state.phase {
    header_semantics.ResponseControlData(status), AwaitingFinal
      if status >= 100 && status < 200
    -> accept_informational(state)
    header_semantics.ResponseControlData(_), AwaitingFinal -> {
      use incoming <- result.try(
        message.response_from_validated(validated, Nil)
        |> result.map_error(MessageFailure),
      )
      case end_stream {
        True -> finish(State(..state, phase: Receiving(incoming)), [])
        False -> Ok(State(..state, phase: Receiving(incoming)))
      }
    }
    header_semantics.TrailerControlData, Receiving(_) -> {
      use trailers <- result.try(
        message.trailers_from_validated(validated)
        |> result.map_error(MessageFailure),
      )
      finish(state, trailers)
    }
    _, _ -> Error(UnexpectedHeaders)
  }
}

fn accept_informational(state: State) -> Result(State, Error) {
  let received = state.informational_received + 1
  case received > state.maximum_informational {
    True -> Error(TooManyInformational(maximum: state.maximum_informational))
    False -> Ok(State(..state, informational_received: received))
  }
}

fn accept_data(
  state: State,
  bytes: BitArray,
  end_stream: Bool,
) -> Result(State, Error) {
  case state.phase {
    AwaitingFinal -> Error(DataBeforeFinalHeaders)
    Finished(_) -> Error(DataAfterCompletion)
    Receiving(_) -> {
      let count = bit_array.byte_size(bytes)
      use _ <- result.try(
        case count <= state.maximum_body_bytes - state.body_bytes_received {
          True -> Ok(Nil)
          False -> Error(BodyTooLarge(maximum: state.maximum_body_bytes))
        },
      )
      let state =
        State(
          ..state,
          body_bytes_received: state.body_bytes_received + count,
          reversed_body: [bytes, ..state.reversed_body],
        )
      case end_stream {
        True -> finish(state, [])
        False -> Ok(state)
      }
    }
  }
}

fn finish(state: State, trailers: body.Headers) -> Result(State, Error) {
  case state.phase {
    Receiving(head) -> {
      let bytes = state.reversed_body |> list.reverse |> bit_array.concat
      let incoming =
        Response(..head, body: body.from_bytes_with_trailers(bytes, trailers))
      Ok(State(..state, phase: Finished(incoming), reversed_body: []))
    }
    AwaitingFinal -> Error(DataBeforeFinalHeaders)
    Finished(_) -> Error(DataAfterCompletion)
  }
}

fn require_stream(state: State, received: Int) -> Result(Nil, Error) {
  case received == state.stream_id {
    True -> Ok(Nil)
    False ->
      Error(UnexpectedStream(expected: state.stream_id, received: received))
  }
}

fn reverse_prepend(
  credits: List(Credit),
  reversed: List(Credit),
) -> List(Credit) {
  case credits {
    [] -> reversed
    [credit, ..rest] -> reverse_prepend(rest, [credit, ..reversed])
  }
}
