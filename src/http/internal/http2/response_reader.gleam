//// Pure bounded streaming state for one HTTP/2 client response.

import gleam/bit_array
import gleam/http/response.{type Response}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http/body
import http/internal/http2/connection
import http/internal/http2/header_codec
import http/internal/http2/header_semantics
import http/internal/http2/message

/// Final response metadata emitted exactly once.
pub type Head {
  Head(response: Response(Nil), content_length: Option(Int))
}

/// One DATA payload and the receive-window credit retained with it.
pub type Chunk {
  Chunk(bytes: BitArray, flow_controlled_bytes: Int)
}

/// One bounded cursor read and credit released by that exact read.
pub type ChunkRead {
  ChunkPart(bytes: BitArray, remaining: Option(Chunk), released_credit: Int)
}

/// Output produced by one ordered connection-action batch.
pub type Progress {
  Progress(
    state: State,
    head: Option(Head),
    chunks: List(Chunk),
    completion: Option(body.Headers),
  )
}

/// Streaming response sequencing or peer-abort failure.
pub type Error {
  InvalidLimits
  InvalidReadLimit
  InvalidChunk
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
  Receiving
  Finished
}

/// Opaque sequencing state. DATA bytes are emitted and never retained here.
pub opaque type State {
  State(
    stream_id: Int,
    maximum_body_bytes: Int,
    maximum_informational: Int,
    informational_received: Int,
    body_bytes_received: Int,
    phase: Phase,
  )
}

type Accumulator {
  Accumulator(
    state: State,
    head: Option(Head),
    reversed_chunks: List(Chunk),
    completion: Option(body.Headers),
  )
}

/// Construct an empty streaming reader with finite per-response limits.
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
        phase: AwaitingFinal,
      ))
  }
}

/// Consume actions transactionally without accumulating emitted body bytes.
pub fn accept(
  state: State,
  actions: List(connection.Action),
) -> Result(Progress, Error) {
  use accumulated <- result.try(accept_actions(
    Accumulator(state, None, [], None),
    actions,
  ))
  let Accumulator(state, head, reversed_chunks, completion) = accumulated
  Ok(Progress(state, head, list.reverse(reversed_chunks), completion))
}

/// Total DATA payload bytes accepted for the response.
pub fn body_bytes_received(state: State) -> Int {
  state.body_bytes_received
}

/// Return whether END_STREAM or trailers completed the response.
pub fn finished(state: State) -> Bool {
  state.phase == Finished
}

/// Take at most `maximum_bytes`, retaining credit until the final part.
pub fn read_chunk(
  chunk: Chunk,
  maximum_bytes: Int,
) -> Result(ChunkRead, Error) {
  let Chunk(bytes, controlled) = chunk
  case maximum_bytes > 0, bit_array.bit_size(bytes) % 8 == 0, controlled >= 0 {
    False, _, _ -> Error(InvalidReadLimit)
    _, False, _ | _, _, False -> Error(InvalidChunk)
    True, True, True -> {
      let size = bit_array.byte_size(bytes)
      case size <= maximum_bytes {
        True -> Ok(ChunkPart(bytes, None, released_credit: controlled))
        False -> {
          use prefix <- result.try(
            bit_array.slice(bytes, at: 0, take: maximum_bytes)
            |> result.replace_error(InvalidChunk),
          )
          use remaining <- result.try(
            bit_array.slice(
              bytes,
              at: maximum_bytes,
              take: size - maximum_bytes,
            )
            |> result.replace_error(InvalidChunk),
          )
          Ok(ChunkPart(
            prefix,
            Some(Chunk(remaining, controlled)),
            released_credit: 0,
          ))
        }
      }
    }
  }
}

fn accept_actions(
  accumulated: Accumulator,
  actions: List(connection.Action),
) -> Result(Accumulator, Error) {
  case actions {
    [] -> Ok(accumulated)
    [action, ..rest] -> {
      use accumulated <- result.try(accept_action(accumulated, action))
      accept_actions(accumulated, rest)
    }
  }
}

fn accept_action(
  accumulated: Accumulator,
  action: connection.Action,
) -> Result(Accumulator, Error) {
  case action {
    connection.HeadersReceived(section) -> accept_headers(accumulated, section)
    connection.DataReceived(stream_id, bytes, end_stream, controlled) ->
      accept_data(accumulated, stream_id, bytes, end_stream, controlled)
    connection.StreamReset(stream_id, error_code) -> {
      use _ <- result.try(require_stream(accumulated.state, stream_id))
      Error(StreamReset(error_code: error_code))
    }
    connection.PeerGoAway(last_stream_id, _, _) ->
      case last_stream_id < accumulated.state.stream_id {
        True -> Error(StreamRefused)
        False -> Ok(accumulated)
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
    | connection.IgnoredUnknownFrame(_) -> Ok(accumulated)
  }
}

fn accept_headers(
  accumulated: Accumulator,
  section: header_codec.HeaderSection,
) -> Result(Accumulator, Error) {
  let header_codec.HeaderSection(stream_id, end_stream, validated, _) = section
  use _ <- result.try(require_stream(accumulated.state, stream_id))
  let header_semantics.Validated(control, _, content_length) = validated
  case control, accumulated.state.phase {
    header_semantics.ResponseControlData(status), AwaitingFinal
      if status >= 100 && status < 200
    -> accept_informational(accumulated)
    header_semantics.ResponseControlData(_), AwaitingFinal -> {
      use incoming <- result.try(
        message.response_from_validated(validated, Nil)
        |> result.map_error(MessageFailure),
      )
      Ok(
        Accumulator(
          ..accumulated,
          state: State(..accumulated.state, phase: case end_stream {
            True -> Finished
            False -> Receiving
          }),
          head: Some(Head(incoming, content_length)),
          completion: case end_stream {
            True -> Some([])
            False -> None
          },
        ),
      )
    }
    header_semantics.TrailerControlData, Receiving -> {
      use trailers <- result.try(
        message.trailers_from_validated(validated)
        |> result.map_error(MessageFailure),
      )
      Ok(
        Accumulator(
          ..accumulated,
          state: State(..accumulated.state, phase: Finished),
          completion: Some(trailers),
        ),
      )
    }
    _, _ -> Error(UnexpectedHeaders)
  }
}

fn accept_informational(
  accumulated: Accumulator,
) -> Result(Accumulator, Error) {
  let received = accumulated.state.informational_received + 1
  case received > accumulated.state.maximum_informational {
    True ->
      Error(TooManyInformational(
        maximum: accumulated.state.maximum_informational,
      ))
    False ->
      Ok(
        Accumulator(
          ..accumulated,
          state: State(..accumulated.state, informational_received: received),
        ),
      )
  }
}

fn accept_data(
  accumulated: Accumulator,
  stream_id: Int,
  bytes: BitArray,
  end_stream: Bool,
  controlled: Int,
) -> Result(Accumulator, Error) {
  use _ <- result.try(require_stream(accumulated.state, stream_id))
  case accumulated.state.phase {
    AwaitingFinal -> Error(DataBeforeFinalHeaders)
    Finished -> Error(DataAfterCompletion)
    Receiving -> {
      let count = bit_array.byte_size(bytes)
      use _ <- result.try(
        case
          count
          <= accumulated.state.maximum_body_bytes
          - accumulated.state.body_bytes_received
        {
          True -> Ok(Nil)
          False ->
            Error(BodyTooLarge(maximum: accumulated.state.maximum_body_bytes))
        },
      )
      let state =
        State(
          ..accumulated.state,
          body_bytes_received: accumulated.state.body_bytes_received + count,
          phase: case end_stream {
            True -> Finished
            False -> Receiving
          },
        )
      let reversed_chunks = case count > 0 || controlled > 0 {
        True -> [Chunk(bytes, controlled), ..accumulated.reversed_chunks]
        False -> accumulated.reversed_chunks
      }
      Ok(
        Accumulator(
          ..accumulated,
          state:,
          reversed_chunks:,
          completion: case end_stream {
            True -> Some([])
            False -> None
          },
        ),
      )
    }
  }
}

fn require_stream(state: State, received: Int) -> Result(Nil, Error) {
  case received == state.stream_id {
    True -> Ok(Nil)
    False ->
      Error(UnexpectedStream(expected: state.stream_id, received: received))
  }
}
