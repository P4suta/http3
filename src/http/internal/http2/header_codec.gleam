//// Bounded HTTP/2 field-section assembly, HPACK, and semantic validation.

import gleam/dict.{type Dict}
import gleam/option.{type Option}
import gleam/result
import http/internal/http2/frame
import http/internal/http2/header_block
import http/internal/http2/header_semantics
import http/internal/http2/hpack/decoder

/// The local endpoint role receiving field sections.
pub type Role {
  Client
  Server
}

/// Finite compressed, decoded, dynamic-table, and stream-phase limits.
pub type Limits {
  Limits(
    maximum_block_bytes: Int,
    maximum_header_list_bytes: Int,
    maximum_table_capacity: Int,
    maximum_tracked_streams: Int,
  )
}

/// One complete, decompressed, semantically validated field section.
pub type HeaderSection {
  HeaderSection(
    stream_id: Int,
    end_stream: Bool,
    validated: header_semantics.Validated,
    priority: Option(header_block.Priority),
  )
}

/// Progress after accepting one HEADERS or CONTINUATION frame.
pub type Outcome {
  Waiting(State)
  Complete(State, HeaderSection)
}

/// Configuration, framing, compression, semantics, or resource failure.
pub type Error {
  InvalidLimits
  BlockFailure(header_block.Error)
  CompressionFailure(decoder.Error)
  SemanticsFailure(header_semantics.Error)
  TooManyTrackedStreams(maximum: Int)
  TrailersWithoutEndStream(stream_id: Int)
}

type Phase {
  AwaitingFinalResponse
  MessageHeadersReceived
}

/// Connection-scoped codec. No process, socket, or backend terms are exposed.
pub opaque type State {
  State(
    role: Role,
    limits: Limits,
    assembler: header_block.State,
    decoder: decoder.Decoder,
    phases: Dict(Int, Phase),
    extended_connect_enabled: Bool,
  )
}

/// Construct a bounded connection-scoped field-section codec.
pub fn new(
  role: Role,
  limits: Limits,
  extended_connect_enabled extended_connect_enabled: Bool,
) -> Result(State, Error) {
  let Limits(
    maximum_block_bytes,
    maximum_header_list_bytes,
    maximum_table_capacity,
    maximum_tracked_streams,
  ) = limits
  case maximum_tracked_streams > 0 {
    False -> Error(InvalidLimits)
    True -> {
      use assembler <- result.try(
        header_block.new(maximum_block_bytes)
        |> result.map_error(BlockFailure),
      )
      use decoder <- result.try(
        decoder.new(maximum_table_capacity, maximum_header_list_bytes)
        |> result.map_error(CompressionFailure),
      )
      Ok(State(
        role:,
        limits:,
        assembler:,
        decoder:,
        phases: dict.new(),
        extended_connect_enabled:,
      ))
    }
  }
}

/// Accept one field-section frame transactionally.
pub fn accept(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Outcome, Error) {
  use assembled <- result.try(
    header_block.accept(state.assembler, header, payload)
    |> result.map_error(BlockFailure),
  )
  case assembled {
    header_block.Waiting(assembler) ->
      Ok(Waiting(State(..state, assembler: assembler)))
    header_block.Complete(assembler, block) ->
      complete_block(state, assembler, block)
  }
}

/// Forget phase metadata after a stream and its application delivery finish.
pub fn release(state: State, stream_id: Int) -> State {
  State(..state, phases: dict.delete(state.phases, stream_id))
}

/// Number of stream phases retained under the configured bound.
pub fn tracked_streams(state: State) -> Int {
  dict.size(state.phases)
}

/// Whether no CONTINUATION sequence is currently in progress.
pub fn is_idle(state: State) -> Bool {
  header_block.is_idle(state.assembler)
}

fn complete_block(
  state: State,
  assembler: header_block.State,
  block: header_block.Block,
) -> Result(Outcome, Error) {
  let header_block.Block(stream_id, fragment, end_stream, priority) = block
  let section_kind = section_kind(state, stream_id)
  use _ <- result.try(require_phase_capacity(state, stream_id))
  use decoded <- result.try(
    decoder.decode(state.decoder, fragment)
    |> result.map_error(CompressionFailure),
  )
  let decoder.Decoded(next_decoder, fields) = decoded
  use validated <- result.try(
    header_semantics.validate(
      fields,
      section_kind,
      state.extended_connect_enabled,
    )
    |> result.map_error(SemanticsFailure),
  )
  use _ <- result.try(require_terminating_trailers(
    section_kind,
    stream_id,
    end_stream,
  ))
  let phases = update_phase(state, stream_id, section_kind, validated)
  let next =
    State(..state, assembler: assembler, decoder: next_decoder, phases: phases)
  Ok(Complete(next, HeaderSection(stream_id, end_stream, validated, priority)))
}

fn section_kind(state: State, stream_id: Int) -> header_semantics.SectionKind {
  case state.role, dict.get(state.phases, stream_id) {
    Server, Error(Nil) -> header_semantics.RequestSection
    Client, Error(Nil) | Client, Ok(AwaitingFinalResponse) ->
      header_semantics.ResponseSection
    Client, Ok(MessageHeadersReceived) | Server, Ok(_) ->
      header_semantics.TrailerSection
  }
}

fn update_phase(
  state: State,
  stream_id: Int,
  section_kind: header_semantics.SectionKind,
  validated: header_semantics.Validated,
) -> Dict(Int, Phase) {
  let next = case section_kind, validated {
    header_semantics.ResponseSection,
      header_semantics.Validated(
        header_semantics.ResponseControlData(status),
        _,
        _,
      )
    ->
      case header_semantics.is_informational_status(status) {
        True -> AwaitingFinalResponse
        False -> MessageHeadersReceived
      }
    _, _ -> MessageHeadersReceived
  }
  dict.insert(state.phases, stream_id, next)
}

fn require_phase_capacity(state: State, stream_id: Int) -> Result(Nil, Error) {
  let Limits(_, _, _, maximum) = state.limits
  case
    dict.has_key(state.phases, stream_id) || dict.size(state.phases) < maximum
  {
    True -> Ok(Nil)
    False -> Error(TooManyTrackedStreams(maximum: maximum))
  }
}

fn require_terminating_trailers(
  section_kind: header_semantics.SectionKind,
  stream_id: Int,
  end_stream: Bool,
) -> Result(Nil, Error) {
  case section_kind, end_stream {
    header_semantics.TrailerSection, False ->
      Error(TrailersWithoutEndStream(stream_id: stream_id))
    _, _ -> Ok(Nil)
  }
}
