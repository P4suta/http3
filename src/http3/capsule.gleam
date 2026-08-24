//// Bounded RFC 9297 Capsule Protocol codec for Extended CONNECT streams.

import gleam/result
import gleam_quic/internal/http3/capsule as core

/// One standard DATAGRAM Capsule or an extension capsule.
pub type Capsule {
  Datagram(BitArray)
  Extension(capsule_type: Int, value: BitArray)
}

/// Incremental decoder retaining at most its configured byte limit.
pub opaque type Decoder {
  Decoder(state: core.State)
}

/// Result of parsing at most one capsule.
pub type Outcome {
  NeedMore(Decoder)
  Ready(decoder: Decoder, capsule: Capsule)
}

/// Invalid configuration, wire input, bound, or clean stream end.
pub type Error {
  InvalidConfiguration
  NonByteAligned
  BufferLimitExceeded(limit: Int)
  CapsuleLimitExceeded(limit: Int)
  Truncated
  InvalidCapsuleType
}

/// Create a bounded incremental decoder.
pub fn decoder(
  maximum_capsule_bytes maximum_capsule_bytes: Int,
  maximum_buffered_bytes maximum_buffered_bytes: Int,
) -> Result(Decoder, Error) {
  core.new(maximum_capsule_bytes, maximum_buffered_bytes)
  |> result.map(Decoder)
  |> result.map_error(map_error)
}

/// Append one byte-aligned HTTP DATA fragment.
pub fn push(
  decoder decoder: Decoder,
  bytes bytes: BitArray,
) -> Result(Decoder, Error) {
  let Decoder(state) = decoder
  core.push(state, bytes)
  |> result.map(Decoder)
  |> result.map_error(map_error)
}

/// Parse at most one capsule while preserving following bytes.
pub fn next(decoder: Decoder) -> Result(Outcome, Error) {
  let Decoder(state) = decoder
  case core.next(state) {
    Ok(core.NeedMore(state)) -> Ok(NeedMore(Decoder(state)))
    Ok(core.CapsuleReady(state, value)) ->
      Ok(Ready(Decoder(state), from_core(value)))
    Error(error) -> Error(map_error(error))
  }
}

/// Validate that stream FIN arrived exactly on a capsule boundary.
pub fn finish(decoder: Decoder) -> Result(Nil, Error) {
  let Decoder(state) = decoder
  core.finish(state) |> result.map_error(map_error)
}

/// Encode one complete capsule.
pub fn encode(capsule: Capsule) -> Result(BitArray, Error) {
  core.encode(to_core(capsule)) |> result.map_error(map_error)
}

/// Return bytes retained for an incomplete or following capsule.
pub fn buffered_bytes(decoder: Decoder) -> Int {
  let Decoder(state) = decoder
  core.buffered_bytes(state)
}

fn to_core(capsule: Capsule) -> core.Capsule {
  case capsule {
    Datagram(payload) -> core.Datagram(payload)
    Extension(capsule_type, value) -> core.Unknown(capsule_type, value)
  }
}

fn from_core(capsule: core.Capsule) -> Capsule {
  case capsule {
    core.Datagram(payload) -> Datagram(payload)
    core.Unknown(capsule_type, value) -> Extension(capsule_type, value)
  }
}

fn map_error(error: core.Error) -> Error {
  case error {
    core.InvalidConfiguration -> InvalidConfiguration
    core.NonByteAligned -> NonByteAligned
    core.BufferLimitExceeded(limit) -> BufferLimitExceeded(limit)
    core.CapsuleLimitExceeded(limit) -> CapsuleLimitExceeded(limit)
    core.TruncatedCapsule -> Truncated
    core.IntegerFailure(_) -> InvalidCapsuleType
  }
}
