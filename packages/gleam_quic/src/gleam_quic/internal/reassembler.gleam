//// Bounded out-of-order CRYPTO and STREAM byte reassembly.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/varint

type Segment {
  Segment(offset: Int, data: BitArray)
}

/// Sorted non-overlapping segments and immutable final-size state.
pub opaque type Reassembler {
  Reassembler(
    read_offset: Int,
    final_size: Option(Int),
    segments: List(Segment),
    buffered_bytes: Int,
    maximum_buffered_bytes: Int,
    maximum_final_size: Int,
  )
}

/// One bounded contiguous read.
pub type Read {
  Read(state: Reassembler, data: BitArray, finished: Bool)
}

/// A malformed range, conflicting retransmission, or resource-limit failure.
pub type Error {
  InvalidInput
  NonByteAligned
  ConflictingOverlap
  FinalSizeChanged
  FinalSizeTooSmall
  BeyondFinalSize
  BufferLimitExceeded(Int)
}

/// Create an empty ordered-byte reassembler with explicit resource bounds.
pub fn new(
  maximum_buffered_bytes: Int,
  maximum_final_size: Int,
) -> Result(Reassembler, Error) {
  case
    maximum_buffered_bytes >= 0
    && maximum_final_size >= 0
    && maximum_final_size <= varint.maximum
  {
    True ->
      Ok(Reassembler(0, None, [], 0, maximum_buffered_bytes, maximum_final_size))
    False -> Error(InvalidInput)
  }
}

/// Insert one offset range, deduplicating identical overlap and applying FIN.
pub fn insert(
  state: Reassembler,
  offset: Int,
  data: BitArray,
  fin: Bool,
) -> Result(Reassembler, Error) {
  case bit_array.bit_size(data) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> insert_aligned(state, offset, data, fin)
  }
}

/// Read at most `maximum_bytes` from the current contiguous prefix.
pub fn read(state: Reassembler, maximum_bytes: Int) -> Result(Read, Error) {
  case maximum_bytes > 0 {
    False -> Error(InvalidInput)
    True -> read_bounded(state, maximum_bytes)
  }
}

/// Return unique unread bytes retained in memory.
pub fn buffered_bytes(state: Reassembler) -> Int {
  state.buffered_bytes
}

/// Release all unread bytes after a RESET_STREAM final size is authenticated.
pub fn discard_to_final(state: Reassembler) -> Result(Reassembler, Error) {
  case state.final_size {
    None -> Error(InvalidInput)
    Some(final_size) ->
      Ok(
        Reassembler(
          ..state,
          read_offset: final_size,
          segments: [],
          buffered_bytes: 0,
        ),
      )
  }
}

fn insert_aligned(
  state: Reassembler,
  offset: Int,
  data: BitArray,
  fin: Bool,
) -> Result(Reassembler, Error) {
  let data_length = bit_array.byte_size(data)
  let end = offset + data_length
  case
    offset < 0
    || end < offset
    || end > state.maximum_final_size
    || end > varint.maximum
  {
    True -> Error(InvalidInput)
    False -> {
      use next_final_size <- result.try(validate_final_size(state, end, fin))
      use trimmed <- result.try(trim_consumed(state.read_offset, offset, data))
      insert_trimmed(state, trimmed, next_final_size)
    }
  }
}

fn validate_final_size(
  state: Reassembler,
  end: Int,
  fin: Bool,
) -> Result(Option(Int), Error) {
  let highest = highest_received(state)
  case state.final_size, fin {
    Some(final_size), _ if end > final_size -> Error(BeyondFinalSize)
    Some(final_size), True if end != final_size -> Error(FinalSizeChanged)
    Some(final_size), _ -> Ok(Some(final_size))
    None, True if end < highest -> Error(FinalSizeTooSmall)
    None, True -> Ok(Some(end))
    None, False -> Ok(None)
  }
}

fn insert_trimmed(
  state: Reassembler,
  segment: Option(Segment),
  final_size: Option(Int),
) -> Result(Reassembler, Error) {
  case segment {
    None -> Ok(Reassembler(..state, final_size: final_size))
    Some(value) -> {
      use segments <- result.try(insert_segment(state.segments, value, []))
      let buffered = total_bytes(segments, 0)
      case buffered > state.maximum_buffered_bytes {
        True -> Error(BufferLimitExceeded(buffered))
        False ->
          Ok(
            Reassembler(
              ..state,
              final_size: final_size,
              segments: segments,
              buffered_bytes: buffered,
            ),
          )
      }
    }
  }
}

fn trim_consumed(
  read_offset: Int,
  offset: Int,
  data: BitArray,
) -> Result(Option(Segment), Error) {
  let end = offset + bit_array.byte_size(data)
  case end <= read_offset, offset < read_offset {
    True, _ -> Ok(None)
    _, True -> {
      use trimmed <- result.try(slice_from(data, read_offset - offset))
      case trimmed {
        <<>> -> Ok(None)
        _ -> Ok(Some(Segment(read_offset, trimmed)))
      }
    }
    _, _ ->
      case data {
        <<>> -> Ok(None)
        _ -> Ok(Some(Segment(offset, data)))
      }
  }
}

fn insert_segment(
  segments: List(Segment),
  incoming: Segment,
  before_reversed: List(Segment),
) -> Result(List(Segment), Error) {
  case segments {
    [] -> Ok(list.append(list.reverse(before_reversed), [incoming]))
    [current, ..rest] ->
      insert_against_current(current, rest, incoming, before_reversed)
  }
}

fn insert_against_current(
  current: Segment,
  rest: List(Segment),
  incoming: Segment,
  before_reversed: List(Segment),
) -> Result(List(Segment), Error) {
  let current_end = segment_end(current)
  let incoming_end = segment_end(incoming)
  case incoming_end < current.offset, current_end < incoming.offset {
    True, _ ->
      Ok(
        list.append(list.reverse(before_reversed), [incoming, current, ..rest]),
      )
    _, True -> insert_segment(rest, incoming, [current, ..before_reversed])
    _, _ -> {
      use merged <- result.try(merge(current, incoming))
      insert_segment(rest, merged, before_reversed)
    }
  }
}

fn merge(left: Segment, right: Segment) -> Result(Segment, Error) {
  use Nil <- result.try(validate_overlap(left, right))
  case left.offset <= right.offset {
    True -> merge_ordered(left, right)
    False -> merge_ordered(right, left)
  }
}

fn merge_ordered(first: Segment, second: Segment) -> Result(Segment, Error) {
  let first_end = segment_end(first)
  let second_end = segment_end(second)
  case first_end >= second_end {
    True -> Ok(first)
    False -> {
      use suffix <- result.try(slice_from(
        second.data,
        first_end - second.offset,
      ))
      Ok(Segment(first.offset, <<first.data:bits, suffix:bits>>))
    }
  }
}

fn validate_overlap(left: Segment, right: Segment) -> Result(Nil, Error) {
  let overlap_start = maximum(left.offset, right.offset)
  let overlap_end = minimum(segment_end(left), segment_end(right))
  let overlap_length = overlap_end - overlap_start
  case overlap_length <= 0 {
    True -> Ok(Nil)
    False -> {
      use left_overlap <- result.try(slice(
        left.data,
        overlap_start - left.offset,
        overlap_length,
      ))
      use right_overlap <- result.try(slice(
        right.data,
        overlap_start - right.offset,
        overlap_length,
      ))
      case left_overlap == right_overlap {
        True -> Ok(Nil)
        False -> Error(ConflictingOverlap)
      }
    }
  }
}

fn read_bounded(state: Reassembler, maximum_bytes: Int) -> Result(Read, Error) {
  case state.segments {
    [Segment(offset, data), ..rest] if offset == state.read_offset -> {
      let count = minimum(maximum_bytes, bit_array.byte_size(data))
      use prefix <- result.try(slice(data, 0, count))
      use suffix <- result.try(slice_from(data, count))
      let next_offset = state.read_offset + count
      let next_segments = case suffix {
        <<>> -> rest
        _ -> [Segment(next_offset, suffix), ..rest]
      }
      let next =
        Reassembler(
          ..state,
          read_offset: next_offset,
          segments: next_segments,
          buffered_bytes: state.buffered_bytes - count,
        )
      Ok(Read(next, prefix, is_finished(next)))
    }
    _ -> Ok(Read(state, <<>>, is_finished(state)))
  }
}

fn is_finished(state: Reassembler) -> Bool {
  case state.final_size {
    Some(final_size) -> state.read_offset == final_size
    None -> False
  }
}

fn highest_received(state: Reassembler) -> Int {
  list.fold(state.segments, state.read_offset, fn(highest, segment) {
    maximum(highest, segment_end(segment))
  })
}

fn total_bytes(segments: List(Segment), accumulator: Int) -> Int {
  case segments {
    [] -> accumulator
    [Segment(_, data), ..rest] ->
      total_bytes(rest, accumulator + bit_array.byte_size(data))
  }
}

fn segment_end(segment: Segment) -> Int {
  segment.offset + bit_array.byte_size(segment.data)
}

fn slice_from(bytes: BitArray, offset: Int) -> Result(BitArray, Error) {
  slice(bytes, offset, bit_array.byte_size(bytes) - offset)
}

fn slice(bytes: BitArray, offset: Int, length: Int) -> Result(BitArray, Error) {
  case
    offset < 0 || length < 0 || offset + length > bit_array.byte_size(bytes)
  {
    True -> Error(InvalidInput)
    False -> {
      let offset_bits = offset * 8
      let length_bits = length * 8
      case bytes {
        <<_:bits-size(offset_bits), value:bits-size(length_bits), _:bits>> ->
          Ok(value)
        _ -> Error(InvalidInput)
      }
    }
  }
}

fn minimum(left: Int, right: Int) -> Int {
  case left < right {
    True -> left
    False -> right
  }
}

fn maximum(left: Int, right: Int) -> Int {
  case left > right {
    True -> left
    False -> right
  }
}
