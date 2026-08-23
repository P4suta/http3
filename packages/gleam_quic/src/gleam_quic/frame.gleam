//// Bounded QUIC v1/v2 transport frame codec.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/varint

/// The stream type selected by MAX_STREAMS or STREAMS_BLOCKED.
pub type StreamDirection {
  Bidirectional
  Unidirectional
}

/// One inclusive acknowledged packet-number range.
pub type AckRange {
  AckRange(Int, Int)
}

/// ECN counters carried by an ACK_ECN frame.
pub type EcnCounts {
  EcnCounts(Int, Int, Int)
}

/// A decoded ACK or ACK_ECN frame body.
pub type Acknowledgement {
  Acknowledgement(delay: Int, ranges: List(AckRange), ecn: Option(EcnCounts))
}

/// A QUIC transport frame defined by RFC 9000 or RFC 9221.
pub type Frame {
  Padding(Int)
  Ping
  Ack(Acknowledgement)
  ResetStream(Int, Int, Int)
  StopSending(Int, Int)
  Crypto(Int, BitArray)
  NewToken(BitArray)
  Stream(Int, Int, BitArray, Bool)
  MaxData(Int)
  MaxStreamData(Int, Int)
  MaxStreams(StreamDirection, Int)
  DataBlocked(Int)
  StreamDataBlocked(Int, Int)
  StreamsBlocked(StreamDirection, Int)
  NewConnectionId(Int, Int, BitArray, BitArray)
  RetireConnectionId(Int)
  PathChallenge(BitArray)
  PathResponse(BitArray)
  ConnectionCloseTransport(Int, Int, String)
  ConnectionCloseApplication(Int, String)
  HandshakeDone
  Datagram(BitArray)
}

/// Peer-controlled allocation and iteration limits for frame decoding.
pub type Limits {
  Limits(
    max_frames: Int,
    max_ack_ranges: Int,
    max_data_length: Int,
    max_token_length: Int,
    max_reason_length: Int,
  )
}

/// A frame codec failure.
pub type Error {
  NonByteAligned
  Truncated
  InvalidUtf8
  InvalidFrame
  InvalidLimits
  UnknownFrameType(Int)
  FrameLimitExceeded(Int)
  AckRangeLimitExceeded(Int)
  DataLimitExceeded(Int)
  TokenLimitExceeded(Int)
  ReasonLimitExceeded(Int)
}

/// Conservative defaults suitable for a single decrypted UDP packet.
pub fn default_limits() -> Limits {
  Limits(
    max_frames: 4096,
    max_ack_ranges: 256,
    max_data_length: 65_527,
    max_token_length: 4096,
    max_reason_length: 1024,
  )
}

/// Decode every frame from one decrypted QUIC packet payload.
pub fn decode_all(
  payload payload: BitArray,
  limits limits: Limits,
) -> Result(List(Frame), Error) {
  case bit_array.bit_size(payload) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case valid_limits(limits) {
        False -> Error(InvalidLimits)
        True -> decode_frames(payload, limits, 0, [])
      }
  }
}

/// Encode a sequence of transport frames.
pub fn encode_all(frames: List(Frame)) -> Result(BitArray, Error) {
  encode_frames(frames, <<>>)
}

/// Encode one transport frame using a deterministic valid representation.
pub fn encode(frame: Frame) -> Result(BitArray, Error) {
  case frame_is_byte_aligned(frame) {
    False -> Error(NonByteAligned)
    True -> encode_aligned(frame)
  }
}

fn encode_aligned(frame: Frame) -> Result(BitArray, Error) {
  case frame {
    Padding(count) -> encode_padding(count, <<>>)
    Ping -> Ok(<<0x01>>)
    Ack(acknowledgement) -> encode_ack(acknowledgement)
    ResetStream(stream_id, application_error_code, final_size) -> {
      use stream_id <- result.try(encode_integer(stream_id))
      use application_error_code <- result.try(encode_integer(
        application_error_code,
      ))
      use final_size <- result.try(encode_integer(final_size))
      Ok(<<0x04, stream_id:bits, application_error_code:bits, final_size:bits>>)
    }
    StopSending(stream_id, application_error_code) -> {
      use stream_id <- result.try(encode_integer(stream_id))
      use application_error_code <- result.try(encode_integer(
        application_error_code,
      ))
      Ok(<<0x05, stream_id:bits, application_error_code:bits>>)
    }
    Crypto(offset, data) -> encode_offset_data(0x06, offset, data)
    NewToken(token) ->
      case bit_array.byte_size(token) {
        0 -> Error(InvalidFrame)
        length -> {
          use length <- result.try(encode_integer(length))
          Ok(<<0x07, length:bits, token:bits>>)
        }
      }
    Stream(stream_id, offset, data, fin) ->
      encode_stream(stream_id, offset, data, fin)
    MaxData(maximum) -> encode_single_integer(0x10, maximum)
    MaxStreamData(stream_id, maximum) ->
      encode_two_integers(0x11, stream_id, maximum)
    MaxStreams(direction, maximum) ->
      encode_single_integer(direction_type(direction, 0x12, 0x13), maximum)
    DataBlocked(limit) -> encode_single_integer(0x14, limit)
    StreamDataBlocked(stream_id, limit) ->
      encode_two_integers(0x15, stream_id, limit)
    StreamsBlocked(direction, limit) ->
      encode_single_integer(direction_type(direction, 0x16, 0x17), limit)
    NewConnectionId(sequence, retire_prior_to, connection_id, reset_token) ->
      encode_new_connection_id(
        sequence,
        retire_prior_to,
        connection_id,
        reset_token,
      )
    RetireConnectionId(sequence) -> encode_single_integer(0x19, sequence)
    PathChallenge(data) -> encode_path_data(0x1a, data)
    PathResponse(data) -> encode_path_data(0x1b, data)
    ConnectionCloseTransport(error_code, frame_type, reason) ->
      encode_close(0x1c, error_code, Some(frame_type), reason)
    ConnectionCloseApplication(error_code, reason) ->
      encode_close(0x1d, error_code, None, reason)
    HandshakeDone -> Ok(<<0x1e>>)
    Datagram(data) -> {
      use length <- result.try(encode_integer(bit_array.byte_size(data)))
      Ok(<<0x31, length:bits, data:bits>>)
    }
  }
}

fn frame_is_byte_aligned(frame: Frame) -> Bool {
  case frame {
    Crypto(_, data)
    | NewToken(data)
    | Stream(_, _, data, _)
    | PathChallenge(data)
    | PathResponse(data)
    | Datagram(data) -> bit_array.bit_size(data) % 8 == 0
    NewConnectionId(_, _, connection_id, reset_token) ->
      bit_array.bit_size(connection_id) % 8 == 0
      && bit_array.bit_size(reset_token) % 8 == 0
    _ -> True
  }
}

fn valid_limits(limits: Limits) -> Bool {
  limits.max_frames > 0
  && limits.max_ack_ranges >= 0
  && limits.max_data_length >= 0
  && limits.max_token_length >= 0
  && limits.max_reason_length >= 0
}

fn decode_frames(
  bytes: BitArray,
  limits: Limits,
  consumed_frames: Int,
  reversed: List(Frame),
) -> Result(List(Frame), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    _ -> {
      use #(frame_type, after_type) <- result.try(read_integer(bytes))
      use #(decoded, rest, frame_cost) <- result.try(decode_one(
        frame_type,
        after_type,
        limits,
      ))
      let next_count = consumed_frames + frame_cost
      case next_count > limits.max_frames {
        True -> Error(FrameLimitExceeded(limits.max_frames))
        False -> decode_frames(rest, limits, next_count, [decoded, ..reversed])
      }
    }
  }
}

fn decode_one(
  frame_type: Int,
  bytes: BitArray,
  limits: Limits,
) -> Result(#(Frame, BitArray, Int), Error) {
  case frame_type {
    0 -> {
      let #(padding_count, rest) = count_padding(bytes, 1)
      Ok(#(Padding(padding_count), rest, padding_count))
    }
    1 -> Ok(#(Ping, bytes, 1))
    2 -> decode_ack(bytes, limits, False)
    3 -> decode_ack(bytes, limits, True)
    4 -> decode_reset_stream(bytes)
    5 -> decode_stop_sending(bytes)
    6 -> decode_crypto(bytes, limits)
    7 -> decode_new_token(bytes, limits)
    frame_type if frame_type >= 8 && frame_type <= 15 ->
      decode_stream(frame_type, bytes, limits)
    0x10 -> decode_one_integer(bytes, MaxData)
    0x11 -> decode_two_integers(bytes, MaxStreamData)
    0x12 -> decode_max_streams(bytes, Bidirectional)
    0x13 -> decode_max_streams(bytes, Unidirectional)
    0x14 -> decode_one_integer(bytes, DataBlocked)
    0x15 -> decode_two_integers(bytes, StreamDataBlocked)
    0x16 -> decode_streams_blocked(bytes, Bidirectional)
    0x17 -> decode_streams_blocked(bytes, Unidirectional)
    0x18 -> decode_new_connection_id(bytes)
    0x19 -> decode_one_integer(bytes, RetireConnectionId)
    0x1a -> decode_path_data(bytes, PathChallenge)
    0x1b -> decode_path_data(bytes, PathResponse)
    0x1c -> decode_transport_close(bytes, limits)
    0x1d -> decode_application_close(bytes, limits)
    0x1e -> Ok(#(HandshakeDone, bytes, 1))
    0x30 -> decode_datagram_without_length(bytes, limits)
    0x31 -> decode_datagram_with_length(bytes, limits)
    unknown -> Error(UnknownFrameType(unknown))
  }
}

fn count_padding(bytes: BitArray, count: Int) -> #(Int, BitArray) {
  case bytes {
    <<0, rest:bits>> -> count_padding(rest, count + 1)
    _ -> #(count, bytes)
  }
}

fn decode_reset_stream(
  bytes: BitArray,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(stream_id, rest) <- result.try(read_integer(bytes))
  use #(error_code, rest) <- result.try(read_integer(rest))
  use #(final_size, rest) <- result.try(read_integer(rest))
  Ok(#(ResetStream(stream_id, error_code, final_size), rest, 1))
}

fn decode_stop_sending(
  bytes: BitArray,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(stream_id, rest) <- result.try(read_integer(bytes))
  use #(error_code, rest) <- result.try(read_integer(rest))
  Ok(#(StopSending(stream_id, error_code), rest, 1))
}

fn decode_crypto(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(offset, rest) <- result.try(read_integer(bytes))
  use #(length, rest) <- result.try(read_integer(rest))
  use #(data, rest) <- result.try(take_data(
    rest,
    length,
    limits.max_data_length,
  ))
  Ok(#(Crypto(offset, data), rest, 1))
}

fn decode_new_token(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(length, rest) <- result.try(read_integer(bytes))
  case length {
    0 -> Error(InvalidFrame)
    length if length > limits.max_token_length ->
      Error(TokenLimitExceeded(limits.max_token_length))
    _ -> {
      use #(token, rest) <- result.try(take(rest, length))
      Ok(#(NewToken(token), rest, 1))
    }
  }
}

fn decode_stream(
  frame_type: Int,
  bytes: BitArray,
  limits: Limits,
) -> Result(#(Frame, BitArray, Int), Error) {
  let has_offset = int.bitwise_and(frame_type, 0x04) != 0
  let has_length = int.bitwise_and(frame_type, 0x02) != 0
  let fin = int.bitwise_and(frame_type, 0x01) != 0
  use #(stream_id, rest) <- result.try(read_integer(bytes))
  use #(offset, rest) <- result.try(case has_offset {
    True -> read_integer(rest)
    False -> Ok(#(0, rest))
  })
  use #(data, rest) <- result.try(case has_length {
    True -> {
      use #(length, data) <- result.try(read_integer(rest))
      take_data(data, length, limits.max_data_length)
    }
    False ->
      case bit_array.byte_size(rest) > limits.max_data_length {
        True -> Error(DataLimitExceeded(limits.max_data_length))
        False -> Ok(#(rest, <<>>))
      }
  })
  Ok(#(Stream(stream_id, offset, data, fin), rest, 1))
}

fn decode_one_integer(
  bytes: BitArray,
  constructor: fn(Int) -> Frame,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(value, rest) <- result.try(read_integer(bytes))
  Ok(#(constructor(value), rest, 1))
}

fn decode_two_integers(
  bytes: BitArray,
  constructor: fn(Int, Int) -> Frame,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(first, rest) <- result.try(read_integer(bytes))
  use #(second, rest) <- result.try(read_integer(rest))
  Ok(#(constructor(first, second), rest, 1))
}

fn decode_max_streams(
  bytes: BitArray,
  direction: StreamDirection,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(maximum, rest) <- result.try(read_integer(bytes))
  case maximum > 1_152_921_504_606_846_975 {
    True -> Error(InvalidFrame)
    False -> Ok(#(MaxStreams(direction, maximum), rest, 1))
  }
}

fn decode_streams_blocked(
  bytes: BitArray,
  direction: StreamDirection,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(limit, rest) <- result.try(read_integer(bytes))
  case limit > 1_152_921_504_606_846_975 {
    True -> Error(InvalidFrame)
    False -> Ok(#(StreamsBlocked(direction, limit), rest, 1))
  }
}

fn decode_new_connection_id(
  bytes: BitArray,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(sequence, rest) <- result.try(read_integer(bytes))
  use #(retire_prior_to, rest) <- result.try(read_integer(rest))
  case rest {
    <<connection_id_length, connection_id_and_token:bits>> ->
      case
        connection_id_length < 1
        || connection_id_length > 20
        || retire_prior_to > sequence
      {
        True -> Error(InvalidFrame)
        False -> {
          use #(connection_id, token) <- result.try(take(
            connection_id_and_token,
            connection_id_length,
          ))
          use #(reset_token, rest) <- result.try(take(token, 16))
          Ok(#(
            NewConnectionId(
              sequence,
              retire_prior_to,
              connection_id,
              reset_token,
            ),
            rest,
            1,
          ))
        }
      }
    _ -> Error(Truncated)
  }
}

fn decode_path_data(
  bytes: BitArray,
  constructor: fn(BitArray) -> Frame,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(data, rest) <- result.try(take(bytes, 8))
  Ok(#(constructor(data), rest, 1))
}

fn decode_transport_close(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(error_code, rest) <- result.try(read_integer(bytes))
  use #(frame_type, rest) <- result.try(read_integer(rest))
  use #(reason, rest) <- result.try(decode_reason(rest, limits))
  Ok(#(ConnectionCloseTransport(error_code, frame_type, reason), rest, 1))
}

fn decode_application_close(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(error_code, rest) <- result.try(read_integer(bytes))
  use #(reason, rest) <- result.try(decode_reason(rest, limits))
  Ok(#(ConnectionCloseApplication(error_code, reason), rest, 1))
}

fn decode_reason(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(String, BitArray), Error) {
  use #(length, rest) <- result.try(read_integer(bytes))
  case length > limits.max_reason_length {
    True -> Error(ReasonLimitExceeded(limits.max_reason_length))
    False -> {
      use #(reason_bytes, rest) <- result.try(take(rest, length))
      case bit_array.to_string(reason_bytes) {
        Ok(reason) -> Ok(#(reason, rest))
        Error(_) -> Error(InvalidUtf8)
      }
    }
  }
}

fn decode_datagram_without_length(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(Frame, BitArray, Int), Error) {
  case bit_array.byte_size(bytes) > limits.max_data_length {
    True -> Error(DataLimitExceeded(limits.max_data_length))
    False -> Ok(#(Datagram(bytes), <<>>, 1))
  }
}

fn decode_datagram_with_length(
  bytes: BitArray,
  limits: Limits,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(length, rest) <- result.try(read_integer(bytes))
  use #(data, rest) <- result.try(take_data(
    rest,
    length,
    limits.max_data_length,
  ))
  Ok(#(Datagram(data), rest, 1))
}

fn decode_ack(
  bytes: BitArray,
  limits: Limits,
  with_ecn: Bool,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(largest, rest) <- result.try(read_integer(bytes))
  use #(delay, rest) <- result.try(read_integer(rest))
  use #(additional_range_count, rest) <- result.try(read_integer(rest))
  case additional_range_count > limits.max_ack_ranges {
    True -> Error(AckRangeLimitExceeded(limits.max_ack_ranges))
    False ->
      decode_ack_body(largest, delay, additional_range_count, rest, with_ecn)
  }
}

fn decode_ack_body(
  largest: Int,
  delay: Int,
  additional_range_count: Int,
  bytes: BitArray,
  with_ecn: Bool,
) -> Result(#(Frame, BitArray, Int), Error) {
  use #(first_range_length, rest) <- result.try(read_integer(bytes))
  case first_range_length > largest {
    True -> Error(InvalidFrame)
    False -> {
      let first = AckRange(largest - first_range_length, largest)
      use #(ranges, rest) <- result.try(
        decode_ack_ranges(
          rest,
          additional_range_count,
          largest - first_range_length,
          [first],
        ),
      )
      use #(ecn, rest) <- result.try(decode_ecn(rest, with_ecn))
      Ok(#(Ack(Acknowledgement(delay, ranges, ecn)), rest, 1))
    }
  }
}

fn decode_ecn(
  bytes: BitArray,
  with_ecn: Bool,
) -> Result(#(Option(EcnCounts), BitArray), Error) {
  case with_ecn {
    False -> Ok(#(None, bytes))
    True -> {
      use #(ect0, rest) <- result.try(read_integer(bytes))
      use #(ect1, rest) <- result.try(read_integer(rest))
      use #(ce, rest) <- result.try(read_integer(rest))
      Ok(#(Some(EcnCounts(ect0, ect1, ce)), rest))
    }
  }
}

fn decode_ack_ranges(
  bytes: BitArray,
  remaining: Int,
  previous_smallest: Int,
  reversed: List(AckRange),
) -> Result(#(List(AckRange), BitArray), Error) {
  case remaining {
    0 -> Ok(#(list.reverse(reversed), bytes))
    _ -> {
      use #(gap, rest) <- result.try(read_integer(bytes))
      use #(range_length, rest) <- result.try(read_integer(rest))
      let largest = previous_smallest - gap - 2
      let smallest = largest - range_length
      case largest < 0 || smallest < 0 {
        True -> Error(InvalidFrame)
        False ->
          decode_ack_ranges(rest, remaining - 1, smallest, [
            AckRange(smallest, largest),
            ..reversed
          ])
      }
    }
  }
}

fn encode_frames(
  frames: List(Frame),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case frames {
    [] -> Ok(accumulator)
    [frame, ..rest] -> {
      use encoded <- result.try(encode(frame))
      encode_frames(rest, <<accumulator:bits, encoded:bits>>)
    }
  }
}

fn encode_padding(
  count: Int,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case count {
    count if count < 1 -> Error(InvalidFrame)
    1 -> Ok(<<accumulator:bits, 0>>)
    _ -> encode_padding(count - 1, <<accumulator:bits, 0>>)
  }
}

fn encode_integer(value: Int) -> Result(BitArray, Error) {
  case varint.encode(value) {
    Ok(encoded) -> Ok(encoded)
    Error(_) -> Error(InvalidFrame)
  }
}

fn encode_single_integer(
  frame_type: Int,
  value: Int,
) -> Result(BitArray, Error) {
  use value <- result.try(encode_integer(value))
  Ok(<<frame_type, value:bits>>)
}

fn encode_two_integers(
  frame_type: Int,
  first: Int,
  second: Int,
) -> Result(BitArray, Error) {
  use first <- result.try(encode_integer(first))
  use second <- result.try(encode_integer(second))
  Ok(<<frame_type, first:bits, second:bits>>)
}

fn encode_offset_data(
  frame_type: Int,
  offset: Int,
  data: BitArray,
) -> Result(BitArray, Error) {
  use offset <- result.try(encode_integer(offset))
  use length <- result.try(encode_integer(bit_array.byte_size(data)))
  Ok(<<frame_type, offset:bits, length:bits, data:bits>>)
}

fn encode_stream(
  stream_id: Int,
  offset: Int,
  data: BitArray,
  fin: Bool,
) -> Result(BitArray, Error) {
  use stream_id <- result.try(encode_integer(stream_id))
  use offset_bytes <- result.try(encode_integer(offset))
  use length <- result.try(encode_integer(bit_array.byte_size(data)))
  let offset_flag = case offset > 0 {
    True -> 4
    False -> 0
  }
  let fin_flag = case fin {
    True -> 1
    False -> 0
  }
  let frame_type = 0x08 + offset_flag + 2 + fin_flag
  case offset_flag {
    0 -> Ok(<<frame_type, stream_id:bits, length:bits, data:bits>>)
    _ ->
      Ok(<<
        frame_type,
        stream_id:bits,
        offset_bytes:bits,
        length:bits,
        data:bits,
      >>)
  }
}

fn direction_type(
  direction: StreamDirection,
  bidirectional: Int,
  unidirectional: Int,
) -> Int {
  case direction {
    Bidirectional -> bidirectional
    Unidirectional -> unidirectional
  }
}

fn encode_new_connection_id(
  sequence: Int,
  retire_prior_to: Int,
  connection_id: BitArray,
  reset_token: BitArray,
) -> Result(BitArray, Error) {
  let connection_id_length = bit_array.byte_size(connection_id)
  case
    connection_id_length < 1
    || connection_id_length > 20
    || bit_array.byte_size(reset_token) != 16
    || retire_prior_to > sequence
  {
    True -> Error(InvalidFrame)
    False -> {
      use sequence <- result.try(encode_integer(sequence))
      use retire_prior_to <- result.try(encode_integer(retire_prior_to))
      Ok(<<
        0x18,
        sequence:bits,
        retire_prior_to:bits,
        connection_id_length,
        connection_id:bits,
        reset_token:bits,
      >>)
    }
  }
}

fn encode_path_data(
  frame_type: Int,
  data: BitArray,
) -> Result(BitArray, Error) {
  case bit_array.byte_size(data) == 8 && bit_array.bit_size(data) % 8 == 0 {
    True -> Ok(<<frame_type, data:bits>>)
    False -> Error(InvalidFrame)
  }
}

fn encode_close(
  frame_type: Int,
  error_code: Int,
  causing_frame_type: Option(Int),
  reason: String,
) -> Result(BitArray, Error) {
  use error_code <- result.try(encode_integer(error_code))
  use causing_frame <- result.try(case causing_frame_type {
    Some(value) -> encode_integer(value)
    None -> Ok(<<>>)
  })
  let reason = bit_array.from_string(reason)
  use length <- result.try(encode_integer(bit_array.byte_size(reason)))
  Ok(<<
    frame_type,
    error_code:bits,
    causing_frame:bits,
    length:bits,
    reason:bits,
  >>)
}

fn encode_ack(acknowledgement: Acknowledgement) -> Result(BitArray, Error) {
  let Acknowledgement(delay, ranges, ecn) = acknowledgement
  case ranges {
    [] -> Error(InvalidFrame)
    [AckRange(first_smallest, first_largest), ..additional] ->
      case first_smallest < 0 || first_smallest > first_largest {
        True -> Error(InvalidFrame)
        False -> {
          use largest <- result.try(encode_integer(first_largest))
          use delay <- result.try(encode_integer(delay))
          use range_count <- result.try(encode_integer(list.length(additional)))
          use first_length <- result.try(encode_integer(
            first_largest - first_smallest,
          ))
          use encoded_ranges <- result.try(
            encode_ack_ranges(additional, first_smallest, <<>>),
          )
          use encoded_ecn <- result.try(encode_ecn(ecn))
          let frame_type = case ecn {
            Some(_) -> 3
            None -> 2
          }
          Ok(<<
            frame_type,
            largest:bits,
            delay:bits,
            range_count:bits,
            first_length:bits,
            encoded_ranges:bits,
            encoded_ecn:bits,
          >>)
        }
      }
  }
}

fn encode_ack_ranges(
  ranges: List(AckRange),
  previous_smallest: Int,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case ranges {
    [] -> Ok(accumulator)
    [AckRange(smallest, largest), ..rest] -> {
      let gap = previous_smallest - largest - 2
      case smallest < 0 || smallest > largest || gap < 0 {
        True -> Error(InvalidFrame)
        False -> {
          use gap <- result.try(encode_integer(gap))
          use length <- result.try(encode_integer(largest - smallest))
          encode_ack_ranges(rest, smallest, <<
            accumulator:bits,
            gap:bits,
            length:bits,
          >>)
        }
      }
    }
  }
}

fn encode_ecn(ecn: Option(EcnCounts)) -> Result(BitArray, Error) {
  case ecn {
    None -> Ok(<<>>)
    Some(EcnCounts(ect0, ect1, ce)) -> {
      use ect0 <- result.try(encode_integer(ect0))
      use ect1 <- result.try(encode_integer(ect1))
      use ce <- result.try(encode_integer(ce))
      Ok(<<ect0:bits, ect1:bits, ce:bits>>)
    }
  }
}

fn read_integer(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case varint.decode(bytes) {
    Ok(decoded) -> Ok(decoded)
    Error(_) -> Error(Truncated)
  }
}

fn take_data(
  bytes: BitArray,
  length: Int,
  maximum: Int,
) -> Result(#(BitArray, BitArray), Error) {
  case length > maximum {
    True -> Error(DataLimitExceeded(maximum))
    False -> take(bytes, length)
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Error) {
  case length < 0 || length > bit_array.byte_size(bytes) {
    True -> Error(Truncated)
    False -> {
      let bit_length = length * 8
      case bytes {
        <<prefix:bits-size(bit_length), rest:bits>> -> Ok(#(prefix, rest))
        _ -> Error(Truncated)
      }
    }
  }
}
