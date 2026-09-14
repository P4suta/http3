import gleeunit
import http/internal/http2/data_writer

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn the_smaller_flow_window_bounds_partial_frame_output_test() -> Nil {
  let assert Ok(data_writer.Written(
    frames,
    consumed: 7,
    remaining: <<"hijkl":utf8>>,
    end_stream_sent: False,
  )) =
    data_writer.encode(
      <<"abcdefghijkl":utf8>>,
      stream_id: 1,
      end_stream: True,
      maximum_frame_bytes: 5,
      connection_credit: 12,
      stream_credit: 7,
    )
  assert frames
    == [
      <<0, 0, 5, 0, 0, 0, 0, 0, 1, "abcde":utf8>>,
      <<0, 0, 2, 0, 0, 0, 0, 0, 1, "fg":utf8>>,
    ]
}

pub fn the_final_fragment_alone_carries_end_stream_test() -> Nil {
  let assert Ok(data_writer.Written(
    frames,
    consumed: 12,
    remaining: <<>>,
    end_stream_sent: True,
  )) =
    data_writer.encode(
      <<"abcdefghijkl":utf8>>,
      stream_id: 3,
      end_stream: True,
      maximum_frame_bytes: 5,
      connection_credit: 20,
      stream_credit: 20,
    )
  assert frames
    == [
      <<0, 0, 5, 0, 0, 0, 0, 0, 3, "abcde":utf8>>,
      <<0, 0, 5, 0, 0, 0, 0, 0, 3, "fghij":utf8>>,
      <<0, 0, 2, 0, 1, 0, 0, 0, 3, "kl":utf8>>,
    ]
}

pub fn zero_credit_blocks_non_empty_data_without_consumption_test() -> Nil {
  assert data_writer.encode(
      <<"x":utf8>>,
      stream_id: 1,
      end_stream: False,
      maximum_frame_bytes: 16_384,
      connection_credit: 0,
      stream_credit: 100,
    )
    == Ok(data_writer.Blocked)
}

pub fn an_empty_end_stream_still_emits_a_zero_length_data_frame_test() -> Nil {
  assert data_writer.encode(
      <<>>,
      stream_id: 1,
      end_stream: True,
      maximum_frame_bytes: 16_384,
      connection_credit: 0,
      stream_credit: 0,
    )
    == Ok(data_writer.Written(
      frames: [<<0, 0, 0, 0, 1, 0, 0, 0, 1>>],
      consumed: 0,
      remaining: <<>>,
      end_stream_sent: True,
    ))
}

pub fn invalid_stream_limit_alignment_and_credit_are_rejected_test() -> Nil {
  assert data_writer.encode(
      <<1:size(1)>>,
      stream_id: 1,
      end_stream: False,
      maximum_frame_bytes: 1,
      connection_credit: 1,
      stream_credit: 1,
    )
    == Error(data_writer.NonByteAligned)
  assert data_writer.encode(
      <<>>,
      stream_id: 0,
      end_stream: False,
      maximum_frame_bytes: 1,
      connection_credit: 1,
      stream_credit: 1,
    )
    == Error(data_writer.InvalidStreamIdentifier)
  assert data_writer.encode(
      <<>>,
      stream_id: 1,
      end_stream: False,
      maximum_frame_bytes: 0,
      connection_credit: 1,
      stream_credit: 1,
    )
    == Error(data_writer.InvalidFrameLimit)
  assert data_writer.encode(
      <<>>,
      stream_id: 1,
      end_stream: False,
      maximum_frame_bytes: 1,
      connection_credit: -1,
      stream_credit: 1,
    )
    == Error(data_writer.InvalidCredit)
}
