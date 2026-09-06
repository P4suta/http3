import gleeunit
import http/internal/http2/data
import http/internal/http2/frame

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn application_bytes_and_flow_controlled_length_are_distinct_test() -> Nil {
  assert data.decode(frame.Header(3, frame.Data, 1, 1), <<"abc":utf8>>)
    == Ok(data.Data(
      bytes: <<"abc":utf8>>,
      end_stream: True,
      flow_controlled_bytes: 3,
    ))

  assert data.decode(frame.Header(6, frame.Data, 8, 1), <<2, "abc":utf8, 0, 0>>)
    == Ok(data.Data(
      bytes: <<"abc":utf8>>,
      end_stream: False,
      flow_controlled_bytes: 6,
    ))
}

pub fn empty_data_with_all_remaining_bytes_as_padding_is_valid_test() -> Nil {
  assert data.decode(frame.Header(3, frame.Data, 8, 1), <<2, 0, 0>>)
    == Ok(data.Data(<<>>, False, 3))
}

pub fn malformed_data_payloads_are_rejected_test() -> Nil {
  assert data.decode(frame.Header(2, frame.Data, 8, 1), <<2, 0>>)
    == Error(data.InvalidPadding)
  assert data.decode(frame.Header(0, frame.Headers, 4, 1), <<>>)
    == Error(data.UnexpectedFrameType)
  assert data.decode(frame.Header(2, frame.Data, 0, 1), <<"a":utf8>>)
    == Error(data.InvalidPayloadLength)
  assert data.decode(frame.Header(0, frame.Data, 0, 1), <<1:size(1)>>)
    == Error(data.NonByteAligned)
}
