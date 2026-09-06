import gleam/option.{None, Some}
import gleeunit
import http/internal/http2/frame
import http/internal/http2/header_block
import http/internal/http2/header_codec
import http/internal/http2/header_semantics

pub fn main() -> Nil {
  gleeunit.main()
}

fn limits(maximum_tracked_streams: Int) -> header_codec.Limits {
  header_codec.Limits(
    maximum_block_bytes: 1024,
    maximum_header_list_bytes: 4096,
    maximum_table_capacity: 4096,
    maximum_tracked_streams: maximum_tracked_streams,
  )
}

fn request_block() -> BitArray {
  <<0x82, 0x87, 0x84, 0x01, 11, "example.com":utf8>>
}

pub fn server_decodes_and_validates_a_complete_request_section_test() -> Nil {
  let assert Ok(codec) =
    header_codec.new(
      header_codec.Server,
      limits(4),
      extended_connect_enabled: False,
    )
  let block = request_block()
  let assert Ok(header_codec.Complete(codec, section)) =
    header_codec.accept(codec, frame.Header(16, frame.Headers, 0x5, 1), block)
  let assert header_codec.HeaderSection(
    stream_id: 1,
    end_stream: True,
    validated: header_semantics.Validated(
      header_semantics.RequestControlData(control),
      [],
      None,
    ),
    priority: None,
  ) = section
  assert control.method == <<"GET">>
  assert control.scheme == Some(<<"https">>)
  assert control.authority == Some(<<"example.com">>)
  assert control.path == Some(<<"/">>)
  assert header_codec.tracked_streams(codec) == 1
}

pub fn continuation_sequences_reject_interleaving_before_hpack_test() -> Nil {
  let assert Ok(codec) =
    header_codec.new(
      header_codec.Server,
      limits(4),
      extended_connect_enabled: False,
    )
  let block = request_block()
  let assert <<first:bytes-size(4), rest:bytes>> = block
  let assert Ok(header_codec.Waiting(codec)) =
    header_codec.accept(codec, frame.Header(4, frame.Headers, 0, 1), first)
  assert header_codec.accept(codec, frame.Header(8, frame.Ping, 0, 0), <<
      "12345678":utf8,
    >>)
    == Error(
      header_codec.BlockFailure(header_block.ExpectedContinuation(stream_id: 1)),
    )
  let assert Ok(header_codec.Complete(_, _)) =
    header_codec.accept(
      codec,
      frame.Header(12, frame.Continuation, 0x4, 1),
      rest,
    )
  Nil
}

pub fn client_accepts_informational_final_and_terminating_trailers_test() -> Nil {
  let assert Ok(codec) =
    header_codec.new(
      header_codec.Client,
      limits(2),
      extended_connect_enabled: False,
    )
  let informational = <<0x08, 3, "103":utf8>>
  let assert Ok(header_codec.Complete(codec, section)) =
    header_codec.accept(
      codec,
      frame.Header(5, frame.Headers, 0x4, 1),
      informational,
    )
  let assert header_codec.HeaderSection(
    _,
    _,
    header_semantics.Validated(
      header_semantics.ResponseControlData(103),
      [],
      None,
    ),
    _,
  ) = section

  let assert Ok(header_codec.Complete(codec, section)) =
    header_codec.accept(codec, frame.Header(1, frame.Headers, 0x4, 1), <<0x88>>)
  let assert header_codec.HeaderSection(
    _,
    _,
    header_semantics.Validated(
      header_semantics.ResponseControlData(200),
      [],
      None,
    ),
    _,
  ) = section

  let trailers = <<0x00, 8, "checksum":utf8, 2, "ok":utf8>>
  let assert Ok(header_codec.Complete(codec, section)) =
    header_codec.accept(
      codec,
      frame.Header(13, frame.Headers, 0x5, 1),
      trailers,
    )
  let assert header_codec.HeaderSection(
    _,
    True,
    header_semantics.Validated(header_semantics.TrailerControlData, [_], None),
    _,
  ) = section
  assert header_codec.tracked_streams(codec) == 1
}

pub fn trailers_must_end_the_stream_and_phase_tracking_is_bounded_test() -> Nil {
  let assert Ok(codec) =
    header_codec.new(
      header_codec.Server,
      limits(1),
      extended_connect_enabled: False,
    )
  let block = request_block()
  let assert Ok(header_codec.Complete(codec, _)) =
    header_codec.accept(codec, frame.Header(16, frame.Headers, 0x4, 1), block)
  let trailers = <<0x00, 8, "checksum":utf8, 2, "ok":utf8>>
  assert header_codec.accept(
      codec,
      frame.Header(13, frame.Headers, 0x4, 1),
      trailers,
    )
    == Error(header_codec.TrailersWithoutEndStream(stream_id: 1))
  assert header_codec.accept(
      codec,
      frame.Header(16, frame.Headers, 0x4, 3),
      block,
    )
    == Error(header_codec.TooManyTrackedStreams(maximum: 1))
}

pub fn invalid_header_codec_limits_are_rejected_test() -> Nil {
  assert header_codec.new(
      header_codec.Server,
      limits(0),
      extended_connect_enabled: False,
    )
    == Error(header_codec.InvalidLimits)
}
