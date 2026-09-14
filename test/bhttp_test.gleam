import gleam/bit_array
import gleeunit
import http/bhttp

pub fn main() -> Nil {
  gleeunit.main()
}

fn request() -> bhttp.Message {
  bhttp.Request(
    method: "POST",
    scheme: "https",
    authority: "example.com",
    path: "/submit",
    headers: [bhttp.Field("content-type", <<"text/plain":utf8>>)],
    content: [<<"one":utf8>>, <<"two":utf8>>],
    trailers: [bhttp.Field("digest", <<"sha-256=:AQI=:":utf8>>)],
    padding: 5,
  )
}

pub fn rfc9292_known_length_request_vector_test() -> Nil {
  let wire = <<
    0,
    3,
    "GET":utf8,
    5,
    "https":utf8,
    0,
    10,
    "/hello.txt":utf8,
    0x40,
    0x6c,
    10,
    "user-agent":utf8,
    52,
    "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3":utf8,
    4,
    "host":utf8,
    15,
    "www.example.com":utf8,
    15,
    "accept-language":utf8,
    6,
    "en, mi":utf8,
    0,
    0,
  >>
  let expected =
    bhttp.Request(
      method: "GET",
      scheme: "https",
      authority: "",
      path: "/hello.txt",
      headers: [
        bhttp.Field("user-agent", <<
          "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3":utf8,
        >>),
        bhttp.Field("host", <<"www.example.com":utf8>>),
        bhttp.Field("accept-language", <<"en, mi":utf8>>),
      ],
      content: [],
      trailers: [],
      padding: 0,
    )
  assert bhttp.decode(wire, bhttp.defaults()) == Ok(expected)
  assert bhttp.encode(expected, bhttp.KnownLength, bhttp.defaults()) == Ok(wire)

  let truncated =
    bit_array.slice(wire, at: 0, take: bit_array.byte_size(wire) - 2)
    |> result_or_empty
  assert bhttp.decode(truncated, bhttp.defaults()) == Ok(expected)
}

pub fn indeterminate_request_preserves_chunks_trailers_and_padding_test() -> Nil {
  let assert Ok(wire) =
    bhttp.encode(request(), bhttp.IndeterminateLength, bhttp.defaults())
  assert bhttp.decode(wire, bhttp.defaults()) == Ok(request())

  let assert [first, second, third] = [
    bit_array.slice(wire, at: 0, take: 3) |> result_or_empty,
    bit_array.slice(wire, at: 3, take: 7) |> result_or_empty,
    bit_array.slice(wire, at: 10, take: bit_array.byte_size(wire) - 10)
      |> result_or_empty,
  ]
  let assert Ok(decoder) = bhttp.decoder(bhttp.defaults())
  let assert Ok(bhttp.Awaiting(decoder)) = bhttp.push(decoder, first, False)
  let assert Ok(bhttp.Awaiting(decoder)) = bhttp.push(decoder, second, False)
  assert bhttp.push(decoder, third, True) == Ok(bhttp.Decoded(request()))
}

pub fn response_informational_sections_round_trip_in_both_modes_test() -> Nil {
  let response =
    bhttp.Response(
      informational: [
        bhttp.Informational(103, [
          bhttp.Field("link", <<"</style.css>; rel=preload":utf8>>),
        ]),
      ],
      status: 200,
      headers: [bhttp.Field("content-type", <<"text/plain":utf8>>)],
      content: [<<"hello":utf8>>],
      trailers: [],
      padding: 2,
    )
  let assert Ok(known) =
    bhttp.encode(response, bhttp.KnownLength, bhttp.defaults())
  let assert Ok(indeterminate) =
    bhttp.encode(response, bhttp.IndeterminateLength, bhttp.defaults())
  assert bhttp.decode(known, bhttp.defaults()) == Ok(response)
  assert bhttp.decode(indeterminate, bhttp.defaults()) == Ok(response)
}

pub fn all_empty_trailing_sections_may_be_omitted_test() -> Nil {
  assert bhttp.decode(
      <<0, 3, "GET":utf8, 5, "https":utf8, 11, "example.com":utf8, 1, "/":utf8>>,
      bhttp.defaults(),
    )
    == Ok(bhttp.Request("GET", "https", "example.com", "/", [], [], [], 0))
  assert bhttp.decode(<<1, 0x40, 0xc8>>, bhttp.defaults())
    == Ok(bhttp.Response([], 200, [], [], [], 0))
}

pub fn malformed_and_oversized_messages_fail_closed_test() -> Nil {
  assert bhttp.decode(<<4>>, bhttp.defaults()) == Error(bhttp.InvalidFraming)
  let assert Ok(wire) =
    bhttp.encode(request(), bhttp.KnownLength, bhttp.defaults())
  assert bhttp.decode(<<wire:bits, 1>>, bhttp.defaults())
    == Error(bhttp.InvalidPadding)

  let limits =
    bhttp.Limits(
      maximum_bytes: 1024,
      maximum_fields: 8,
      maximum_field_section_bytes: 128,
      maximum_content_bytes: 5,
      maximum_chunks: 4,
      maximum_padding_bytes: 4,
    )
  assert bhttp.encode(request(), bhttp.IndeterminateLength, limits)
    == Error(bhttp.LimitExceeded)
  assert bhttp.decode(<<0, 0>>, bhttp.defaults()) == Error(bhttp.Truncated)
}

pub fn rfc9292_rejects_http2_malformed_field_values_test() -> Nil {
  let leading_space = known_request_with_field("x-test", <<" invalid":utf8>>)
  let trailing_space = known_request_with_field("x-test", <<"invalid ":utf8>>)
  let leading_tab = known_request_with_field("x-test", <<9, "invalid":utf8>>)
  let trailing_tab = known_request_with_field("x-test", <<"invalid":utf8, 9>>)

  assert bhttp.decode(leading_space, bhttp.defaults())
    == Error(bhttp.InvalidField)
  assert bhttp.decode(trailing_space, bhttp.defaults())
    == Error(bhttp.InvalidField)
  assert bhttp.decode(leading_tab, bhttp.defaults())
    == Error(bhttp.InvalidField)
  assert bhttp.decode(trailing_tab, bhttp.defaults())
    == Error(bhttp.InvalidField)
  assert bhttp.encode(
      request_with_field("x-test", <<" invalid":utf8>>),
      bhttp.KnownLength,
      bhttp.defaults(),
    )
    == Error(bhttp.InvalidField)
  assert bhttp.encode(
      request_with_field("x-test", <<"invalid":utf8, 9>>),
      bhttp.IndeterminateLength,
      bhttp.defaults(),
    )
    == Error(bhttp.InvalidField)

  let valid =
    known_request_with_field("x-test", <<"one two":utf8, 9, "three":utf8>>)
  assert bhttp.decode(valid, bhttp.defaults())
    == Ok(request_with_field("x-test", <<"one two":utf8, 9, "three":utf8>>))
}

pub fn rfc9292_erratum_8559_rejects_malformed_field_names_test() -> Nil {
  assert bhttp.decode(
      known_request_with_field("X-Test", <<"value":utf8>>),
      bhttp.defaults(),
    )
    == Error(bhttp.InvalidField)
  assert bhttp.decode(
      known_request_with_field("bad name", <<"value":utf8>>),
      bhttp.defaults(),
    )
    == Error(bhttp.InvalidField)
  assert bhttp.decode(
      known_request_with_field(":method", <<"GET":utf8>>),
      bhttp.defaults(),
    )
    == Error(bhttp.InvalidField)
  assert bhttp.encode(
      request_with_field("X-Test", <<"value":utf8>>),
      bhttp.KnownLength,
      bhttp.defaults(),
    )
    == Error(bhttp.InvalidField)
}

pub fn invalid_message_ends_incremental_decode_without_progress_test() -> Nil {
  let invalid = known_request_with_field("x-test", <<" invalid":utf8>>)
  let split_at = bit_array.byte_size(invalid) - 2
  let first = bit_array.slice(invalid, at: 0, take: split_at) |> result_or_empty
  let last = bit_array.slice(invalid, at: split_at, take: 2) |> result_or_empty
  let assert Ok(decoder) = bhttp.decoder(bhttp.defaults())
  let assert Ok(bhttp.Awaiting(decoder)) = bhttp.push(decoder, first, False)
  assert bhttp.push(decoder, last, True) == Error(bhttp.InvalidField)
}

pub fn connection_fields_are_preserved_for_message_capture_test() -> Nil {
  let message = request_with_field("connection", <<"close":utf8>>)
  let assert Ok(wire) =
    bhttp.encode(message, bhttp.KnownLength, bhttp.defaults())
  assert bhttp.decode(wire, bhttp.defaults()) == Ok(message)
}

fn request_with_field(name: String, value: BitArray) -> bhttp.Message {
  bhttp.Request(
    method: "GET",
    scheme: "https",
    authority: "example.com",
    path: "/",
    headers: [bhttp.Field(name, value)],
    content: [],
    trailers: [],
    padding: 0,
  )
}

fn known_request_with_field(name: String, value: BitArray) -> BitArray {
  let name = bit_array.from_string(name)
  let name_length = bit_array.byte_size(name)
  let value_length = bit_array.byte_size(value)
  let section_length = name_length + value_length + 2
  <<
    0,
    3,
    "GET":utf8,
    5,
    "https":utf8,
    11,
    "example.com":utf8,
    1,
    "/":utf8,
    section_length,
    name_length,
    name:bits,
    value_length,
    value:bits,
    0,
    0,
  >>
}

fn result_or_empty(value: Result(BitArray, Nil)) -> BitArray {
  let assert Ok(value) = value
  value
}
