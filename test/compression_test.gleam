import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import http/compression

@external(erlang, "compression_test_ffi", "rfc1951_full_range_vector")
fn rfc1951_full_range_vector() -> #(BitArray, BitArray)

@external(erlang, "compression_test_ffi", "rfc1952_optional_header_vector")
fn rfc1952_optional_header_vector() -> BitArray

pub fn main() -> Nil {
  gleeunit.main()
}

fn payload() -> BitArray {
  bit_array.from_string(
    "the quick brown fox jumps over the lazy dog; the quick brown fox jumps over the lazy dog",
  )
}

pub fn gzip_deflate_brotli_and_zstandard_round_trip_test() -> Nil {
  let codings = [
    compression.Gzip,
    compression.Deflate,
    compression.Brotli,
    compression.Zstandard,
  ]
  list.each(codings, fn(coding) {
    let assert Ok(encoded) =
      compression.encode(coding, payload(), None, compression.defaults())
    assert encoded != payload()
    assert compression.decode(coding, encoded, None, compression.defaults())
      == Ok(payload())
  })
}

pub fn rfc1950_zlib_vector_and_mandatory_validation_test() -> Nil {
  let hello = <<"hello":utf8>>
  let vector = <<120, 156, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 21>>
  assert compression.encode(
      compression.Deflate,
      hello,
      None,
      compression.defaults(),
    )
    == Ok(vector)
  assert compression.decode(
      compression.Deflate,
      vector,
      None,
      compression.defaults(),
    )
    == Ok(hello)

  // FCHECK, CM, CINFO, and ADLER32 are independently invalid below. The CM
  // and CINFO fixtures retain a valid modulo-31 header check so the test
  // proves those fields are inspected rather than rejected incidentally.
  let bad_fcheck = <<120, 157, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 21>>
  let bad_method = <<119, 137, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 21>>
  let bad_window = <<136, 152, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 21>>
  let bad_checksum = <<120, 156, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 20>>
  [bad_fcheck, bad_method, bad_window, bad_checksum]
  |> list.each(fn(invalid) {
    assert compression.decode(
        compression.Deflate,
        invalid,
        None,
        compression.defaults(),
      )
      == Error(compression.InvalidEncoding)
  })
}

pub fn rfc1950_dictionary_truncation_and_trailing_bytes_fail_closed_test() -> Nil {
  let vector = <<120, 156, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 21>>
  let truncated = <<120, 156, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2>>
  assert compression.decode(
      compression.Deflate,
      truncated,
      None,
      compression.defaults(),
    )
    == Error(compression.InvalidEncoding)

  // RFC 1950 permits a preset dictionary only when the embedding format
  // specifies it. HTTP content coding does not, so FDICT and caller-supplied
  // dictionary state are both rejected.
  let fdict = <<
    120,
    187,
    0,
    0,
    0,
    1,
    203,
    72,
    205,
    201,
    201,
    7,
    0,
    6,
    44,
    2,
    21,
  >>
  assert compression.decode(
      compression.Deflate,
      fdict,
      None,
      compression.defaults(),
    )
    == Error(compression.InvalidDictionary)
  assert compression.decode(
      compression.Deflate,
      vector,
      Some(<<"dictionary":utf8>>),
      compression.defaults(),
    )
    == Error(compression.InvalidDictionary)

  // A one-shot content decoder must not silently discard bytes following
  // ADLER32, where an HTTP message or second coding could otherwise hide.
  assert compression.decode(
      compression.Deflate,
      <<vector:bits, "GET /smuggled HTTP/1.1\r\n":utf8>>,
      None,
      compression.defaults(),
    )
    == Error(compression.InvalidEncoding)
}

pub fn rfc1951_stored_and_fixed_huffman_vectors_test() -> Nil {
  let hello = <<"hello":utf8>>
  // One final uncompressed DEFLATE block inside a valid zlib wrapper.
  let stored = <<
    120,
    1,
    1,
    5,
    0,
    250,
    255,
    "hello":utf8,
    6,
    44,
    2,
    21,
  >>
  assert compression.decode(
      compression.Deflate,
      stored,
      None,
      compression.defaults(),
    )
    == Ok(hello)

  // This fixed-Huffman stream uses two-bit extra values for both a length
  // and a distance. They are deliberately asymmetric, so it also locks in
  // the least-significant-bit-first interpretation from reported erratum
  // 7764 instead of reproducing the reversed prose in RFC 1951 section 3.2.5.
  let extra_bits = <<
    120,
    1,
    75,
    76,
    74,
    78,
    73,
    77,
    75,
    207,
    200,
    204,
    202,
    206,
    201,
    205,
    195,
    202,
    3,
    0,
    252,
    147,
    14,
    15,
  >>
  assert compression.decode(
      compression.Deflate,
      extra_bits,
      None,
      compression.defaults(),
    )
    == Ok(<<"abcdefghijklmnabcdefghijklmnabcdefg":utf8>>)
}

pub fn rfc1951_reserved_truncated_and_impossible_blocks_fail_closed_test() -> Nil {
  let reserved_block_type = <<120, 1, 7, 0, 0, 0, 1>>
  let stored_length_complement_mismatch = <<
    120,
    1,
    1,
    5,
    0,
    251,
    255,
    "hello":utf8,
    6,
    44,
    2,
    21,
  >>
  let truncated_dynamic_tree = <<120, 1, 5, 0, 0, 0, 1>>
  let distance_before_history = <<120, 1, 3, 2, 0, 0, 0, 0, 1>>
  [
    reserved_block_type,
    stored_length_complement_mismatch,
    truncated_dynamic_tree,
    distance_before_history,
  ]
  |> list.each(fn(invalid) {
    assert compression.decode(
        compression.Deflate,
        invalid,
        None,
        compression.defaults(),
      )
      == Error(compression.InvalidEncoding)
  })
}

pub fn rfc1951_decoder_accepts_large_multi_block_streams_test() -> Nil {
  let input =
    "0123456789abcdef"
    |> string.repeat(8192)
    |> bit_array.from_string
  let assert Ok(encoded) =
    compression.encode(compression.Deflate, input, None, compression.defaults())
  assert compression.decode(
      compression.Deflate,
      encoded,
      None,
      compression.defaults(),
    )
    == Ok(input)

  let #(full_range_vector, full_range_output) = rfc1951_full_range_vector()
  assert compression.decode(
      compression.Deflate,
      full_range_vector,
      None,
      compression.defaults(),
    )
    == Ok(full_range_output)
}

pub fn rfc1952_minimal_and_optional_header_vectors_test() -> Nil {
  let hello = <<"hello":utf8>>
  let minimal = <<
    31,
    139,
    8,
    0,
    0,
    0,
    0,
    0,
    0,
    3,
    203,
    72,
    205,
    201,
    201,
    7,
    0,
    134,
    166,
    16,
    54,
    5,
    0,
    0,
    0,
  >>
  // RFC 1952 section 2.3.1 leaves the OS byte to the platform the compression
  // ran on, and Erlang's zlib reports 3 where this vector was taken but 19 on
  // macOS. The encoder is therefore checked around that one byte rather than
  // through it: the magic, the deflate method, the absent flags, the zeroed
  // MTIME, the extra flags, and the deflate stream are all this product's to
  // decide and stay fixed.
  let assert Ok(<<encoded_header:bytes-size(9), _encoded_os, encoded_body:bits>>) =
    compression.encode(compression.Gzip, hello, None, compression.defaults())
  let assert <<vector_header:bytes-size(9), _vector_os, vector_body:bits>> =
    minimal
  assert encoded_header == vector_header
  assert encoded_body == vector_body
  assert compression.decode(
      compression.Gzip,
      minimal,
      None,
      compression.defaults(),
    )
    == Ok(hello)
  assert compression.decode(
      compression.Gzip,
      rfc1952_optional_header_vector(),
      None,
      compression.defaults(),
    )
    == Ok(hello)
}

pub fn rfc1952_concatenated_members_and_trailing_garbage_test() -> Nil {
  let hello = <<
    31,
    139,
    8,
    0,
    0,
    0,
    0,
    0,
    0,
    3,
    203,
    72,
    205,
    201,
    201,
    7,
    0,
    134,
    166,
    16,
    54,
    5,
    0,
    0,
    0,
  >>
  let world = <<
    31,
    139,
    8,
    0,
    0,
    0,
    0,
    0,
    0,
    3,
    43,
    207,
    47,
    202,
    73,
    1,
    0,
    67,
    17,
    119,
    58,
    5,
    0,
    0,
    0,
  >>
  assert compression.decode(
      compression.Gzip,
      <<hello:bits, world:bits>>,
      None,
      compression.defaults(),
    )
    == Ok(<<"helloworld":utf8>>)
  assert compression.decode(
      compression.Gzip,
      <<hello:bits, "HTTP/1.1":utf8>>,
      None,
      compression.defaults(),
    )
    == Error(compression.InvalidEncoding)
}

pub fn rfc1952_mandatory_header_trailer_and_bounds_fail_closed_test() -> Nil {
  let bad_magic = <<0, 139, 8, 0, 0, 0, 0, 0, 0, 3>>
  let bad_method = <<31, 139, 7, 0, 0, 0, 0, 0, 0, 3>>
  let reserved_flag = <<31, 139, 8, 32, 0, 0, 0, 0, 0, 3>>
  let truncated_extra = <<31, 139, 8, 4, 0, 0, 0, 0, 0, 3, 255, 255>>
  let bad_crc = <<
    31,
    139,
    8,
    0,
    0,
    0,
    0,
    0,
    0,
    3,
    203,
    72,
    205,
    201,
    201,
    7,
    0,
    135,
    166,
    16,
    54,
    5,
    0,
    0,
    0,
  >>
  let bad_size = <<
    31,
    139,
    8,
    0,
    0,
    0,
    0,
    0,
    0,
    3,
    203,
    72,
    205,
    201,
    201,
    7,
    0,
    134,
    166,
    16,
    54,
    6,
    0,
    0,
    0,
  >>
  [bad_magic, bad_method, reserved_flag, truncated_extra, bad_crc, bad_size]
  |> list.each(fn(invalid) {
    assert compression.decode(
        compression.Gzip,
        invalid,
        None,
        compression.defaults(),
      )
      == Error(compression.InvalidEncoding)
  })
}

pub fn brotli_trivial_stream_and_zstandard_magic_are_interoperable_test() -> Nil {
  assert compression.encode(
      compression.Brotli,
      <<>>,
      None,
      compression.defaults(),
    )
    == Ok(<<6>>)
  assert compression.encode(
      compression.Brotli,
      <<"a":utf8>>,
      None,
      compression.defaults(),
    )
    == Ok(<<12, 0, 0, 8, "a":utf8, 3>>)

  let assert Ok(zstd) =
    compression.encode(
      compression.Zstandard,
      payload(),
      None,
      compression.defaults(),
    )
  let assert <<0x28, 0xb5, 0x2f, 0xfd, _rest:bits>> = zstd
  Nil
}

pub fn malformed_bomb_and_non_byte_aligned_input_fail_closed_test() -> Nil {
  let expanded = bit_array.from_string(string.repeat("A", 65_536))
  let assert Ok(compressed) =
    compression.encode(compression.Gzip, expanded, None, compression.defaults())
  let limits =
    compression.Limits(
      maximum_input_bytes: 1_048_576,
      maximum_output_bytes: 1024,
      maximum_ratio: 16,
      maximum_work_units: 128,
      maximum_window_log: 23,
      maximum_dictionary_bytes: 1024,
    )
  assert compression.decode(compression.Gzip, compressed, None, limits)
    == Error(compression.LimitExceeded)
  assert compression.decode(
      compression.Brotli,
      <<12, 1, 0, 8, 0, 3>>,
      None,
      compression.defaults(),
    )
    == Error(compression.InvalidEncoding)
  assert compression.decode(
      compression.Deflate,
      <<1:size(1)>>,
      None,
      compression.defaults(),
    )
    == Error(compression.NonByteAligned)
}

pub fn rfc9842_dictionary_headers_hash_and_round_trip_test() -> Nil {
  let dictionary =
    bit_array.from_string("common dictionary words and document template")
  let body = bit_array.from_string("common dictionary words and response")
  let assert Ok(hash) =
    compression.dictionary_hash(dictionary, compression.defaults())

  let assert Ok(dcb) =
    compression.encode(
      compression.DictionaryBrotli,
      body,
      Some(dictionary),
      compression.defaults(),
    )
  let assert <<0xff, 0x44, 0x43, 0x42, actual_hash:bytes-size(32), _rest:bits>> =
    dcb
  assert actual_hash == hash
  assert compression.decode(
      compression.DictionaryBrotli,
      dcb,
      Some(dictionary),
      compression.defaults(),
    )
    == Ok(body)

  let assert Ok(dcz) =
    compression.encode(
      compression.DictionaryZstandard,
      body,
      Some(dictionary),
      compression.defaults(),
    )
  let assert <<
    0x5e,
    0x2a,
    0x4d,
    0x18,
    0x20,
    0,
    0,
    0,
    actual_hash:bytes-size(32),
    _rest:bits,
  >> = dcz
  assert actual_hash == hash
  assert compression.decode(
      compression.DictionaryZstandard,
      dcz,
      Some(dictionary),
      compression.defaults(),
    )
    == Ok(body)
  assert compression.decode(
      compression.DictionaryZstandard,
      dcz,
      Some(<<"wrong":utf8>>),
      compression.defaults(),
    )
    == Error(compression.DictionaryMismatch)
}

pub fn rfc9842_structured_fields_are_strict_and_canonical_test() -> Nil {
  let expected =
    compression.UseAsDictionary(
      match: "/app/*/main.js",
      destinations: ["script"],
      identifier: "dictionary-12345",
      dictionary_type: compression.Raw,
      extensions: [],
    )
  let wire =
    "match=\"/app/*/main.js\", match-dest=(\"script\"), id=\"dictionary-12345\", type=raw"
  assert compression.parse_use_as_dictionary(wire) == Ok(expected)
  assert compression.serialize_use_as_dictionary(expected) == Ok(wire)

  let bytes = <<1, 2, 3>>
  let assert Ok(hash) =
    compression.dictionary_hash(bytes, compression.defaults())
  let assert Ok(available) = compression.serialize_available_dictionary(hash)
  assert compression.parse_available_dictionary(available) == Ok(hash)
  assert compression.parse_available_dictionary(":AQI=:")
    == Error(compression.InvalidDictionary)
  assert compression.parse_dictionary_id("\"id-1\"") == Ok("id-1")
}

pub fn dictionary_store_partitions_origin_destination_and_freshness_test() -> Nil {
  let directive =
    compression.UseAsDictionary(
      match: "/app/*/main.js",
      destinations: ["script"],
      identifier: "v1",
      dictionary_type: compression.Raw,
      extensions: [],
    )
  let isolation = compression.IsolationKey("top.example", "default")
  let assert Ok(store) =
    compression.store(maximum_entries: 4, maximum_bytes: 4096)
  let assert Ok(store) =
    compression.insert_dictionary(
      store,
      isolation,
      origin: "https://example.com",
      directive: directive,
      content: <<"dictionary":utf8>>,
      fresh_until: 200,
      fetched_at: 100,
    )
  let assert Ok(selected) =
    compression.select_dictionary(
      store,
      isolation,
      origin: "https://example.com",
      path: "/app/v2/main.js",
      destination: "script",
      now: 150,
    )
  assert selected.identifier == "v1"
  assert compression.select_dictionary(
      store,
      isolation,
      origin: "https://other.example",
      path: "/app/v2/main.js",
      destination: "script",
      now: 150,
    )
    == Error(compression.NoMatchingDictionary)
  assert compression.select_dictionary(
      store,
      isolation,
      origin: "https://example.com",
      path: "/app/v2/main.js",
      destination: "document",
      now: 150,
    )
    == Error(compression.NoMatchingDictionary)
  assert compression.select_dictionary(
      store,
      isolation,
      origin: "https://example.com",
      path: "/app/v2/main.js",
      destination: "script",
      now: 201,
    )
    == Error(compression.NoMatchingDictionary)
}
