//// Bounded HTTP content codings and RFC 9842 dictionary transport.
////
//// gzip and deflate use OTP zlib's incremental safe inflate path. Zstandard
//// uses the OTP 28+ streaming codec with an explicit maximum window. Brotli
//// encoding implements RFC 7932's portable trivial compressor; decoding
//// accepts that bounded stored representation and rejects other compressed
//// meta-blocks explicitly rather than treating bytes as decoded content.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/digest
import http/structured_fields

/// Registered content codings supported by this module.
pub type Coding {
  Identity
  Gzip
  Deflate
  Brotli
  Zstandard
  DictionaryBrotli
  DictionaryZstandard
}

/// Independent allocation and work ceilings for one codec operation.
pub type Limits {
  Limits(
    maximum_input_bytes: Int,
    maximum_output_bytes: Int,
    maximum_ratio: Int,
    maximum_work_units: Int,
    maximum_window_log: Int,
    maximum_dictionary_bytes: Int,
  )
}

/// RFC 9842 dictionary format. Unknown formats are retained but never used.
pub type DictionaryType {
  Raw
  ExtensionDictionaryType(String)
}

/// Parsed `Use-As-Dictionary` directive with unknown members retained.
pub type UseAsDictionary {
  UseAsDictionary(
    match: String,
    destinations: List(String),
    identifier: String,
    dictionary_type: DictionaryType,
    extensions: List(structured_fields.DictionaryMember),
  )
}

/// Network-isolation partition key for dictionary state.
pub type IsolationKey {
  IsolationKey(top_level_site: String, profile: String)
}

/// One finite, origin-bound, fresh dictionary record.
pub type Dictionary {
  Dictionary(
    isolation_key: IsolationKey,
    origin: String,
    match: String,
    destinations: List(String),
    identifier: String,
    dictionary_type: DictionaryType,
    content: BitArray,
    hash: BitArray,
    fresh_until: Int,
    fetched_at: Int,
    retained_bytes: Int,
  )
}

/// A finite in-memory dictionary store. Entries are newest first.
pub opaque type Store {
  Store(
    maximum_entries: Int,
    maximum_bytes: Int,
    retained_bytes: Int,
    entries: List(Dictionary),
  )
}

/// Codec, syntax, dictionary, resource, or availability failure.
pub type Error {
  InvalidLimits
  InvalidEncoding
  InvalidDictionary
  DictionaryRequired
  DictionaryMismatch
  UnsupportedAlgorithm
  UnsupportedBrotliStream
  NonByteAligned
  LimitExceeded
  NoMatchingDictionary
  CryptoFailure
}

/// Conservative per-message defaults.
pub fn defaults() -> Limits {
  Limits(
    maximum_input_bytes: 16_777_216,
    maximum_output_bytes: 67_108_864,
    maximum_ratio: 1000,
    maximum_work_units: 4096,
    maximum_window_log: 27,
    maximum_dictionary_bytes: 16_777_216,
  )
}

/// Encode one byte-aligned representation.
pub fn encode(
  coding coding: Coding,
  input input: BitArray,
  dictionary dictionary: Option(BitArray),
  limits limits: Limits,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_operation(input, limits))
  use encoded <- result.try(case coding {
    Identity -> {
      use _ <- result.try(require_no_dictionary(dictionary))
      Ok(input)
    }
    Gzip -> {
      use _ <- result.try(require_no_dictionary(dictionary))
      ffi_compress(1, input, <<>>, 6) |> from_ffi
    }
    Deflate -> {
      use _ <- result.try(require_no_dictionary(dictionary))
      ffi_compress(2, input, <<>>, 6) |> from_ffi
    }
    Brotli -> {
      use _ <- result.try(require_no_dictionary(dictionary))
      encode_brotli(input, limits)
    }
    Zstandard -> {
      use _ <- result.try(require_no_dictionary(dictionary))
      ffi_compress(4, input, <<>>, 3) |> from_ffi
    }
    DictionaryBrotli -> {
      use dictionary <- result.try(require_dictionary(dictionary, limits))
      use hash <- result.try(dictionary_hash(dictionary, limits))
      use stream <- result.try(encode_brotli(input, limits))
      Ok(<<0xff, 0x44, 0x43, 0x42, hash:bits, stream:bits>>)
    }
    DictionaryZstandard -> {
      use dictionary <- result.try(require_dictionary(dictionary, limits))
      use hash <- result.try(dictionary_hash(dictionary, limits))
      use stream <- result.try(
        ffi_compress(4, input, dictionary, 3) |> from_ffi,
      )
      Ok(<<0x5e, 0x2a, 0x4d, 0x18, 0x20, 0, 0, 0, hash:bits, stream:bits>>)
    }
  })
  case bit_array.byte_size(encoded) <= limits.maximum_output_bytes {
    True -> Ok(encoded)
    False -> Error(LimitExceeded)
  }
}

/// Decode one byte-aligned representation with output, ratio, work, and
/// window limits applied during expansion.
pub fn decode(
  coding coding: Coding,
  input input: BitArray,
  dictionary dictionary: Option(BitArray),
  limits limits: Limits,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_operation(input, limits))
  case coding {
    Identity -> {
      use _ <- result.try(require_no_dictionary(dictionary))
      bounded_identity(input, limits)
    }
    Gzip -> {
      use _ <- result.try(require_no_dictionary(dictionary))
      decode_ffi(1, input, <<>>, limits)
    }
    Deflate -> {
      use _ <- result.try(require_no_dictionary(dictionary))
      decode_ffi(2, input, <<>>, limits)
    }
    Brotli -> {
      use _ <- result.try(require_no_dictionary(dictionary))
      decode_brotli(input, limits)
    }
    Zstandard -> {
      use _ <- result.try(require_no_dictionary(dictionary))
      decode_ffi(4, input, <<>>, limits)
    }
    DictionaryBrotli -> {
      use dictionary <- result.try(require_dictionary(dictionary, limits))
      use stream <- result.try(open_dictionary_header(
        input,
        dictionary,
        <<0xff, 0x44, 0x43, 0x42>>,
        4,
        limits,
      ))
      decode_brotli(stream, limits)
    }
    DictionaryZstandard -> {
      use dictionary <- result.try(require_dictionary(dictionary, limits))
      use stream <- result.try(open_dictionary_header(
        input,
        dictionary,
        <<0x5e, 0x2a, 0x4d, 0x18, 0x20, 0, 0, 0>>,
        8,
        limits,
      ))
      decode_ffi(4, stream, dictionary, limits)
    }
  }
}

/// Compute the RFC 9842 SHA-256 dictionary identifier under the dictionary
/// size limit.
pub fn dictionary_hash(
  dictionary: BitArray,
  limits: Limits,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(aligned(dictionary))
  use _ <- result.try(
    case
      bit_array.byte_size(dictionary) > 0
      && bit_array.byte_size(dictionary) <= limits.maximum_dictionary_bytes
    {
      True -> Ok(Nil)
      False -> Error(InvalidDictionary)
    },
  )
  case
    digest.compute(dictionary, digest.Sha256, limits.maximum_dictionary_bytes)
  {
    Ok(digest.Digest(_, value, _)) -> Ok(value)
    Error(_) -> Error(CryptoFailure)
  }
}

/// Parse the RFC 9842 `Use-As-Dictionary` Structured Field.
pub fn parse_use_as_dictionary(
  input: String,
) -> Result(UseAsDictionary, Error) {
  use members <- result.try(
    structured_fields.parse_dictionary(input)
    |> result.map_error(fn(_) { InvalidDictionary }),
  )
  use parsed <- result.try(
    parse_directive_members(members, None, [], "", Raw, []),
  )
  use _ <- result.try(validate_directive(parsed))
  Ok(parsed)
}

/// Serialize a canonical `Use-As-Dictionary` field.
pub fn serialize_use_as_dictionary(
  directive: UseAsDictionary,
) -> Result(String, Error) {
  use _ <- result.try(validate_directive(directive))
  let destinations =
    directive.destinations
    |> list.map(fn(value) {
      structured_fields.Item(structured_fields.StringValue(value), [])
    })
  let required = [
    structured_fields.DictionaryMember(
      "match",
      structured_fields.ListItem(
        structured_fields.Item(
          structured_fields.StringValue(directive.match),
          [],
        ),
      ),
    ),
    structured_fields.DictionaryMember(
      "match-dest",
      structured_fields.InnerList(destinations, []),
    ),
    structured_fields.DictionaryMember(
      "id",
      structured_fields.ListItem(
        structured_fields.Item(
          structured_fields.StringValue(directive.identifier),
          [],
        ),
      ),
    ),
    structured_fields.DictionaryMember(
      "type",
      structured_fields.ListItem(
        structured_fields.Item(
          structured_fields.Token(dictionary_type_name(
            directive.dictionary_type,
          )),
          [],
        ),
      ),
    ),
  ]
  structured_fields.serialize_dictionary(list.append(
    required,
    directive.extensions,
  ))
  |> result.map_error(fn(_) { InvalidDictionary })
}

/// Parse a single SHA-256 `Available-Dictionary` byte sequence.
pub fn parse_available_dictionary(input: String) -> Result(BitArray, Error) {
  case structured_fields.parse_item(input) {
    Ok(structured_fields.Item(structured_fields.ByteSequence(value), [])) ->
      case bit_array.byte_size(value) == 32 {
        True -> Ok(value)
        False -> Error(InvalidDictionary)
      }
    _ -> Error(InvalidDictionary)
  }
}

/// Serialize a SHA-256 `Available-Dictionary` value.
pub fn serialize_available_dictionary(hash: BitArray) -> Result(String, Error) {
  case bit_array.bit_size(hash) % 8, bit_array.byte_size(hash) {
    0, 32 ->
      structured_fields.serialize_item(
        structured_fields.Item(structured_fields.ByteSequence(hash), []),
      )
      |> result.map_error(fn(_) { InvalidDictionary })
    _, _ -> Error(InvalidDictionary)
  }
}

/// Parse an opaque `Dictionary-ID` string of at most 1024 characters.
pub fn parse_dictionary_id(input: String) -> Result(String, Error) {
  case structured_fields.parse_item(input) {
    Ok(structured_fields.Item(structured_fields.StringValue(value), [])) ->
      case string.length(value) <= 1024 {
        True -> Ok(value)
        False -> Error(InvalidDictionary)
      }
    _ -> Error(InvalidDictionary)
  }
}

/// Serialize an opaque `Dictionary-ID`.
pub fn serialize_dictionary_id(value: String) -> Result(String, Error) {
  case string.length(value) <= 1024 && safe_text(value) {
    False -> Error(InvalidDictionary)
    True ->
      structured_fields.serialize_item(
        structured_fields.Item(structured_fields.StringValue(value), []),
      )
      |> result.map_error(fn(_) { InvalidDictionary })
  }
}

/// Create a finite, initially empty dictionary store.
pub fn store(
  maximum_entries maximum_entries: Int,
  maximum_bytes maximum_bytes: Int,
) -> Result(Store, Error) {
  case
    maximum_entries > 0
    && maximum_entries <= 1_000_000
    && maximum_bytes > 0
    && maximum_bytes <= 1_073_741_824
  {
    True -> Ok(Store(maximum_entries, maximum_bytes, 0, []))
    False -> Error(InvalidLimits)
  }
}

/// Insert an origin-bound fresh raw dictionary, evicting oldest entries to
/// maintain both finite ceilings.
pub fn insert_dictionary(
  store store: Store,
  isolation_key isolation_key: IsolationKey,
  origin origin: String,
  directive directive: UseAsDictionary,
  content content: BitArray,
  fresh_until fresh_until: Int,
  fetched_at fetched_at: Int,
) -> Result(Store, Error) {
  use _ <- result.try(validate_isolation(isolation_key))
  use _ <- result.try(validate_origin(origin))
  use _ <- result.try(validate_directive(directive))
  use _ <- result.try(case directive.dictionary_type {
    Raw -> Ok(Nil)
    ExtensionDictionaryType(_) -> Error(UnsupportedAlgorithm)
  })
  use _ <- result.try(aligned(content))
  use _ <- result.try(
    case bit_array.byte_size(content) > 0 && fresh_until > fetched_at {
      True -> Ok(Nil)
      False -> Error(InvalidDictionary)
    },
  )
  let retained =
    bit_array.byte_size(content)
    + string.byte_size(origin)
    + string.byte_size(directive.match)
    + string.byte_size(directive.identifier)
    + destination_bytes(directive.destinations, 0)
    + 96
  use _ <- result.try(case retained <= store.maximum_bytes {
    True -> Ok(Nil)
    False -> Error(LimitExceeded)
  })
  use hash <- result.try(dictionary_hash(
    content,
    Limits(
      maximum_input_bytes: store.maximum_bytes,
      maximum_output_bytes: store.maximum_bytes,
      maximum_ratio: 1,
      maximum_work_units: 1,
      maximum_window_log: 10,
      maximum_dictionary_bytes: store.maximum_bytes,
    ),
  ))
  let entry =
    Dictionary(
      isolation_key,
      origin,
      directive.match,
      directive.destinations,
      directive.identifier,
      directive.dictionary_type,
      content,
      hash,
      fresh_until,
      fetched_at,
      retained,
    )
  let store = remove_same_dictionary(store, isolation_key, origin, hash)
  Ok(evict_to_fit(
    Store(..store, retained_bytes: store.retained_bytes + retained, entries: [
      entry,
      ..store.entries
    ]),
  ))
}

/// Select the best fresh same-origin dictionary in one isolation partition.
pub fn select_dictionary(
  store: Store,
  isolation_key: IsolationKey,
  origin origin: String,
  path path: String,
  destination destination: String,
  now now: Int,
) -> Result(Dictionary, Error) {
  use _ <- result.try(validate_isolation(isolation_key))
  use _ <- result.try(validate_origin(origin))
  use _ <- result.try(case valid_path(path) && safe_text(destination) {
    True -> Ok(Nil)
    False -> Error(InvalidDictionary)
  })
  case
    select_entry(
      store.entries,
      isolation_key,
      origin,
      path,
      destination,
      now,
      None,
    )
  {
    Some(value) -> Ok(value)
    None -> Error(NoMatchingDictionary)
  }
}

fn validate_operation(input: BitArray, limits: Limits) -> Result(Nil, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(aligned(input))
  case bit_array.byte_size(input) <= limits.maximum_input_bytes {
    True -> Ok(Nil)
    False -> Error(LimitExceeded)
  }
}

fn validate_limits(limits: Limits) -> Result(Nil, Error) {
  case
    limits.maximum_input_bytes > 0
    && limits.maximum_output_bytes >= 0
    && limits.maximum_ratio > 0
    && limits.maximum_work_units > 0
    && limits.maximum_window_log >= 10
    && limits.maximum_window_log <= 27
    && limits.maximum_dictionary_bytes > 0
    && limits.maximum_dictionary_bytes <= limits.maximum_input_bytes
  {
    True -> Ok(Nil)
    False -> Error(InvalidLimits)
  }
}

fn bounded_identity(
  input: BitArray,
  limits: Limits,
) -> Result(BitArray, Error) {
  case bit_array.byte_size(input) <= limits.maximum_output_bytes {
    True -> Ok(input)
    False -> Error(LimitExceeded)
  }
}

fn require_no_dictionary(dictionary: Option(BitArray)) -> Result(Nil, Error) {
  case dictionary {
    None -> Ok(Nil)
    Some(_) -> Error(InvalidDictionary)
  }
}

fn require_dictionary(
  dictionary: Option(BitArray),
  limits: Limits,
) -> Result(BitArray, Error) {
  case dictionary {
    None -> Error(DictionaryRequired)
    Some(dictionary) -> {
      use _ <- result.try(aligned(dictionary))
      case
        bit_array.byte_size(dictionary) > 0
        && bit_array.byte_size(dictionary) <= limits.maximum_dictionary_bytes
      {
        True -> Ok(dictionary)
        False -> Error(InvalidDictionary)
      }
    }
  }
}

fn decode_ffi(
  coding: Int,
  input: BitArray,
  dictionary: BitArray,
  limits: Limits,
) -> Result(BitArray, Error) {
  ffi_decompress(
    coding,
    input,
    dictionary,
    limits.maximum_output_bytes,
    limits.maximum_ratio,
    limits.maximum_work_units,
    limits.maximum_window_log,
  )
  |> from_ffi
}

fn from_ffi(value: Result(BitArray, Int)) -> Result(BitArray, Error) {
  case value {
    Ok(value) -> Ok(value)
    Error(2) -> Error(LimitExceeded)
    Error(3) -> Error(UnsupportedAlgorithm)
    Error(4) -> Error(InvalidDictionary)
    Error(_) -> Error(InvalidEncoding)
  }
}

fn encode_brotli(input: BitArray, limits: Limits) -> Result(BitArray, Error) {
  case input {
    <<>> -> Ok(<<6>>)
    _ -> {
      use chunks <- result.try(
        encode_brotli_chunks(input, limits.maximum_work_units, []),
      )
      Ok(bit_array.concat([<<12>>, ..list.append(chunks, [<<3>>])]))
    }
  }
}

fn encode_brotli_chunks(
  input: BitArray,
  work: Int,
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case input, work {
    <<>>, _ -> Ok(list.reverse(reversed))
    _, 0 -> Error(LimitExceeded)
    _, _ -> {
      let length = minimum(bit_array.byte_size(input), 65_536)
      use #(chunk, rest) <- result.try(take(input, length))
      let remaining = length - 1
      let first = { remaining % 32 } * 8
      let second = { remaining / 32 } % 256
      let third = 8 + { remaining / 8192 }
      encode_brotli_chunks(rest, work - 1, [
        <<first, second, third, chunk:bits>>,
        ..reversed
      ])
    }
  }
}

fn decode_brotli(input: BitArray, limits: Limits) -> Result(BitArray, Error) {
  case input {
    <<6>> -> Ok(<<>>)
    <<12, rest:bits>> -> {
      let allowed = allowed_output(input, limits)
      use chunks <- result.try(
        decode_brotli_chunks(rest, allowed, limits.maximum_work_units, 0, []),
      )
      Ok(bit_array.concat(chunks))
    }
    _ -> Error(UnsupportedBrotliStream)
  }
}

fn decode_brotli_chunks(
  input: BitArray,
  allowed: Int,
  work: Int,
  output_bytes: Int,
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case input, work {
    <<3>>, _ -> Ok(list.reverse(reversed))
    _, 0 -> Error(LimitExceeded)
    <<first, second, third, rest:bits>>, _ -> {
      use _ <- result.try(case first % 8 == 0 && third >= 8 && third <= 15 {
        True -> Ok(Nil)
        False -> Error(InvalidEncoding)
      })
      let length =
        { first / 8 } + { second * 32 } + { { third - 8 } * 8192 } + 1
      use _ <- result.try(
        case length <= 65_536 && output_bytes + length <= allowed {
          True -> Ok(Nil)
          False -> Error(LimitExceeded)
        },
      )
      use #(chunk, rest) <- result.try(take(rest, length))
      decode_brotli_chunks(rest, allowed, work - 1, output_bytes + length, [
        chunk,
        ..reversed
      ])
    }
    _, _ -> Error(InvalidEncoding)
  }
}

fn allowed_output(input: BitArray, limits: Limits) -> Int {
  minimum(
    limits.maximum_output_bytes,
    bit_array.byte_size(input) * limits.maximum_ratio,
  )
}

fn open_dictionary_header(
  input: BitArray,
  dictionary: BitArray,
  magic: BitArray,
  magic_length: Int,
  limits: Limits,
) -> Result(BitArray, Error) {
  use expected_hash <- result.try(dictionary_hash(dictionary, limits))
  let header_length = magic_length + 32
  case bit_array.byte_size(input) >= header_length {
    False -> Error(InvalidEncoding)
    True ->
      case input {
        <<
          actual_magic:bytes-size(magic_length),
          actual_hash:bytes-size(32),
          stream:bits,
        >> ->
          case actual_magic == magic, actual_hash == expected_hash {
            False, _ -> Error(InvalidEncoding)
            _, False -> Error(DictionaryMismatch)
            True, True -> Ok(stream)
          }
        _ -> Error(InvalidEncoding)
      }
  }
}

fn parse_directive_members(
  members: List(structured_fields.DictionaryMember),
  match: Option(String),
  destinations: List(String),
  identifier: String,
  dictionary_type: DictionaryType,
  reversed_extensions: List(structured_fields.DictionaryMember),
) -> Result(UseAsDictionary, Error) {
  case members {
    [] ->
      case match {
        Some(match) ->
          Ok(UseAsDictionary(
            match,
            destinations,
            identifier,
            dictionary_type,
            list.reverse(reversed_extensions),
          ))
        None -> Error(InvalidDictionary)
      }
    [member, ..rest] -> {
      let structured_fields.DictionaryMember(key, value) = member
      case key, value {
        "match",
          structured_fields.ListItem(structured_fields.Item(
            structured_fields.StringValue(value),
            [],
          ))
        ->
          parse_directive_members(
            rest,
            Some(value),
            destinations,
            identifier,
            dictionary_type,
            reversed_extensions,
          )
        "match-dest", structured_fields.InnerList(items, []) -> {
          use destinations <- result.try(parse_destinations(items, []))
          parse_directive_members(
            rest,
            match,
            destinations,
            identifier,
            dictionary_type,
            reversed_extensions,
          )
        }
        "id",
          structured_fields.ListItem(structured_fields.Item(
            structured_fields.StringValue(value),
            [],
          ))
        ->
          parse_directive_members(
            rest,
            match,
            destinations,
            value,
            dictionary_type,
            reversed_extensions,
          )
        "type",
          structured_fields.ListItem(structured_fields.Item(
            structured_fields.Token(value),
            [],
          ))
        ->
          parse_directive_members(
            rest,
            match,
            destinations,
            identifier,
            parse_dictionary_type(value),
            reversed_extensions,
          )
        "match", _ | "match-dest", _ | "id", _ | "type", _ ->
          Error(InvalidDictionary)
        _, _ ->
          parse_directive_members(
            rest,
            match,
            destinations,
            identifier,
            dictionary_type,
            [member, ..reversed_extensions],
          )
      }
    }
  }
}

fn parse_destinations(
  items: List(structured_fields.Item),
  reversed: List(String),
) -> Result(List(String), Error) {
  case items {
    [] -> Ok(list.reverse(reversed))
    [structured_fields.Item(structured_fields.StringValue(value), []), ..rest] ->
      parse_destinations(rest, [value, ..reversed])
    _ -> Error(InvalidDictionary)
  }
}

fn validate_directive(directive: UseAsDictionary) -> Result(Nil, Error) {
  case
    valid_pattern(directive.match)
    && string.length(directive.identifier) <= 1024
    && safe_text(directive.identifier)
    && list.length(directive.destinations) <= 64
    && valid_destinations(directive.destinations)
    && list.length(directive.extensions) <= 64
  {
    True -> Ok(Nil)
    False -> Error(InvalidDictionary)
  }
}

fn valid_pattern(pattern: String) -> Bool {
  string.starts_with(pattern, "/")
  && string.byte_size(pattern) <= 2048
  && safe_text(pattern)
  && !string.contains(pattern, "(")
  && !string.contains(pattern, ")")
  && list.length(string.split(pattern, on: "*")) <= 17
}

fn valid_destinations(destinations: List(String)) -> Bool {
  case destinations {
    [] -> True
    [destination, ..rest] ->
      case
        destination != ""
        && string.byte_size(destination) <= 64
        && safe_text(destination)
        && !list.contains(rest, destination)
      {
        True -> valid_destinations(rest)
        False -> False
      }
  }
}

fn parse_dictionary_type(value: String) -> DictionaryType {
  case value {
    "raw" -> Raw
    value -> ExtensionDictionaryType(value)
  }
}

fn dictionary_type_name(value: DictionaryType) -> String {
  case value {
    Raw -> "raw"
    ExtensionDictionaryType(value) -> value
  }
}

fn validate_isolation(key: IsolationKey) -> Result(Nil, Error) {
  case
    key.top_level_site != ""
    && key.profile != ""
    && string.byte_size(key.top_level_site) <= 1024
    && string.byte_size(key.profile) <= 1024
    && safe_text(key.top_level_site)
    && safe_text(key.profile)
  {
    True -> Ok(Nil)
    False -> Error(InvalidDictionary)
  }
}

fn validate_origin(origin: String) -> Result(Nil, Error) {
  case
    string.starts_with(origin, "https://")
    && string.length(origin) > string.length("https://")
    && string.byte_size(origin) <= 2048
    && safe_text(origin)
  {
    True -> Ok(Nil)
    False -> Error(InvalidDictionary)
  }
}

fn valid_path(path: String) -> Bool {
  string.starts_with(path, "/")
  && string.byte_size(path) <= 8192
  && safe_text(path)
}

fn safe_text(value: String) -> Bool {
  safe_bytes(bit_array.from_string(value))
}

fn safe_bytes(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, rest:bits>> if byte != 0 && byte != 10 && byte != 13 ->
      safe_bytes(rest)
    _ -> False
  }
}

fn destination_bytes(destinations: List(String), total: Int) -> Int {
  case destinations {
    [] -> total
    [value, ..rest] -> destination_bytes(rest, total + string.byte_size(value))
  }
}

fn remove_same_dictionary(
  store: Store,
  isolation_key: IsolationKey,
  origin: String,
  hash: BitArray,
) -> Store {
  let #(entries, removed) =
    remove_entry(store.entries, isolation_key, origin, hash, [], 0)
  Store(
    ..store,
    retained_bytes: store.retained_bytes - removed,
    entries: entries,
  )
}

fn remove_entry(
  entries: List(Dictionary),
  isolation_key: IsolationKey,
  origin: String,
  hash: BitArray,
  reversed: List(Dictionary),
  removed: Int,
) -> #(List(Dictionary), Int) {
  case entries {
    [] -> #(list.reverse(reversed), removed)
    [entry, ..rest] ->
      case
        entry.isolation_key == isolation_key
        && entry.origin == origin
        && entry.hash == hash
      {
        True ->
          remove_entry(
            rest,
            isolation_key,
            origin,
            hash,
            reversed,
            removed + entry.retained_bytes,
          )
        False ->
          remove_entry(
            rest,
            isolation_key,
            origin,
            hash,
            [entry, ..reversed],
            removed,
          )
      }
  }
}

fn evict_to_fit(store: Store) -> Store {
  case
    list.length(store.entries) <= store.maximum_entries
    && store.retained_bytes <= store.maximum_bytes
  {
    True -> store
    False -> {
      let #(entries, removed) = remove_oldest(store.entries, [])
      evict_to_fit(
        Store(
          ..store,
          retained_bytes: store.retained_bytes - removed,
          entries: entries,
        ),
      )
    }
  }
}

fn remove_oldest(
  entries: List(Dictionary),
  reversed: List(Dictionary),
) -> #(List(Dictionary), Int) {
  case entries {
    [] -> #([], 0)
    [entry] -> #(list.reverse(reversed), entry.retained_bytes)
    [entry, ..rest] -> remove_oldest(rest, [entry, ..reversed])
  }
}

fn select_entry(
  entries: List(Dictionary),
  isolation_key: IsolationKey,
  origin: String,
  path: String,
  destination: String,
  now: Int,
  selected: Option(Dictionary),
) -> Option(Dictionary) {
  case entries {
    [] -> selected
    [entry, ..rest] -> {
      let matches =
        entry.isolation_key == isolation_key
        && entry.origin == origin
        && entry.fresh_until >= now
        && destination_matches(entry.destinations, destination)
        && pattern_matches(entry.match, path)
      let selected = case matches, selected {
        False, _ -> selected
        True, None -> Some(entry)
        True, Some(current) ->
          case preferred(entry, current) {
            True -> Some(entry)
            False -> selected
          }
      }
      select_entry(
        rest,
        isolation_key,
        origin,
        path,
        destination,
        now,
        selected,
      )
    }
  }
}

fn destination_matches(
  destinations: List(String),
  destination: String,
) -> Bool {
  case destinations {
    [] -> True
    _ -> list.contains(destinations, destination)
  }
}

fn preferred(candidate: Dictionary, current: Dictionary) -> Bool {
  let candidate_specific = candidate.destinations != []
  let current_specific = current.destinations != []
  case candidate_specific, current_specific {
    True, False -> True
    False, True -> False
    _, _ ->
      case string.length(candidate.match) - string.length(current.match) {
        difference if difference > 0 -> True
        difference if difference < 0 -> False
        _ -> candidate.fetched_at > current.fetched_at
      }
  }
}

fn pattern_matches(pattern: String, path: String) -> Bool {
  let segments =
    string.split(pattern, on: "*")
    |> list.map(bit_array.from_string)
  let anchored_end = !string.ends_with(pattern, "*")
  case segments {
    [] -> False
    [first, ..rest] ->
      case starts_with(bit_array.from_string(path), first) {
        None -> False
        Some(remaining) -> match_segments(remaining, rest, anchored_end)
      }
  }
}

fn match_segments(
  remaining: BitArray,
  segments: List(BitArray),
  anchored_end: Bool,
) -> Bool {
  case segments {
    [] -> remaining == <<>>
    [last] if anchored_end -> ends_with(remaining, last)
    [segment, ..rest] ->
      case find_after(remaining, segment) {
        None -> False
        Some(remaining) -> match_segments(remaining, rest, anchored_end)
      }
  }
}

fn starts_with(input: BitArray, prefix: BitArray) -> Option(BitArray) {
  let length = bit_array.byte_size(prefix)
  case bit_array.byte_size(input) >= length {
    False -> None
    True -> {
      let bits = length * 8
      case input {
        <<actual:bits-size(bits), rest:bits>> if actual == prefix -> Some(rest)
        _ -> None
      }
    }
  }
}

fn ends_with(input: BitArray, suffix: BitArray) -> Bool {
  let input_size = bit_array.byte_size(input)
  let suffix_size = bit_array.byte_size(suffix)
  case suffix_size <= input_size {
    False -> False
    True -> {
      let prefix_bits = { input_size - suffix_size } * 8
      case input {
        <<_:size(prefix_bits), actual:bits>> -> actual == suffix
        _ -> False
      }
    }
  }
}

fn find_after(input: BitArray, needle: BitArray) -> Option(BitArray) {
  case needle {
    <<>> -> Some(input)
    _ -> find_after_at(input, needle)
  }
}

fn find_after_at(input: BitArray, needle: BitArray) -> Option(BitArray) {
  case starts_with(input, needle) {
    Some(rest) -> Some(rest)
    None ->
      case input {
        <<_, rest:bits>> -> find_after_at(rest, needle)
        <<>> -> None
        _ -> None
      }
  }
}

fn aligned(bytes: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(bytes) % 8 {
    0 -> Ok(Nil)
    _ -> Error(NonByteAligned)
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Error) {
  case take_nil(bytes, length) {
    Ok(value) -> Ok(value)
    Error(_) -> Error(InvalidEncoding)
  }
}

fn take_nil(
  bytes: BitArray,
  length: Int,
) -> Result(#(BitArray, BitArray), Nil) {
  case length >= 0 && length <= bit_array.byte_size(bytes) {
    False -> Error(Nil)
    True -> {
      let bits = length * 8
      case bytes {
        <<value:bits-size(bits), rest:bits>> -> Ok(#(value, rest))
        _ -> Error(Nil)
      }
    }
  }
}

fn minimum(first: Int, second: Int) -> Int {
  case first <= second {
    True -> first
    False -> second
  }
}

@external(erlang, "http_compression_ffi", "compress")
fn ffi_compress(
  coding: Int,
  input: BitArray,
  dictionary: BitArray,
  level: Int,
) -> Result(BitArray, Int)

@external(erlang, "http_compression_ffi", "decompress")
fn ffi_decompress(
  coding: Int,
  input: BitArray,
  dictionary: BitArray,
  maximum_output_bytes: Int,
  maximum_ratio: Int,
  maximum_work_units: Int,
  maximum_window_log: Int,
) -> Result(BitArray, Int)
