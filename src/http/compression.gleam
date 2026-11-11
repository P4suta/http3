//// Bounded HTTP content codings and RFC 9842 dictionary transport.
////
//// gzip and deflate use OTP zlib's incremental safe inflate path. Zstandard
//// uses the OTP 28+ streaming codec with an explicit maximum window. Brotli
//// encoding implements RFC 7932's portable trivial compressor. Its pure BEAM
//// decoder supports compressed, stored, and metadata blocks, all static
//// dictionary transforms, and RFC 9842 raw prefix dictionaries. Brotli work
//// units reserve 1024 parser/output steps, including tree and context-map
//// construction, independently of byte and window limits.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/digest
import http/internal/url_pattern/component
import http/internal/url_pattern/pattern
import http/internal/url_pattern/url
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

/// Provenance of all bytes supplied to one secure-channel compression call.
///
/// Each call creates a fresh compression context.
/// Confidential and attacker-controlled bytes therefore remain in separate contexts only when the caller classifies and encodes them in separate calls.
pub type ContentProvenance {
  /// Content which is neither confidential nor attacker controlled.
  PublicContent
  /// Confidential content with no attacker-controlled bytes in this input.
  ConfidentialContent
  /// Attacker-controlled content with no confidential bytes in this input.
  AttackerControlledContent
  /// One input containing both confidential and attacker-controlled bytes.
  MixedConfidentialAndAttackerControlled
  /// The complete source of the input cannot be established.
  UnknownProvenance
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

/// Whether the caller supports Fetch request destinations.
/// A supported empty destination is a real destination, distinct from an unsupported capability.
pub type DestinationCapability {
  SupportedDestination(String)
  DestinationsUnsupported
}

/// Explicit scope for clearing this immutable dictionary store.
pub type DictionaryClearScope {
  PartitionDictionaries(IsolationKey)
  ProfileDictionaries(String)
  AllDictionaries
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

/// A finite in-memory dictionary store.
/// Entries are newest first.
/// Its byte budget covers copied content and metadata, binary headers, and record/list storage conservatively.
/// It applies to the returned store value; callers control the lifetime of older immutable store values they retain.
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
  UnsafeCompressionProvenance
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

/// Encode one byte-aligned representation as a low-level codec operation.
///
/// This function does not establish whether compression is safe for a secure transport.
/// HTTP over TLS callers should use `encode_for_secure_channel`,
/// which requires an explicit input-provenance decision.
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

/// Encode content for transmission over a secure channel.
///
/// RFC 9114 section 10.6 forbids compression when the input's provenance is unknown, and when confidential and attacker-controlled bytes share a compression context.
/// `Identity` never compresses and is therefore always allowed.
/// Every other coding is refused before codec or dictionary work begins unless this invocation contains one known source class.
///
/// Encode confidential and attacker-controlled parts in separate calls when a protocol provides a safe way to carry separate representations.
/// Joining those parts into one `BitArray` is deliberately classified as mixed and is rejected.
pub fn encode_for_secure_channel(
  coding coding: Coding,
  input input: BitArray,
  dictionary dictionary: Option(BitArray),
  limits limits: Limits,
  provenance provenance: ContentProvenance,
) -> Result(BitArray, Error) {
  use _ <- result.try(case secure_compression_allowed(coding, provenance) {
    True -> Ok(Nil)
    False -> Error(UnsafeCompressionProvenance)
  })
  encode(coding:, input:, dictionary:, limits:)
}

fn secure_compression_allowed(
  coding: Coding,
  provenance: ContentProvenance,
) -> Bool {
  case coding, provenance {
    Identity, _ -> True
    _, PublicContent | _, ConfidentialContent | _, AttackerControlledContent ->
      True
    _, MixedConfidentialAndAttackerControlled | _, UnknownProvenance -> False
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
      decode_ffi(3, input, <<>>, limits)
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
      decode_ffi(3, stream, dictionary, limits)
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
/// Unknown parameters are fully parsed, then ignored on recognized members;
/// unknown dictionary members retain their values and parameters as extensions.
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
    Ok(structured_fields.Item(
      structured_fields.ByteSequence(value),
      _parameters,
    )) ->
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
    Ok(structured_fields.Item(structured_fields.StringValue(value), _parameters)) ->
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
  use _ <- result.try(validate_origin(origin))
  insert_dictionary_from_url(
    store:,
    isolation_key:,
    dictionary_url: origin <> "/",
    directive:,
    content:,
    fresh_until:,
    fetched_at:,
  )
}

/// Insert a dictionary fetched from a complete HTTPS URL.
/// The match pattern is validated with that URL as its constructor base.
/// Only its canonical origin and the original match pattern are retained; the URL is not retained.
/// Existing entry, byte, freshness and work ceilings still apply.
pub fn insert_dictionary_from_url(
  store store: Store,
  isolation_key isolation_key: IsolationKey,
  dictionary_url dictionary_url: String,
  directive directive: UseAsDictionary,
  content content: BitArray,
  fresh_until fresh_until: Int,
  fetched_at fetched_at: Int,
) -> Result(Store, Error) {
  use _ <- result.try(validate_isolation(isolation_key))
  use base <- result.try(secure_url(dictionary_url))
  let origin = url.origin(base)
  use _ <- result.try(validate_directive(directive))
  use _ <- result.try(
    pattern.compile(input: directive.match, base: base, work: 1_048_576)
    |> result.map_error(pattern_error),
  )
  use _ <- result.try(case directive.dictionary_type {
    Raw -> Ok(Nil)
    ExtensionDictionaryType(_) -> Error(UnsupportedAlgorithm)
  })
  use _ <- result.try(aligned(content))
  use _ <- result.try(
    case
      bit_array.byte_size(content) > 0
      && fetched_at >= -9_223_372_036_854_775_808
      && fresh_until <= 9_223_372_036_854_775_807
      && fresh_until > fetched_at
    {
      True -> Ok(Nil)
      False -> Error(InvalidDictionary)
    },
  )
  let retained =
    bit_array.byte_size(content)
    + string.byte_size(isolation_key.top_level_site)
    + string.byte_size(isolation_key.profile)
    + string.byte_size(origin)
    + string.byte_size(directive.match)
    + string.byte_size(directive.identifier)
    + destination_bytes(directive.destinations, 0)
    // Fixed tuples, list links, seven binary headers, digest bytes, alignment and two signed 64-bit clock values fit in this prepaid allowance.
    + 1024
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
  let store = remove_same_dictionary(store, isolation_key, origin, hash)
  let store = reserve_dictionary(store, retained)
  let entry =
    Dictionary(
      IsolationKey(
        retain_string(isolation_key.top_level_site),
        retain_string(isolation_key.profile),
      ),
      retain_string(origin),
      retain_string(directive.match),
      list.map(directive.destinations, retain_string),
      retain_string(directive.identifier),
      directive.dictionary_type,
      retain_bytes(content),
      hash,
      fresh_until,
      fetched_at,
      retained,
    )
  Ok(
    Store(..store, retained_bytes: store.retained_bytes + retained, entries: [
      entry,
      ..store.entries
    ]),
  )
}

/// Select the best fresh same-origin dictionary in one isolation partition.
/// The caller supports request destinations; an empty string is the actual
/// empty Fetch destination. Use `select_dictionary_for_request` when the
/// caller does not implement request destinations.
pub fn select_dictionary(
  store: Store,
  isolation_key: IsolationKey,
  origin origin: String,
  path path: String,
  destination destination: String,
  now now: Int,
) -> Result(Dictionary, Error) {
  select_dictionary_for_request(
    store,
    isolation_key,
    origin:,
    path:,
    destination: SupportedDestination(destination),
    now:,
  )
}

/// Select using an explicit request-destination capability.
/// Unsupported destinations ignore `match-dest` for both matching and precedence; path specificity, freshness, origin, partition and recency still apply.
pub fn select_dictionary_for_request(
  store: Store,
  isolation_key: IsolationKey,
  origin origin: String,
  path path: String,
  destination destination: DestinationCapability,
  now now: Int,
) -> Result(Dictionary, Error) {
  use _ <- result.try(validate_origin(origin))
  use _ <- result.try(case valid_path(path) {
    True -> Ok(Nil)
    False -> Error(InvalidDictionary)
  })
  select_dictionary_for_url(
    store,
    isolation_key,
    request_url: origin <> path,
    destination:,
    now:,
  )
}

/// Select against a complete HTTPS request URL.
/// RFC 9842 matching constructs each pattern with the outgoing URL as its base, after canonical same-origin and partition checks.
/// All candidates share one finite work allowance.
/// The caller supplies `now` in the same signed 64-bit clock domain and units as admission.
/// Records are eligible from `fetched_at` through, but excluding,
/// `fresh_until`.
/// This store does not derive age from HTTP cache headers.
pub fn select_dictionary_for_url(
  store: Store,
  isolation_key: IsolationKey,
  request_url request_url: String,
  destination destination: DestinationCapability,
  now now: Int,
) -> Result(Dictionary, Error) {
  use _ <- result.try(validate_isolation(isolation_key))
  use _ <- result.try(
    case now >= -9_223_372_036_854_775_808 && now <= 9_223_372_036_854_775_807 {
      True -> Ok(Nil)
      False -> Error(InvalidDictionary)
    },
  )
  use request <- result.try(secure_url(request_url))
  let valid_destination = case destination {
    SupportedDestination(value) -> safe_text(value)
    DestinationsUnsupported -> True
  }
  use _ <- result.try(case valid_destination {
    True -> Ok(Nil)
    False -> Error(InvalidDictionary)
  })
  use selected <- result.try(select_entry(
    store.entries,
    isolation_key,
    url.origin(request),
    request,
    destination,
    now,
    None,
    8_388_608,
  ))
  case selected {
    Some(value) -> Ok(value)
    None -> Error(NoMatchingDictionary)
  }
}

/// Return a store with dictionaries in the requested scope removed, preserving its entry and byte ceilings.
/// Partition/profile clearing visits each existing entry once; clearing all drops this value's entries immediately.
///
/// Replace the authoritative store with the returned value.
/// Older immutable stores and already selected dictionaries remain usable while callers retain them.
/// This function is not connected to a client's cookie lifecycle.
pub fn clear_dictionaries(
  store: Store,
  scope scope: DictionaryClearScope,
) -> Result(Store, Error) {
  case scope {
    AllDictionaries -> Ok(Store(..store, retained_bytes: 0, entries: []))
    PartitionDictionaries(key) -> {
      use _ <- result.try(validate_isolation(key))
      Ok(clear_matching(store, fn(entry) { entry.isolation_key == key }))
    }
    ProfileDictionaries(profile) -> {
      use _ <- result.try(case valid_isolation_component(profile) {
        True -> Ok(Nil)
        False -> Error(InvalidDictionary)
      })
      Ok(
        clear_matching(store, fn(entry) {
          entry.isolation_key.profile == profile
        }),
      )
    }
  }
}

fn clear_matching(store: Store, remove: fn(Dictionary) -> Bool) -> Store {
  let #(entries, retained) = retain_uncleared(store.entries, remove, [], 0)
  Store(..store, retained_bytes: retained, entries: entries)
}

fn retain_uncleared(
  entries: List(Dictionary),
  remove: fn(Dictionary) -> Bool,
  reversed: List(Dictionary),
  retained: Int,
) -> #(List(Dictionary), Int) {
  case entries {
    [] -> #(list.reverse(reversed), retained)
    [entry, ..rest] ->
      case remove(entry) {
        True -> retain_uncleared(rest, remove, reversed, retained)
        False ->
          retain_uncleared(
            rest,
            remove,
            [entry, ..reversed],
            retained + entry.retained_bytes,
          )
      }
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
    Error(5) -> Error(UnsupportedBrotliStream)
    Error(_) -> Error(InvalidEncoding)
  }
}

fn encode_brotli(input: BitArray, limits: Limits) -> Result(BitArray, Error) {
  // An empty metadata block aligns the following stored blocks.
  // Small windows use the seven-bit WBITS form; the default retains WBITS=16.
  let #(empty, prefix) = case limits.maximum_window_log < 16 {
    True -> {
      let window = 1 + { limits.maximum_window_log - 8 } * 16
      let final_window = window + 128
      #(<<final_window, 1>>, <<window, 3>>)
    }
    False -> #(<<6>>, <<12>>)
  }
  case input {
    <<>> -> Ok(empty)
    _ -> {
      use chunks <- result.try(
        encode_brotli_chunks(input, limits.maximum_work_units, []),
      )
      Ok(bit_array.concat([prefix, ..list.append(chunks, [<<3>>])]))
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
            _parameters,
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
        "match-dest", structured_fields.InnerList(items, _parameters) -> {
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
            _parameters,
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
            _parameters,
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
    [
      structured_fields.Item(structured_fields.StringValue(value), _parameters),
      ..rest
    ] -> parse_destinations(rest, [value, ..reversed])
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

fn valid_pattern(value: String) -> Bool {
  case string.byte_size(value) <= 2048 && safe_text(value) {
    False -> False
    True -> {
      // Header parsing has no response URL.
      // A concrete caller context is checked again at insertion; this base only checks pattern syntax.
      let base =
        url.Url(
          "https",
          "",
          "",
          "dictionary.invalid",
          "",
          "/",
          "",
          "",
          False,
          False,
          False,
        )
      result.is_ok(pattern.compile(input: value, base: base, work: 1_048_576))
    }
  }
}

fn valid_destinations(destinations: List(String)) -> Bool {
  case destinations {
    [] -> True
    [destination, ..rest] ->
      case string.byte_size(destination) <= 64 && safe_text(destination) {
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
    valid_isolation_component(key.top_level_site)
    && valid_isolation_component(key.profile)
  {
    True -> Ok(Nil)
    False -> Error(InvalidDictionary)
  }
}

fn validate_origin(origin: String) -> Result(Nil, Error) {
  use _ <- result.try(
    case
      string.starts_with(origin, "https://")
      && string.length(origin) > string.length("https://")
      && string.byte_size(origin) <= 2048
      && safe_text(origin)
    {
      True -> Ok(Nil)
      False -> Error(InvalidDictionary)
    },
  )
  use parsed <- result.try(
    url.parse(origin) |> result.map_error(fn(_) { InvalidDictionary }),
  )
  let authority = string.drop_start(origin, 8)
  case
    parsed.protocol == "https"
    && !parsed.has_userinfo
    && !parsed.has_query
    && !parsed.has_fragment
    && !string.contains(authority, "/")
    && !string.contains(authority, "\\")
  {
    True -> Ok(Nil)
    False -> Error(InvalidDictionary)
  }
}

fn secure_url(value: String) -> Result(url.Url, Error) {
  use _ <- result.try(
    case string.byte_size(value) <= 10_240 && safe_text(value) {
      True -> Ok(Nil)
      False -> Error(InvalidDictionary)
    },
  )
  use parsed <- result.try(url.parse(value) |> result.map_error(pattern_error))
  case
    parsed.protocol == "https" && string.byte_size(url.origin(parsed)) <= 2048
  {
    True -> Ok(parsed)
    False -> Error(InvalidDictionary)
  }
}

fn valid_isolation_component(value: String) -> Bool {
  value != "" && string.byte_size(value) <= 1024 && safe_text(value)
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
    [value, ..rest] ->
      destination_bytes(rest, total + string.byte_size(value) + 96)
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

fn reserve_dictionary(store: Store, incoming: Int) -> Store {
  let #(entries, retained) =
    retain_newest(
      store.entries,
      store.maximum_entries - 1,
      store.maximum_bytes - incoming,
      [],
      0,
    )
  Store(..store, retained_bytes: retained, entries: entries)
}

// Keep the newest prefix in one traversal.
// Repeatedly removing the last entry would perform quadratic work when one large insertion evicts many.
fn retain_newest(
  entries: List(Dictionary),
  remaining_entries: Int,
  remaining_bytes: Int,
  reversed: List(Dictionary),
  retained: Int,
) -> #(List(Dictionary), Int) {
  case entries, remaining_entries {
    [], _ | _, 0 -> #(list.reverse(reversed), retained)
    [entry, ..rest], _ ->
      case entry.retained_bytes <= remaining_bytes {
        False -> #(list.reverse(reversed), retained)
        True ->
          retain_newest(
            rest,
            remaining_entries - 1,
            remaining_bytes - entry.retained_bytes,
            [entry, ..reversed],
            retained + entry.retained_bytes,
          )
      }
  }
}

// Admission precedes these copies.
// A short sub-binary must not retain a large caller-owned allocation whose size is absent from the store's accounting.
@external(erlang, "http_compression_ffi", "retain_bytes")
fn retain_string(value: String) -> String

@external(erlang, "http_compression_ffi", "retain_bytes")
fn retain_bytes(value: BitArray) -> BitArray

fn select_entry(
  entries: List(Dictionary),
  isolation_key: IsolationKey,
  origin: String,
  request: url.Url,
  destination: DestinationCapability,
  now: Int,
  selected: Option(Dictionary),
  work: Int,
) -> Result(Option(Dictionary), Error) {
  case entries {
    [] -> Ok(selected)
    _ if work <= 0 -> Error(LimitExceeded)
    [entry, ..rest] -> {
      let eligible =
        entry.isolation_key == isolation_key
        && entry.origin == origin
        && entry.fetched_at <= now
        && entry.fresh_until > now
        && destination_matches(entry.destinations, destination)
      use #(matches, work) <- result.try(case eligible {
        False -> Ok(#(False, work - 1))
        True -> pattern_matches(entry.match, request, work - 1)
      })
      let selected = case matches, selected {
        False, _ -> selected
        True, None -> Some(entry)
        True, Some(current) ->
          case preferred(entry, current, destination) {
            True -> Some(entry)
            False -> selected
          }
      }
      select_entry(
        rest,
        isolation_key,
        origin,
        request,
        destination,
        now,
        selected,
        work,
      )
    }
  }
}

fn destination_matches(
  destinations: List(String),
  destination: DestinationCapability,
) -> Bool {
  case destination {
    DestinationsUnsupported -> True
    SupportedDestination(value) ->
      case destinations {
        [] -> True
        _ -> list.contains(destinations, value)
      }
  }
}

fn preferred(
  candidate: Dictionary,
  current: Dictionary,
  capability: DestinationCapability,
) -> Bool {
  let supported = capability != DestinationsUnsupported
  let candidate_specific = supported && candidate.destinations != []
  let current_specific = supported && current.destinations != []
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

fn pattern_matches(
  value: String,
  request: url.Url,
  work: Int,
) -> Result(#(Bool, Int), Error) {
  use #(compiled, remaining) <- result.try(
    pattern.compile(input: value, base: request, work: work)
    |> result.map_error(pattern_error),
  )
  pattern.matches(compiled: compiled, input: request, work: remaining)
  |> result.map_error(pattern_error)
}

fn pattern_error(error: component.Error) -> Error {
  case error {
    component.InvalidPattern -> InvalidDictionary
    component.WorkLimitExceeded -> LimitExceeded
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
