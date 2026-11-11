import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import http3/internal/native/frame
import http3/internal/native/grease
import http3/internal/native/settings_memory
import http3/internal/varint

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn remembered_settings_encoding_is_canonical_and_bounded_test() -> Nil {
  let assert Ok(snapshot) =
    settings_memory.new(4096, 65_536, 16, True, True, [1, 6, 7, 8, 0x33])
  let assert Ok(encoded) = settings_memory.encode(snapshot)
  assert bit_array.byte_size(encoded) == 28
  assert settings_memory.decode(encoded) == Ok(snapshot)

  let assert <<_, tail:bits>> = encoded
  assert settings_memory.decode(<<2, tail:bits>>)
    == Error(settings_memory.InvalidEncoding)
  assert settings_memory.decode(<<encoded:bits, 0>>)
    == Error(settings_memory.InvalidEncoding)
  assert settings_memory.decode(<<1:1>>)
    == Error(settings_memory.InvalidEncoding)

  // An omitted understood setting cannot hide a non-default value.
  let hidden_qpack = <<
    1,
    0,
    1:size(64),
    varint.maximum:size(64),
    0:size(64),
    0,
    0,
  >>
  assert settings_memory.decode(hidden_qpack)
    == Error(settings_memory.InvalidEncoding)
  assert settings_memory.new(1, varint.maximum, 0, False, False, [])
    == Error(settings_memory.InvalidSnapshot)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn zero_rtt_compatibility_checks_limits_values_and_omission_test() -> Nil {
  let assert Ok(remembered) =
    settings_memory.new(4096, 1024, 16, True, True, [1, 6, 7, 8, 0x33])
  let assert Ok(larger) =
    settings_memory.new(8192, 2048, 32, True, True, [1, 6, 7, 8, 0x33])
  assert settings_memory.compatible(remembered, larger)

  let assert Ok(reduced_qpack) =
    settings_memory.new(4095, 2048, 32, True, True, [1, 6, 7, 8, 0x33])
  assert !settings_memory.compatible(remembered, reduced_qpack)
  let assert Ok(reduced_fields) =
    settings_memory.new(8192, 1023, 32, True, True, [1, 6, 7, 8, 0x33])
  assert !settings_memory.compatible(remembered, reduced_fields)
  let assert Ok(reduced_blocked) =
    settings_memory.new(8192, 2048, 15, True, True, [1, 6, 7, 8, 0x33])
  assert !settings_memory.compatible(remembered, reduced_blocked)
  let assert Ok(connect_disabled) =
    settings_memory.new(8192, 2048, 32, False, True, [1, 6, 7, 8, 0x33])
  assert !settings_memory.compatible(remembered, connect_disabled)
  let assert Ok(datagram_disabled) =
    settings_memory.new(8192, 2048, 32, True, False, [1, 6, 7, 8, 0x33])
  assert !settings_memory.compatible(remembered, datagram_disabled)

  let assert Ok(omitted_non_default) =
    settings_memory.new(8192, varint.maximum, 32, True, True, [1, 7, 8, 0x33])
  assert !settings_memory.compatible(remembered, omitted_non_default)
  // With no stored values the client uses RFC defaults.
  // In particular, the default field-section limit is unlimited, so a finite new limit is a reduction and cannot accompany accepted 0-RTT.
  assert !settings_memory.compatible(settings_memory.defaults(), larger)
  let assert Ok(explicit_defaults) =
    settings_memory.new(0, varint.maximum, 0, False, False, [1, 6, 7, 8, 0x33])
  assert settings_memory.compatible(
    settings_memory.defaults(),
    explicit_defaults,
  )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn grease_selection_is_reserved_bounded_and_injectable_test() -> Nil {
  assert grease.setting(False, 17) == None
  let assert Some(frame.Setting(first_identifier, first_value)) =
    grease.setting(True, 0)
  let assert Some(frame.Setting(repeated_identifier, repeated_value)) =
    grease.setting(True, 0)
  assert first_identifier == repeated_identifier
  assert first_value == repeated_value
  assert grease.is_reserved(first_identifier)

  let assert Some(frame.Setting(other_identifier, _)) = grease.setting(True, 1)
  assert grease.is_reserved(other_identifier)
  assert other_identifier != first_identifier
  let assert Some(frame.Setting(negative_identifier, negative_value)) =
    grease.setting(True, -1)
  assert grease.is_reserved(negative_identifier)
  assert negative_value >= 0 && negative_value <= varint.maximum

  let decisions =
    int.range(from: 0, to: 16, with: [], run: list.prepend)
    |> list.reverse
    |> list.map(grease.no_error_code)
  assert list.filter(decisions, grease.is_reserved) |> list.length == 2
  assert list.filter(decisions, fn(value) { value == 0x100 })
    |> list.length
    == 14
}
