import http3/internal/qpack/field_section
import http3/internal/qpack/string_literal

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_every_field_line_representation_test() -> Nil {
  let section =
    field_section.Section(field_section.Prefix(6, False, 5), [
      field_section.Indexed(True, 17),
      field_section.Indexed(False, 2),
      field_section.IndexedPostBase(1),
      field_section.LiteralNameReference(False, True, 4, <<"10">>),
      field_section.LiteralNameReference(True, False, 0, <<"secret">>),
      field_section.LiteralPostBaseNameReference(False, 1, <<"later">>),
      field_section.LiteralLiteralName(True, <<"custom-key">>, <<
        "custom-value",
      >>),
    ])
  let assert Ok(encoded) = field_section.encode(section, True)
  assert field_section.decode(encoded, field_section.default_limits())
    == Ok(section)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_field_and_string_bounds_test() -> Nil {
  let section =
    field_section.Section(field_section.Prefix(0, True, 0), [
      field_section.LiteralLiteralName(False, <<"a">>, <<"1">>),
      field_section.LiteralLiteralName(False, <<"b">>, <<"2">>),
    ])
  let assert Ok(encoded) = field_section.encode(section, False)
  assert field_section.decode(encoded, field_section.Limits(1, 64, 64))
    == Error(field_section.FieldLimitExceeded(1))
  assert field_section.decode(encoded, field_section.Limits(8, 0, 64))
    == Error(
      field_section.StringFailure(string_literal.EncodedLengthLimitExceeded(0)),
    )
}
