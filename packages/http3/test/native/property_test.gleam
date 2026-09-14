import native/property_corpus

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn generated_wire_codec_round_trips_property_test() -> Nil {
  assert property_corpus.exercise(512) == 512
}
