import native/fuzz_corpus

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retained_and_generated_parser_corpus_never_panics_test() -> Nil {
  assert fuzz_corpus.exercise(512) == 528
}
