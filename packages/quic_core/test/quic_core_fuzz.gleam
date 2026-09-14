import fuzz_corpus

pub fn main() -> Nil {
  assert fuzz_corpus.exercise(10_000) == 10_016
}
