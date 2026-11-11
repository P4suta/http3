//// Fixed-seed discovery entrypoints for independent protocol and lifetime models.
//// Extended source-bound campaigns use scripts/http_models.escript.

import gleeunit

type ModelSummary {
  ModelSummary(cases: Int, transitions: Int, digest: String)
}

type ModelFailure {
  ModelFailure(case_index: Int, seed: Int, step: Int, invariant: Int)
}

@external(erlang, "http_models_ffi", "run")
fn run(
  domain: String,
  seed: Int,
  cases: Int,
) -> Result(ModelSummary, ModelFailure)

@external(erlang, "http_models_ffi", "self_test")
fn self_test() -> Nil

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn model_harness_is_bounded_and_reproducible_test() -> Nil {
  self_test()
  assert run("unknown", 0, 1) == Error(ModelFailure(0, 0, 0, 901))
}

pub fn http1_framing_matches_independent_message_boundaries_test() -> Nil {
  let assert Ok(ModelSummary(64, transitions, _)) = run("http1", 104_729, 64)
  assert transitions >= 64
}

pub fn http2_stream_halves_and_flow_credit_match_independent_ledgers_test() -> Nil {
  let assert Ok(ModelSummary(64, 4096, _)) = run("http2", 130_363, 64)
  Nil
}

pub fn hpack_residency_matches_independent_fifo_test() -> Nil {
  let assert Ok(ModelSummary(64, 2048, _)) = run("hpack", 155_921, 64)
  Nil
}

pub fn pool_admission_and_reuse_match_independent_lease_ledger_test() -> Nil {
  let assert Ok(ModelSummary(16, 560, _)) = run("pool", 181_081, 16)
  Nil
}

pub fn cancellation_matches_independent_subscription_set_test() -> Nil {
  let assert Ok(ModelSummary(16, 528, _)) = run("cancellation", 206_369, 16)
  Nil
}

pub fn drain_waits_for_independently_counted_response_owners_test() -> Nil {
  let assert Ok(ModelSummary(16, transitions, _)) = run("drain", 231_701, 16)
  assert transitions >= 80
}
