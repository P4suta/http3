//// EUnit descriptors keep the imported corpus in ordinary gleeunit discovery and package coverage, with one named finite timeout per independent case.

pub type ContractTests

// nolint: trailing_underscore -- EUnit requires the descriptor generator suffix.
@external(erlang, "http_brotli_test", "contracts")
pub fn brotli_decoder_contracts_test_() -> ContractTests
