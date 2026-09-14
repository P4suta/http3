import quic_core/internal/address_token
import quic_core/internal/stateless_reset
import quic_core/version

const token_key = <<
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
  0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
>>

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_address_token_from_another_quic_version_test() -> Nil {
  let address = <<127, 0, 0, 1>>
  let nonce = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11>>
  let assert Ok(token) =
    address_token.seal_with_nonce(
      token_key,
      address_token.NewToken,
      version.Version1,
      address,
      4433,
      <<>>,
      <<>>,
      1000,
      nonce,
    )
  assert address_token.open(
      token_key,
      token,
      version.Version1,
      address,
      4433,
      1050,
      100,
    )
    == Ok(address_token.Token(address_token.NewToken, <<>>, <<>>, 1000))
  assert address_token.open(
      token_key,
      token,
      version.Version2,
      address,
      4433,
      1050,
      100,
    )
    == Error(address_token.VersionMismatch)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn seals_expiring_address_bound_retry_tokens_test() -> Nil {
  let address = <<127, 0, 0, 1>>
  let assert Ok(fresh) =
    address_token.seal(
      token_key,
      address_token.NewToken,
      version.Version1,
      address,
      4433,
      <<>>,
      <<>>,
      1000,
    )
  assert address_token.open(
      token_key,
      fresh,
      version.Version1,
      address,
      4433,
      1000,
      100,
    )
    == Ok(address_token.Token(address_token.NewToken, <<>>, <<>>, 1000))
  assert address_token.open(
      token_key,
      fresh,
      version.Version1,
      address,
      4434,
      1000,
      100,
    )
    == Ok(address_token.Token(address_token.NewToken, <<>>, <<>>, 1000))
  let nonce = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11>>
  let assert Ok(token) =
    address_token.seal_with_nonce(
      token_key,
      address_token.Retry,
      version.Version1,
      address,
      4433,
      <<9, 8, 7, 6, 5, 4, 3, 2>>,
      <<1, 2, 3, 4, 5, 6, 7, 8>>,
      1000,
      nonce,
    )
  assert address_token.open(
      token_key,
      token,
      version.Version1,
      address,
      4433,
      1050,
      100,
    )
    == Ok(address_token.Token(
      address_token.Retry,
      <<9, 8, 7, 6, 5, 4, 3, 2>>,
      <<1, 2, 3, 4, 5, 6, 7, 8>>,
      1000,
    ))
  assert address_token.open(
      token_key,
      token,
      version.Version1,
      <<127, 0, 0, 2>>,
      4433,
      1050,
      100,
    )
    == Error(address_token.AddressMismatch)
  assert address_token.open(
      token_key,
      token,
      version.Version1,
      address,
      4434,
      1050,
      100,
    )
    == Error(address_token.AddressMismatch)
  assert address_token.open(
      token_key,
      token,
      version.Version1,
      address,
      4433,
      1101,
      100,
    )
    == Error(address_token.Expired)

  let assert <<first, rest:bits>> = token
  let changed = first + 1
  let tampered = <<changed, rest:bits>>
  assert address_token.open(
      token_key,
      tampered,
      version.Version1,
      address,
      4433,
      1050,
      100,
    )
    == Error(address_token.AuthenticationFailed)

  assert address_token.seal_with_nonce(
      token_key,
      address_token.Retry,
      version.Version1,
      address,
      4433,
      <<1, 2, 3, 4>>,
      <<1, 2, 3, 4, 5, 6, 7, 8>>,
      1000,
      nonce,
    )
    == Error(address_token.InvalidInput)
  assert address_token.seal_with_nonce(
      token_key,
      address_token.NewToken,
      version.Version1,
      address,
      4433,
      <<1, 2, 3, 4, 5, 6, 7, 8>>,
      <<>>,
      1000,
      nonce,
    )
    == Error(address_token.InvalidInput)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn derives_and_compares_connection_bound_reset_tokens_test() -> Nil {
  let assert Ok(first) = stateless_reset.token_for(token_key, <<1, 2, 3, 4>>)
  let assert Ok(same) = stateless_reset.token_for(token_key, <<1, 2, 3, 4>>)
  let assert Ok(other) = stateless_reset.token_for(token_key, <<1, 2, 3, 5>>)
  assert first == same
  assert first != other
  assert stateless_reset.matches(first, same) == Ok(True)
  assert stateless_reset.matches(first, other) == Ok(False)
  assert stateless_reset.token_for(<<1>>, <<1>>)
    == Error(stateless_reset.InvalidSecret)
}
