import gleam/bit_array
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/handshake
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/pre_shared_key

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_psk_modes_and_offers_test() -> Nil {
  let modes = [pre_shared_key.PskDheKe, pre_shared_key.PskKe]
  let assert Ok(encoded_modes) = pre_shared_key.encode_modes(modes)
  assert encoded_modes == <<2, 1, 0>>
  assert pre_shared_key.decode_modes(encoded_modes) == Ok(modes)

  let offered =
    pre_shared_key.Offered(
      identities: [
        pre_shared_key.Identity(<<"ticket-a">>, 0x01020304),
        pre_shared_key.Identity(<<"ticket-b">>, 0xffff_ffff),
      ],
      binders: [<<0xaa:256>>, <<0xbb:384>>],
    )
  let assert Ok(encoded) = pre_shared_key.encode_offered(offered)
  assert pre_shared_key.decode_offered(encoded) == Ok(offered)

  assert pre_shared_key.encode_selected_identity(7) == Ok(<<0, 7>>)
  assert pre_shared_key.decode_selected_identity(<<0, 7>>) == Ok(7)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_malformed_or_ambiguous_psk_extensions_test() -> Nil {
  assert pre_shared_key.decode_modes(<<2, 1, 1>>)
    == Error(pre_shared_key.DuplicateMode(1))
  assert pre_shared_key.decode_modes(<<1, 2>>)
    == Error(pre_shared_key.InvalidMode(2))
  assert pre_shared_key.encode_offered(
      pre_shared_key.Offered(
        identities: [pre_shared_key.Identity(<<>>, 0)],
        binders: [<<0:256>>],
      ),
    )
    == Error(pre_shared_key.InvalidIdentity)
  assert pre_shared_key.encode_offered(
      pre_shared_key.Offered(
        identities: [pre_shared_key.Identity(<<"ticket">>, 0)],
        binders: [<<0:248>>],
      ),
    )
    == Error(pre_shared_key.InvalidBinder)
  assert pre_shared_key.encode_offered(
      pre_shared_key.Offered(
        identities: [pre_shared_key.Identity(<<"ticket">>, 0)],
        binders: [],
      ),
    )
    == Error(pre_shared_key.MismatchedBinders)
  assert pre_shared_key.decode_offered(<<0, 0, 0, 0>>)
    == Error(pre_shared_key.InvalidLength)
  assert pre_shared_key.decode_selected_identity(<<0, 1, 2>>)
    == Error(pre_shared_key.InvalidLength)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn computes_binder_over_exact_truncated_client_hello_test() -> Nil {
  let placeholder = <<0:256>>
  let offered =
    pre_shared_key.Offered(
      identities: [pre_shared_key.Identity(<<"opaque-ticket">>, 42)],
      binders: [placeholder],
    )
  let assert Ok(encoded_offer) = pre_shared_key.encode_offered(offered)
  let client_hello =
    hello.ClientHello(
      random: <<1:256>>,
      legacy_session_id: <<>>,
      cipher_suites: [hello.Aes128GcmSha256],
      extensions: [
        extension.Extension(extension.SupportedVersions, <<2, 3, 4>>),
        extension.Extension(extension.PskKeyExchangeModes, <<1, 1>>),
        extension.Extension(extension.PreSharedKey, encoded_offer),
      ],
    )
  let assert Ok(body) =
    hello.encode_client(client_hello, hello.default_limits())
  let assert Ok(encoded_client_hello) =
    handshake.encode(handshake.Message(handshake.ClientHello, body), 65_535)

  let assert Ok(truncated) =
    pre_shared_key.binder_transcript(encoded_client_hello, offered)
  assert encoded_client_hello == <<truncated:bits, 0, 33, 32, placeholder:bits>>

  let psk = <<0x55:256>>
  let assert Ok(binder) =
    pre_shared_key.compute_binder(crypto.Sha256, psk, truncated, False)
  assert bit_array.byte_size(binder) == 32
  assert pre_shared_key.verify_binder(
      crypto.Sha256,
      psk,
      truncated,
      binder,
      False,
    )
    == Ok(True)
  assert pre_shared_key.verify_binder(
      crypto.Sha256,
      psk,
      <<truncated:bits, 0>>,
      binder,
      False,
    )
    == Ok(False)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn binder_transcript_rejects_non_suffix_or_non_aligned_input_test() -> Nil {
  let offered =
    pre_shared_key.Offered(
      identities: [pre_shared_key.Identity(<<"ticket">>, 0)],
      binders: [<<0:256>>],
    )
  assert pre_shared_key.binder_transcript(<<1, 2, 3>>, offered)
    == Error(pre_shared_key.BindersNotAtEnd)
  assert pre_shared_key.compute_binder(
      crypto.Sha256,
      <<0:256>>,
      <<1:size(1)>>,
      False,
    )
    == Error(pre_shared_key.NonByteAligned)
}
