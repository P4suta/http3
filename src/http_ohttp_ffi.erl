-module(http_ohttp_ffi).

-export([
    x25519_public/1,
    x25519_shared/2,
    random_bytes/1,
    hkdf_extract/2,
    hkdf_expand/3,
    aead_seal/4,
    aead_open/4,
    sha256/1
]).

-define(HASH_SIZE, 32).
-define(TAG_SIZE, 16).

-spec x25519_public(binary()) -> {ok, binary()} | {error, nil}.
x25519_public(PrivateKey)
    when is_binary(PrivateKey), byte_size(PrivateKey) =:= 32 ->
    with_crypto(fun() ->
        case crypto:generate_key(ecdh, x25519, PrivateKey) of
            {PublicKey, _}
                when is_binary(PublicKey), byte_size(PublicKey) =:= 32 ->
                PublicKey
        end
    end);
x25519_public(_) ->
    {error, nil}.

-spec x25519_shared(binary(), binary()) -> {ok, binary()} | {error, nil}.
x25519_shared(PrivateKey, <<0:256>>)
    when is_binary(PrivateKey), byte_size(PrivateKey) =:= 32 ->
    {error, nil};
x25519_shared(PrivateKey, PeerPublicKey)
    when is_binary(PrivateKey), byte_size(PrivateKey) =:= 32,
         is_binary(PeerPublicKey), byte_size(PeerPublicKey) =:= 32 ->
    with_crypto(fun() ->
        case crypto:compute_key(ecdh, PeerPublicKey, PrivateKey, x25519) of
            <<0:256>> -> erlang:error(invalid_shared_secret);
            Shared when is_binary(Shared), byte_size(Shared) =:= 32 -> Shared
        end
    end);
x25519_shared(_, _) ->
    {error, nil}.

-spec random_bytes(integer()) -> {ok, binary()} | {error, nil}.
random_bytes(Count) when is_integer(Count), Count > 0, Count =< 65536 ->
    with_crypto(fun() -> crypto:strong_rand_bytes(Count) end);
random_bytes(_) ->
    {error, nil}.

-spec hkdf_extract(binary(), binary()) -> {ok, binary()} | {error, nil}.
hkdf_extract(Salt, InputKeyMaterial)
    when is_binary(Salt), is_binary(InputKeyMaterial) ->
    with_crypto(fun() ->
        EffectiveSalt = case Salt of
            <<>> -> <<0:(?HASH_SIZE * 8)>>;
            _ -> Salt
        end,
        crypto:mac(hmac, sha256, EffectiveSalt, InputKeyMaterial)
    end);
hkdf_extract(_, _) ->
    {error, nil}.

-spec hkdf_expand(binary(), binary(), integer()) ->
    {ok, binary()} | {error, nil}.
hkdf_expand(PseudorandomKey, Info, Length)
    when is_binary(PseudorandomKey), is_binary(Info),
         is_integer(Length), Length >= 0, Length =< 255 * ?HASH_SIZE ->
    with_crypto(fun() ->
        Blocks = (Length + ?HASH_SIZE - 1) div ?HASH_SIZE,
        Material = hkdf_blocks(PseudorandomKey, Info, Blocks, 1, <<>>, []),
        binary:part(iolist_to_binary(lists:reverse(Material)), 0, Length)
    end);
hkdf_expand(_, _, _) ->
    {error, nil}.

-spec hkdf_blocks(binary(), binary(), non_neg_integer(), pos_integer(), binary(),
                  [binary()]) -> [binary()].
hkdf_blocks(_Key, _Info, 0, _Index, _Previous, Accumulator) ->
    Accumulator;
hkdf_blocks(Key, Info, Remaining, Index, Previous, Accumulator) ->
    Block = crypto:mac(hmac, sha256, Key, <<Previous/binary, Info/binary, Index:8>>),
    hkdf_blocks(Key, Info, Remaining - 1, Index + 1, Block,
                [Block | Accumulator]).

-spec aead_seal(integer(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, nil}.
aead_seal(Algorithm, Key, Nonce, Plaintext)
    when is_integer(Algorithm), is_binary(Key), is_binary(Nonce),
         is_binary(Plaintext) ->
    case cipher(Algorithm, Key, Nonce) of
        {ok, Cipher} ->
            with_crypto(fun() ->
                {Ciphertext, Tag} = crypto:crypto_one_time_aead(
                    Cipher, Key, Nonce, Plaintext, <<>>, ?TAG_SIZE, true
                ),
                <<Ciphertext/binary, Tag/binary>>
            end);
        error ->
            {error, nil}
    end;
aead_seal(_, _, _, _) ->
    {error, nil}.

-spec aead_open(integer(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, nil}.
aead_open(Algorithm, Key, Nonce, Protected)
    when is_integer(Algorithm), is_binary(Key), is_binary(Nonce),
         is_binary(Protected), byte_size(Protected) >= ?TAG_SIZE ->
    case cipher(Algorithm, Key, Nonce) of
        {ok, Cipher} ->
            CiphertextSize = byte_size(Protected) - ?TAG_SIZE,
            <<Ciphertext:CiphertextSize/binary, Tag:?TAG_SIZE/binary>> = Protected,
            with_crypto(fun() ->
                case crypto:crypto_one_time_aead(
                    Cipher, Key, Nonce, Ciphertext, <<>>, Tag, false
                ) of
                    Plaintext when is_binary(Plaintext) -> Plaintext;
                    error -> erlang:error(authentication_failed)
                end
            end);
        error ->
            {error, nil}
    end;
aead_open(_, _, _, _) ->
    {error, nil}.

-spec sha256(binary()) -> {ok, binary()} | {error, nil}.
sha256(Input) when is_binary(Input) ->
    with_crypto(fun() -> crypto:hash(sha256, Input) end);
sha256(_) ->
    {error, nil}.

-spec cipher(integer(), binary(), binary()) ->
    {ok, aes_128_gcm | chacha20_poly1305} | error.
cipher(1, Key, Nonce) when byte_size(Key) =:= 16, byte_size(Nonce) =:= 12 ->
    {ok, aes_128_gcm};
cipher(3, Key, Nonce) when byte_size(Key) =:= 32, byte_size(Nonce) =:= 12 ->
    {ok, chacha20_poly1305};
cipher(_, _, _) ->
    error.

-spec with_crypto(fun(() -> binary())) -> {ok, binary()} | {error, nil}.
with_crypto(Operation) ->
    case application:ensure_all_started(crypto) of
        {ok, _} ->
            try Operation() of
                Value when is_binary(Value) -> {ok, Value}
            catch
                _:_ -> {error, nil}
            end;
        {error, _} ->
            {error, nil}
    end.
