-module(gleam_quic_crypto_ffi).

-export([
    aes_128_ecb_encrypt/2,
    aes_128_gcm_decrypt/4,
    aes_128_gcm_encrypt/4,
    aes_256_ecb_encrypt/2,
    aes_256_gcm_decrypt/4,
    aes_256_gcm_encrypt/4,
    chacha20_header_mask/2,
    chacha20_poly1305_decrypt/4,
    chacha20_poly1305_encrypt/4,
    hash_sha256/1,
    hash_sha384/1,
    hmac_sha256/2,
    hmac_sha384/2,
    secure_random/1,
    x25519_generate/0,
    x25519_public/1,
    x25519_shared/2
]).

-spec hash_sha256(binary()) -> {ok, binary()} | {error, 1 | 2}.
hash_sha256(Data) when is_binary(Data) ->
    with_crypto(fun() -> crypto:hash(sha256, Data) end);
hash_sha256(_Data) ->
    {error, 1}.

-spec hash_sha384(binary()) -> {ok, binary()} | {error, 1 | 2}.
hash_sha384(Data) when is_binary(Data) ->
    with_crypto(fun() -> crypto:hash(sha384, Data) end);
hash_sha384(_Data) ->
    {error, 1}.

-spec hmac_sha256(binary(), binary()) -> {ok, binary()} | {error, 1 | 2}.
hmac_sha256(Key, Data) when is_binary(Key), is_binary(Data) ->
    with_crypto(fun() -> crypto:mac(hmac, sha256, Key, Data) end);
hmac_sha256(_Key, _Data) ->
    {error, 1}.

-spec hmac_sha384(binary(), binary()) -> {ok, binary()} | {error, 1 | 2}.
hmac_sha384(Key, Data) when is_binary(Key), is_binary(Data) ->
    with_crypto(fun() -> crypto:mac(hmac, sha384, Key, Data) end);
hmac_sha384(_Key, _Data) ->
    {error, 1}.

-spec secure_random(integer()) -> {ok, binary()} | {error, 1 | 2}.
secure_random(Length) when is_integer(Length), Length >= 0, Length =< 65535 ->
    with_crypto(fun() -> crypto:strong_rand_bytes(Length) end);
secure_random(_Length) ->
    {error, 1}.

-spec x25519_generate() -> {ok, {binary(), binary()}} | {error, 2}.
x25519_generate() ->
    case ensure_crypto() of
        ok ->
            try crypto:generate_key(ecdh, x25519) of
                {PublicKey, PrivateKey}
                    when is_binary(PublicKey), byte_size(PublicKey) =:= 32,
                         is_binary(PrivateKey), byte_size(PrivateKey) =:= 32 ->
                    {ok, {PublicKey, PrivateKey}};
                _Other ->
                    {error, 2}
            catch
                _Class:_Reason -> {error, 2}
            end;
        error ->
            {error, 2}
    end.

-spec x25519_public(binary()) -> {ok, binary()} | {error, 1 | 2}.
x25519_public(PrivateKey)
    when is_binary(PrivateKey), byte_size(PrivateKey) =:= 32 ->
    case ensure_crypto() of
        ok ->
            try crypto:generate_key(ecdh, x25519, PrivateKey) of
                {PublicKey, _PrivateKey}
                    when is_binary(PublicKey), byte_size(PublicKey) =:= 32 ->
                    {ok, PublicKey};
                _Other ->
                    {error, 2}
            catch
                _Class:_Reason -> {error, 2}
            end;
        error ->
            {error, 2}
    end;
x25519_public(_PrivateKey) ->
    {error, 1}.

-spec x25519_shared(binary(), binary()) -> {ok, binary()} | {error, 1 | 2 | 4}.
x25519_shared(PrivateKey, <<0:256>>)
    when is_binary(PrivateKey), byte_size(PrivateKey) =:= 32 ->
    {error, 4};
x25519_shared(PrivateKey, PeerPublicKey)
    when is_binary(PrivateKey), byte_size(PrivateKey) =:= 32,
         is_binary(PeerPublicKey), byte_size(PeerPublicKey) =:= 32 ->
    case ensure_crypto() of
        ok ->
            try crypto:compute_key(ecdh, PeerPublicKey, PrivateKey, x25519) of
                <<0:256>> -> {error, 4};
                SharedSecret
                    when is_binary(SharedSecret), byte_size(SharedSecret) =:= 32 ->
                    {ok, SharedSecret};
                _Other ->
                    {error, 2}
            catch
                error:_Reason -> {error, 4};
                _Class:_Reason -> {error, 2}
            end;
        error ->
            {error, 2}
    end;
x25519_shared(_PrivateKey, _PeerPublicKey) ->
    {error, 1}.

-spec aes_128_ecb_encrypt(binary(), binary()) -> {ok, binary()} | {error, 1 | 2}.
aes_128_ecb_encrypt(Key, Block)
    when is_binary(Key), byte_size(Key) =:= 16,
         is_binary(Block), byte_size(Block) =:= 16 ->
    with_crypto(fun() -> crypto:crypto_one_time(aes_128_ecb, Key, Block, true) end);
aes_128_ecb_encrypt(_Key, _Block) ->
    {error, 1}.

-spec aes_256_ecb_encrypt(binary(), binary()) -> {ok, binary()} | {error, 1 | 2}.
aes_256_ecb_encrypt(Key, Block)
    when is_binary(Key), byte_size(Key) =:= 32,
         is_binary(Block), byte_size(Block) =:= 16 ->
    with_crypto(fun() -> crypto:crypto_one_time(aes_256_ecb, Key, Block, true) end);
aes_256_ecb_encrypt(_Key, _Block) ->
    {error, 1}.

-spec chacha20_header_mask(binary(), binary()) -> {ok, binary()} | {error, 1 | 2}.
chacha20_header_mask(Key, Sample)
    when is_binary(Key), byte_size(Key) =:= 32,
         is_binary(Sample), byte_size(Sample) =:= 16 ->
    with_crypto(fun() -> crypto:crypto_one_time(chacha20, Key, Sample, <<0:40>>, true) end);
chacha20_header_mask(_Key, _Sample) ->
    {error, 1}.

-spec aes_128_gcm_encrypt(binary(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, 1 | 2}.
aes_128_gcm_encrypt(Key, Nonce, AssociatedData, Plaintext)
    when is_binary(Key), byte_size(Key) =:= 16,
         is_binary(Nonce), byte_size(Nonce) =:= 12,
         is_binary(AssociatedData), is_binary(Plaintext) ->
    case ensure_crypto() of
        ok ->
            try crypto:crypto_one_time_aead(
                aes_128_gcm,
                Key,
                Nonce,
                Plaintext,
                AssociatedData,
                16,
                true
            ) of
                {Ciphertext, Tag} when is_binary(Ciphertext), byte_size(Tag) =:= 16 ->
                    {ok, <<Ciphertext/binary, Tag/binary>>};
                _Other ->
                    {error, 2}
            catch
                _Class:_Reason -> {error, 2}
            end;
        error ->
            {error, 2}
    end;
aes_128_gcm_encrypt(_Key, _Nonce, _AssociatedData, _Plaintext) ->
    {error, 1}.

-spec aes_128_gcm_decrypt(binary(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, 1 | 2 | 3}.
aes_128_gcm_decrypt(Key, Nonce, AssociatedData, Protected)
    when is_binary(Key), byte_size(Key) =:= 16,
         is_binary(Nonce), byte_size(Nonce) =:= 12,
         is_binary(AssociatedData), is_binary(Protected), byte_size(Protected) >= 16 ->
    CiphertextSize = byte_size(Protected) - 16,
    <<Ciphertext:CiphertextSize/binary, Tag:16/binary>> = Protected,
    case ensure_crypto() of
        ok ->
            try crypto:crypto_one_time_aead(
                aes_128_gcm,
                Key,
                Nonce,
                Ciphertext,
                AssociatedData,
                Tag,
                false
            ) of
                Plaintext when is_binary(Plaintext) -> {ok, Plaintext};
                error -> {error, 3};
                _Other -> {error, 2}
            catch
                _Class:_Reason -> {error, 2}
            end;
        error ->
            {error, 2}
    end;
aes_128_gcm_decrypt(_Key, _Nonce, _AssociatedData, _Protected) ->
    {error, 1}.

-spec aes_256_gcm_encrypt(binary(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, 1 | 2}.
aes_256_gcm_encrypt(Key, Nonce, AssociatedData, Plaintext)
    when is_binary(Key), byte_size(Key) =:= 32,
         is_binary(Nonce), byte_size(Nonce) =:= 12,
         is_binary(AssociatedData), is_binary(Plaintext) ->
    aead_encrypt(aes_256_gcm, Key, Nonce, AssociatedData, Plaintext);
aes_256_gcm_encrypt(_Key, _Nonce, _AssociatedData, _Plaintext) ->
    {error, 1}.

-spec aes_256_gcm_decrypt(binary(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, 1 | 2 | 3}.
aes_256_gcm_decrypt(Key, Nonce, AssociatedData, Protected)
    when is_binary(Key), byte_size(Key) =:= 32,
         is_binary(Nonce), byte_size(Nonce) =:= 12,
         is_binary(AssociatedData), is_binary(Protected), byte_size(Protected) >= 16 ->
    aead_decrypt(aes_256_gcm, Key, Nonce, AssociatedData, Protected);
aes_256_gcm_decrypt(_Key, _Nonce, _AssociatedData, _Protected) ->
    {error, 1}.

-spec chacha20_poly1305_encrypt(binary(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, 1 | 2}.
chacha20_poly1305_encrypt(Key, Nonce, AssociatedData, Plaintext)
    when is_binary(Key), byte_size(Key) =:= 32,
         is_binary(Nonce), byte_size(Nonce) =:= 12,
         is_binary(AssociatedData), is_binary(Plaintext) ->
    aead_encrypt(chacha20_poly1305, Key, Nonce, AssociatedData, Plaintext);
chacha20_poly1305_encrypt(_Key, _Nonce, _AssociatedData, _Plaintext) ->
    {error, 1}.

-spec chacha20_poly1305_decrypt(binary(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, 1 | 2 | 3}.
chacha20_poly1305_decrypt(Key, Nonce, AssociatedData, Protected)
    when is_binary(Key), byte_size(Key) =:= 32,
         is_binary(Nonce), byte_size(Nonce) =:= 12,
         is_binary(AssociatedData), is_binary(Protected), byte_size(Protected) >= 16 ->
    aead_decrypt(chacha20_poly1305, Key, Nonce, AssociatedData, Protected);
chacha20_poly1305_decrypt(_Key, _Nonce, _AssociatedData, _Protected) ->
    {error, 1}.

-spec aead_encrypt(atom(), binary(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, 2}.
aead_encrypt(Cipher, Key, Nonce, AssociatedData, Plaintext) ->
    case ensure_crypto() of
        ok ->
            try crypto:crypto_one_time_aead(
                Cipher,
                Key,
                Nonce,
                Plaintext,
                AssociatedData,
                16,
                true
            ) of
                {Ciphertext, Tag} when is_binary(Ciphertext), byte_size(Tag) =:= 16 ->
                    {ok, <<Ciphertext/binary, Tag/binary>>};
                _Other ->
                    {error, 2}
            catch
                _Class:_Reason -> {error, 2}
            end;
        error ->
            {error, 2}
    end.

-spec aead_decrypt(atom(), binary(), binary(), binary(), binary()) ->
    {ok, binary()} | {error, 2 | 3}.
aead_decrypt(Cipher, Key, Nonce, AssociatedData, Protected) ->
    CiphertextSize = byte_size(Protected) - 16,
    <<Ciphertext:CiphertextSize/binary, Tag:16/binary>> = Protected,
    case ensure_crypto() of
        ok ->
            try crypto:crypto_one_time_aead(
                Cipher,
                Key,
                Nonce,
                Ciphertext,
                AssociatedData,
                Tag,
                false
            ) of
                Plaintext when is_binary(Plaintext) -> {ok, Plaintext};
                error -> {error, 3};
                _Other -> {error, 2}
            catch
                _Class:_Reason -> {error, 2}
            end;
        error ->
            {error, 2}
    end.

-spec with_crypto(fun(() -> binary())) -> {ok, binary()} | {error, 2}.
with_crypto(Operation) ->
    case ensure_crypto() of
        ok ->
            try Operation() of
                Value when is_binary(Value) -> {ok, Value};
                _Other -> {error, 2}
            catch
                _Class:_Reason -> {error, 2}
            end;
        error ->
            {error, 2}
    end.

-spec ensure_crypto() -> ok | error.
ensure_crypto() ->
    case application:ensure_all_started(crypto) of
        {ok, _Applications} -> ok;
        {error, _Reason} -> error
    end.
