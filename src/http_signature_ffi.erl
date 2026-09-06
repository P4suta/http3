-module(http_signature_ffi).

-export([hmac_sha256/2, secure_equal/2]).

-spec hmac_sha256(binary(), binary()) -> {ok, binary()} | {error, nil}.
hmac_sha256(Input, Key) when is_binary(Input), is_binary(Key) ->
    try crypto:mac(hmac, sha256, Key, Input) of
        Signature -> {ok, Signature}
    catch
        _:_ -> {error, nil}
    end;
hmac_sha256(_, _) ->
    {error, nil}.

-spec secure_equal(bitstring(), bitstring()) -> boolean().
secure_equal(First, Second) when is_binary(First), is_binary(Second) ->
    try crypto:hash_equals(First, Second) of
        Equal -> Equal
    catch
        _:_ -> false
    end;
secure_equal(_, _) ->
    false.
