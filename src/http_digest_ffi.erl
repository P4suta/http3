-module(http_digest_ffi).

-export([hash/2, secure_equal/2]).

-spec hash(binary(), binary()) -> {ok, binary()} | {error, nil}.
hash(Input, <<"sha-256">>) when is_binary(Input) ->
    do_hash(sha256, Input);
hash(Input, <<"sha-512">>) when is_binary(Input) ->
    do_hash(sha512, Input);
hash(_, _) ->
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

-spec do_hash(sha256 | sha512, binary()) -> {ok, binary()} | {error, nil}.
do_hash(Algorithm, Input) ->
    try crypto:hash(Algorithm, Input) of
        Digest -> {ok, Digest}
    catch
        _:_ -> {error, nil}
    end.
