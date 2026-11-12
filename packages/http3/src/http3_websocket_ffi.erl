%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_websocket_ffi).

-export([accept/1, client_key/0, mask/2, random_mask/0]).

-define(WEBSOCKET_GUID, <<"258EAFA5-E914-47DA-95CA-C5AB0DC85B11">>).

-spec client_key() -> {ok, binary()} | {error, nil}.
client_key() ->
    try base64:encode(crypto:strong_rand_bytes(16)) of
        Key -> {ok, Key}
    catch
        _:_ -> {error, nil}
    end.

-spec accept(binary()) -> {ok, binary()} | {error, nil}.
accept(Key) when is_binary(Key) ->
    try base64:decode(Key) of
        Decoded when byte_size(Decoded) =:= 16 ->
            case base64:encode(Decoded) of
                Key ->
                    Digest = crypto:hash(
                        sha, <<Key/binary, ?WEBSOCKET_GUID/binary>>),
                    {ok, base64:encode(Digest)};
                _NonCanonical -> {error, nil}
            end;
        _ -> {error, nil}
    catch
        _:_ -> {error, nil}
    end;
accept(_) ->
    {error, nil}.

-spec random_mask() -> {ok, binary()} | {error, nil}.
random_mask() ->
    try crypto:strong_rand_bytes(4) of
        Mask -> {ok, Mask}
    catch
        _:_ -> {error, nil}
    end.

-spec mask(binary(), binary()) -> {ok, binary()} | {error, nil}.
mask(Payload, <<A, B, C, D>>) when is_binary(Payload) ->
    {ok, mask_bytes(Payload, {A, B, C, D}, [])};
mask(_, _) ->
    {error, nil}.

-spec mask_bytes(binary(), {byte(), byte(), byte(), byte()}, iolist()) -> binary().
mask_bytes(<<W, X, Y, Z, Rest/binary>>, {A, B, C, D} = Key, Accumulator) ->
    mask_bytes(Rest, Key,
               [<<(W bxor A), (X bxor B), (Y bxor C), (Z bxor D)>> |
                Accumulator]);
mask_bytes(<<W, X, Y>>, {A, B, C, _D}, Accumulator) ->
    iolist_to_binary(lists:reverse(
        [<<(W bxor A), (X bxor B), (Y bxor C)>> | Accumulator]));
mask_bytes(<<W, X>>, {A, B, _C, _D}, Accumulator) ->
    iolist_to_binary(lists:reverse(
        [<<(W bxor A), (X bxor B)>> | Accumulator]));
mask_bytes(<<W>>, {A, _B, _C, _D}, Accumulator) ->
    iolist_to_binary(lists:reverse([<<(W bxor A)>> | Accumulator]));
mask_bytes(<<>>, _Key, Accumulator) ->
    iolist_to_binary(lists:reverse(Accumulator)).
