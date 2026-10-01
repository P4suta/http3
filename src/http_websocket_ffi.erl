%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_websocket_ffi).

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
    %% The decoded value has to be sixteen bytes, and the encoding of it has to
    %% be the one this key carries. RFC 4648 section 3.5 calls an encoding whose
    %% final character leaves unused bits set non-canonical, and the decoder here
    %% accepts one: "AQIDBAUGBwgJCgsMDQ4PEC==" and "AQIDBAUGBwgJCgsMDQ4PEA=="
    %% decode alike, and RFC 6455 erratum 3150 records that the document's own
    %% example was the former. A length check alone would admit a nonce that is
    %% the encoding of nothing, so the round trip is what decides.
    try base64:decode(Key) of
        Decoded when byte_size(Decoded) =:= 16 ->
            case base64:encode(Decoded) of
                Key ->
                    Digest = crypto:hash(
                        sha, <<Key/binary, ?WEBSOCKET_GUID/binary>>
                    ),
                    {ok, base64:encode(Digest)};
                _ -> {error, nil}
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
    {ok, mask_bytes(Payload, {A, B, C, D}, 0, <<>>)};
mask(_, _) ->
    {error, nil}.

-spec mask_bytes(binary(), {byte(), byte(), byte(), byte()}, non_neg_integer(), binary()) -> binary().
mask_bytes(<<>>, _Key, _Offset, Accumulator) ->
    Accumulator;
mask_bytes(<<Byte, Rest/binary>>, Key, Offset, Accumulator) ->
    MaskByte = element((Offset rem 4) + 1, Key),
    mask_bytes(Rest, Key, Offset + 1, <<Accumulator/binary, (Byte bxor MaskByte)>>).
