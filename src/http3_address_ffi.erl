%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_address_ffi).

-export([format/1, parse/1]).

-spec parse(binary()) -> {ok, binary()} | {error, nil}.
parse(Value) when is_binary(Value) ->
    case inet:parse_address(binary_to_list(Value)) of
        {ok, Address} -> encode(Address);
        {error, _} -> {error, nil}
    end;
parse(_) ->
    {error, nil}.

-spec format(binary()) -> {ok, binary()} | {error, nil}.
format(Bytes) when is_binary(Bytes) ->
    case decode(Bytes) of
        {ok, Address} ->
            try iolist_to_binary(inet:ntoa(Address)) of
                Text -> {ok, Text}
            catch
                _:_ -> {error, nil}
            end;
        error -> {error, nil}
    end;
format(_) ->
    {error, nil}.

-spec encode(inet:ip_address()) -> {ok, binary()} | {error, nil}.
encode({A, B, C, D}) ->
    {ok, <<A, B, C, D>>};
encode({A, B, C, D, E, F, G, H}) ->
    {ok, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>};
encode(_) ->
    {error, nil}.

-spec decode(binary()) -> {ok, inet:ip_address()} | error.
decode(<<A, B, C, D>>) ->
    {ok, {A, B, C, D}};
decode(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {ok, {A, B, C, D, E, F, G, H}};
decode(_) ->
    error.
