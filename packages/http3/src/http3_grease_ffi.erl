%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_grease_ffi).

-export([sample/0]).

-spec sample() -> {ok, non_neg_integer()} | {error, nil}.
sample() ->
    try crypto:strong_rand_bytes(8) of
        <<Value:64/unsigned-big>> -> {ok, Value}
    catch
        _:_ -> {error, nil}
    end.
