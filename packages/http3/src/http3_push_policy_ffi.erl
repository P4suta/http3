%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_push_policy_ffi).

-export([sha256/1]).

-spec sha256(binary()) -> binary().
sha256(Data) when is_binary(Data) ->
    crypto:hash(sha256, Data).
