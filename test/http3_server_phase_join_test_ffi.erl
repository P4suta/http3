%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_server_phase_join_test_ffi).

-export([new_once/0, claim_once/1, is_claimed/1]).

-spec new_once() -> atomics:atomics_ref().
new_once() ->
    atomics:new(1, [{signed, false}]).

-spec claim_once(atomics:atomics_ref()) -> boolean().
claim_once(Once) ->
    try atomics:compare_exchange(Once, 1, 0, 1) of
        ok -> true;
        _ -> false
    catch
        _:_ -> false
    end.

-spec is_claimed(atomics:atomics_ref()) -> boolean().
is_claimed(Once) ->
    try atomics:get(Once, 1) of
        1 -> true;
        _ -> false
    catch
        _:_ -> false
    end.
