%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Fixed-size, payload-free observation shared with the upload reaper. Protocol
%% decisions, deadlines, callback supervision and cleanup remain in Gleam.
-module(http_upload_ffi).
-export([new_observation/0, set_cleanup/2, get_cleanup/1,
    set_failure/2, get_failure/1, flush_events/1]).

new_observation() -> atomics:new(2, [{signed, false}]).
set_cleanup(State, Code) when Code >= 1, Code =< 4 ->
    case atomics:get(State, 1) of
        0 -> atomics:put(State, 1, Code);
        1 when Code > 1 -> atomics:put(State, 1, Code);
        _ -> ok
    end,
    nil.
get_cleanup(State) -> atomics:get(State, 1).
set_failure(State, Code) when Code >= 1, Code =< 4 ->
    _ = atomics:compare_exchange(State, 2, 0, Code),
    nil.
get_failure(State) -> atomics:get(State, 2).
flush_events({subject, Owner, Ref}) when Owner =:= self() -> flush_events(Ref, 4);
flush_events(_) -> nil.
flush_events(_Ref, 0) -> nil;
flush_events(Ref, Remaining) ->
    receive {Ref, _Event} -> flush_events(Ref, Remaining - 1)
    after 0 -> nil end.
