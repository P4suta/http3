%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http1_idle_stop_test_ffi).
-export([await_head_read/2]).

%% Inspect only this listener's monitored child and retain no backend values.
%% The caller receives a Boolean phase barrier, never a stack or process ID.
await_head_read({http1_listener, {listener, Listener, Commands, _, _, _, _, _}}, Timeout)
        when is_integer(Timeout), Timeout > 0, Timeout =< 5000 ->
    {ok, Listener} = gleam@erlang@process:subject_owner(Commands),
    await_read(Listener, erlang:monotonic_time(millisecond) + Timeout);
await_head_read(_, _) -> false.

await_read(Listener, Deadline) ->
    Children = case process_info(Listener, monitors) of
        {monitors, Monitors} when length(Monitors) =< 8 ->
            [P || {process, P} <- Monitors, is_pid(P)];
        _ -> []
    end,
    Found = length([P || P <- Children, reading_head(P)]) =:= 1,
    case Found orelse erlang:monotonic_time(millisecond) >= Deadline of
        true -> Found;
        false -> receive after 1 -> await_read(Listener, Deadline) end
    end.

reading_head(Pid) ->
    case process_info(Pid, current_stacktrace) of
        {current_stacktrace, Stack} ->
            lists:any(fun
                ({http@internal@http1@server, receive_head, _, _}) -> true;
                ({http@internal@http1@server, read_next_head, _, _}) -> true;
                (_) -> false
            end, Stack);
        _ -> false
    end.
