%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Deterministic test-only barriers for the common server's acquire-to-adopt
%% interval. Assertions receive only booleans and bounded counters; process,
%% lifecycle, resource, and command capabilities remain inside this module.
-module(http_server_admission_test_ffi).

-export([
    await_dispatch/1,
    begin_drain/1,
    resource_usage/1,
    resume_executor/1,
    suspend_executor/1
]).

suspend_executor(Server) ->
    try erlang:suspend_process(executor(Server)) of
        _ -> nil
    catch
        _:_ -> nil
    end.

resume_executor(Server) ->
    try erlang:resume_process(executor(Server)) of
        _ -> nil
    catch
        error:badarg -> nil
    end.

await_dispatch(Server) ->
    await_dispatch(Server, erlang:monotonic_time(millisecond) + 1000).

await_dispatch(Server, Deadline) ->
    Queued = lists:any(fun is_dispatch/1, executor_messages(Server)),
    case {Queued, erlang:monotonic_time(millisecond) < Deadline} of
        {true, _} -> true;
        {false, true} ->
            receive after 1 -> await_dispatch(Server, Deadline) end;
        {false, false} -> false
    end.

is_dispatch({_Reference, Command})
        when is_tuple(Command), tuple_size(Command) > 0 ->
    element(1, Command) =:= dispatch;
is_dispatch(_) ->
    false.

%% Set the lifecycle barrier that public drain establishes without asking the
%% deliberately suspended executor to process a command.
begin_drain(Server) ->
    try http_server_ffi:mark_server_draining(lifecycle(Server)) of
        _ -> nil
    catch
        _:_ -> nil
    end.

resource_usage(Server) ->
    try controller(Server) of
        {controller, Handle, _Limits} ->
            http_server_ffi:resource_snapshot(Handle);
        _ -> {-1, -1}
    catch
        _:_ -> {-1, -1}
    end.

executor_messages(Server) ->
    try process_info(executor(Server), messages) of
        {messages, Messages} when is_list(Messages) -> Messages;
        _ -> []
    catch
        _:_ -> []
    end.

executor(Server) -> element(2, Server).
lifecycle(Server) -> element(4, Server).
controller(Server) -> element(5, Server).
