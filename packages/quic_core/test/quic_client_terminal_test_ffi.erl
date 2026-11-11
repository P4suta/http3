%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(quic_client_terminal_test_ffi).
-export([close_both/3]).

%% Queue the application's Close before delivering the peer's close packet.
%% No packet, handle, PID, exception payload or mailbox value leaves this helper.
-spec close_both(term(), term(), pid()) -> {boolean(), boolean(), boolean(), boolean()}.
close_both(Connection, Peer, Actor) ->
    Parent = self(), Ref = make_ref(), Monitor = monitor(process, Actor),
    true = suspend_parked(Actor, erlang:monotonic_time(millisecond) + 2000),
    {Caller, CallerMonitor} = spawn_monitor(fun() ->
        Closed = 'quic_core@client':close(Connection) =:= {ok, closed},
        Parent ! {Ref, Closed}
    end),
    try
        Queued = await_close_command(Actor, erlang:monotonic_time(millisecond) + 2000),
        PeerClosed = 'quic_core@server':close(Peer) =:= {ok, closed},
        true = erlang:resume_process(Actor),
        LocalClosed = receive {Ref, Value} when is_boolean(Value) -> Value after 2000 -> false end,
        Exited = receive {'DOWN', Monitor, process, Actor, _} -> true after 2000 -> false end,
        {Queued, PeerClosed, LocalClosed, Exited}
    after
        try erlang:resume_process(Actor) of
            true -> ok
        catch error:badarg -> ok end,
        exit(Actor, kill),
        exit(Caller, kill),
        await_down(Actor, Monitor), await_down(Caller, CallerMonitor),
        receive {Ref, _} -> ok after 0 -> ok end
    end.

%% Publication precedes the actor's first drive. Freezing it in that drive
%% would let a queued network packet be consumed before the ordered commands.
%% Stop only at an actual receive, checked while the actor is suspended.
suspend_parked(Actor, Deadline) ->
    true = erlang:suspend_process(Actor),
    Parked = case process_info(Actor, current_stacktrace) of
        {current_stacktrace, Stack} -> lists:any(fun
            ({gleam_erlang_ffi, select, Arity, _}) when Arity =:= 1; Arity =:= 2 -> true;
            (_) -> false
        end, Stack);
        _ -> false
    end,
    case Parked of
        true -> true;
        false ->
            true = erlang:resume_process(Actor),
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> false;
                false -> receive after 2 -> suspend_parked(Actor, Deadline) end
            end
    end.

await_close_command(Actor, Deadline) ->
    Present = case process_info(Actor, messages) of
        {messages, Messages} -> lists:any(fun
            ({_, {close, _, _, _}}) -> true;
            (_) -> false
        end, Messages);
        undefined -> false
    end,
    case Present orelse erlang:monotonic_time(millisecond) >= Deadline of
        true -> Present;
        false -> receive after 2 -> await_close_command(Actor, Deadline) end
    end.

await_down(Actor, Monitor) ->
    case is_process_alive(Actor) of
        false -> demonitor(Monitor, [flush]), ok;
        true ->
            receive {'DOWN', Monitor, process, Actor, _} -> ok
            after 2000 -> error(terminal_fixture_cleanup_incomplete)
            end
    end.
