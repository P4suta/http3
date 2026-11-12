%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(quic_frame_progress_test).
-export([contracts/0]).
-include_lib("eunit/include/eunit.hrl").

contracts() -> [
    {"VM envelope contains arity and scalar metadata only", fun scalar_envelope/0},
    {"streaming capture saturates without retaining caller messages", fun bounded_capture/0},
    {"collector rejects foreign and non-scalar envelopes", fun hostile_envelopes/0},
    {"action exception joins collector and preserves caller mailbox", fun action_exception/0},
    {"owner death stops trace sources and collector", fun owner_death/0},
    {"dead traced endpoint does not obscure the action result", fun endpoint_death/0},
    {"collector failure cleans both trace sources", fun collector_death/0}
].

scalar_envelope() ->
    with_workers(fun(Client, Server) ->
        {Observed, Events} = quic_core_test_ffi:trace_frame_progress(Client, Server, fun() ->
            {flags, Flags} = erlang:trace_info(Client, flags),
            {tracer, Tracer} = erlang:trace_info(Client, tracer),
            Suspended = Tracer =/= self(),
            case Suspended of true -> erlang:suspend_process(Tracer); false -> ok end,
            try
                tick(Client, 1),
                Delivered = erlang:trace_delivered(Client),
                receive {trace_delivered, Client, Delivered} -> ok
                after 1000 -> error(trace_delivery_timeout) end,
                {messages, Messages} = process_info(Tracer, messages),
                Envelopes = [Message || Message = {trace, Client0, call, _, _} <- Messages,
                                        Client0 =:= Client],
                Safe = case Envelopes of
                    [{trace, Client, call,
                      {'quic_core@internal@connection_state', tick, 2},
                      {connection_tick, 1}}] -> true;
                    _ -> false
                end,
                {lists:member(arity, Flags), Safe}
            after
                case Suspended of true -> erlang:resume_process(Tracer); false -> ok end
            end
        end),
        ?assertEqual({true, true}, Observed),
        ?assertEqual([{connection_ticked, client_endpoint, 1}], Events)
    end).

bounded_capture() ->
    with_workers(fun(Client, Server) ->
        {{OwnerClean, Tracer}, Events} = quic_core_test_ffi:trace_frame_progress(
            Client, Server, fun() ->
                {tracer, Collector} = erlang:trace_info(Client, tracer),
                tick(Client, 10000),
                {messages, Messages} = process_info(self(), messages),
                Clean = not lists:any(fun(Message) ->
                    is_tuple(Message) andalso tuple_size(Message) >= 1
                    andalso element(1, Message) =:= trace
                end, Messages),
                {Clean, Collector}
            end),
        ?assert(OwnerClean),
        ?assert(Tracer =/= self()),
        ?assertNot(is_process_alive(Tracer)),
        ?assertEqual(1024, length(Events)),
        ?assertEqual(trace_truncated, lists:last(Events)),
        ?assertEqual({flags, []}, erlang:trace_info(Client, flags)),
        ?assertEqual({flags, []}, erlang:trace_info(Server, flags))
    end).

hostile_envelopes() ->
    with_workers(fun(Client, Server) ->
        {nil, Events} = quic_core_test_ffi:trace_frame_progress(Client, Server, fun() ->
            {tracer, Collector} = erlang:trace_info(Client, tracer),
            Module = 'quic_core@internal@connection_state',
            lists:foreach(fun(Message) -> Collector ! Message end, [
                {trace, self(), call, {Module, tick, 2}, {connection_tick, 2}},
                {trace, Client, call, {wrong_module, tick, 2}, {connection_tick, 3}},
                {trace, Client, call, {Module, tick, [<<"private">>, 4]}, {connection_tick, 4}},
                {trace, Client, call, {Module, tick, 2}, {connection_tick, <<"private">>}},
                {trace, Client, call, {Module, tick, 2}, {connection_tick, 1 bsl 128}},
                {trace, Client, call, {Module, commit_packet, 7},
                 {stream_commit, 1, 2, 3, -1, true, 4}},
                {trace, Client, call, {Module, commit_packet, 7},
                 {stream_commit, 1, 2, 3, 4, <<"private">>, 5}},
                {trace, Client, call, {Module, receive_packet, 6},
                 {ack_receive, -1, 5}}
            ]),
            tick(Client, 1),
            nil
        end),
        ?assertEqual([{connection_ticked, client_endpoint, 1}], Events)
    end).

action_exception() ->
    with_workers(fun(Client, Server) ->
        Token = make_ref(),
        self() ! {Token, unrelated},
        try quic_core_test_ffi:trace_frame_progress(Client, Server, fun() ->
            {tracer, Collector} = erlang:trace_info(Client, tracer),
            self() ! {Token, collector, Collector},
            tick(Client, 1),
            error(expected_action_failure)
        end) of _ -> error(action_failure_lost)
        catch error:expected_action_failure -> ok end,
        receive {Token, collector, Collector} -> ?assertNot(is_process_alive(Collector))
        after 1000 -> error(missing_collector) end,
        receive {Token, unrelated} -> ok after 0 -> error(unrelated_message_consumed) end,
        assert_sources_stopped(Client, Server)
    end).

owner_death() ->
    with_workers(fun(Client, Server) ->
        Parent = self(),
        {Owner, OwnerMonitor} = spawn_monitor(fun() ->
            quic_core_test_ffi:trace_frame_progress(Client, Server, fun() ->
                {tracer, Collector} = erlang:trace_info(Client, tracer),
                Parent ! {self(), collector, Collector},
                receive never -> nil after 3000 -> error(owner_fixture_timeout) end
            end)
        end),
        Collector = receive {Owner, collector, Pid} -> Pid
                    after 1000 -> error(owner_fixture_setup_timeout) end,
        Monitor = monitor(process, Collector),
        exit(Owner, kill),
        receive {'DOWN', OwnerMonitor, process, Owner, killed} -> ok
        after 1000 -> error(owner_survived) end,
        receive {'DOWN', Monitor, process, Collector, normal} -> ok
        after 1000 -> error(orphaned_collector) end,
        assert_sources_stopped(Client, Server)
    end).

endpoint_death() ->
    with_workers(fun(Client, Server) ->
        {nil, []} = quic_core_test_ffi:trace_frame_progress(Client, Server, fun() ->
            Monitor = monitor(process, Client),
            exit(Client, kill),
            receive {'DOWN', Monitor, process, Client, killed} -> nil
            after 1000 -> error(endpoint_survived) end
        end),
        ?assertEqual({flags, []}, erlang:trace_info(Server, flags))
    end).

collector_death() ->
    with_workers(fun(Client, Server) ->
        ?assertError(progress_trace_collector_failed,
            quic_core_test_ffi:trace_frame_progress(Client, Server, fun() ->
                {tracer, Collector} = erlang:trace_info(Client, tracer),
                Monitor = monitor(process, Collector),
                exit(Collector, kill),
                receive {'DOWN', Monitor, process, Collector, killed} -> nil
                after 1000 -> error(collector_survived) end
            end)),
        assert_sources_stopped(Client, Server)
    end).

assert_sources_stopped(Client, Server) ->
    ?assertEqual({flags, []}, erlang:trace_info(Client, flags)),
    ?assertEqual({flags, []}, erlang:trace_info(Server, flags)).

with_workers(Run) ->
    {module, 'quic_core@internal@connection_state'} =
        code:ensure_loaded('quic_core@internal@connection_state'),
    Workers = [spawn_monitor(fun worker/0) || _ <- [client, server]],
    [{Client, _}, {Server, _}] = Workers,
    try Run(Client, Server)
    after
        lists:foreach(fun({Pid, Ref}) ->
            exit(Pid, kill),
            receive {'DOWN', Ref, process, Pid, _} -> ok
            after 1000 -> error(trace_fixture_cleanup_timeout) end
        end, Workers)
    end.

tick(Worker, Count) ->
    Ref = make_ref(),
    Worker ! {tick, self(), Ref, Count},
    receive {Ref, completed} -> ok after 2000 -> error(trace_fixture_tick_timeout) end.

worker() ->
    receive
        {tick, Owner, Ref, Count} ->
            lists:foreach(fun(N) ->
                %% A failing core call still produces its call trace. The invalid
                %% state deliberately includes bytes that must never enter it.
                try 'quic_core@internal@connection_state':tick(
                        #{secret => <<"trace-envelope-secret-marker">>}, N)
                catch _:_ -> ok end
            end, lists:seq(1, Count)),
            Owner ! {Ref, completed},
            worker()
    end.
