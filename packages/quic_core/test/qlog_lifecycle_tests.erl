%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(qlog_lifecycle_tests).
-include_lib("eunit/include/eunit.hrl").

blocked_device_close_requires_confirmed_release_test_() ->
    {timeout, 15, fun() -> fixture(fun(_Owner, Writer, Device) ->
        true = erlang:suspend_process(Device),
        ?assert(quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1) =:= {ok, nil}),
        ?assert(quic_core_qlog_ffi:stats(Writer) =:= {ok, {0, 0, 1}}),
        Result = quic_core_qlog_ffi:close(Writer),
        ?assert(Result =:= {error, 3}),
        ?assert(await_dead([Writer, Device], 1000))
    end) end}.

owner_exit_reclaims_a_blocked_writer_test_() ->
    {timeout, 15, fun() -> fixture(fun(Owner, Writer, Device) ->
        true = erlang:suspend_process(Device),
        ?assert(quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1) =:= {ok, nil}),
        ?assert(quic_core_qlog_ffi:stats(Writer) =:= {ok, {0, 0, 1}}),
        exit(Owner, kill),
        ?assert(await_dead([Owner, Writer, Device], 6500))
    end) end}.

device_exit_during_close_replies_and_releases_test_() ->
    {timeout, 10, fun() -> fixture(fun(_Owner, Writer, Device) ->
        true = erlang:suspend_process(Device),
        ?assert(quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1) =:= {ok, nil}),
        Ref = make_ref(),
        Writer ! {qlog_call, self(), Ref, close},
        %% Same sender order makes this a barrier after accepting close.
        ?assert(quic_core_qlog_ffi:stats(Writer) =:= {ok, {0, 0, 1}}),
        exit(Device, kill),
        Replied = receive {qlog_reply, Ref, {error, 3}} -> true after 1500 -> false end,
        ?assert(Replied),
        ?assert(await_dead([Writer, Device], 1000))
    end) end}.

admission_exit_reclaims_its_device_writer_test_() ->
    {timeout, 10, fun() -> fixture(fun(_Owner, Writer, Device) ->
        exit(Writer, kill),
        ?assert(await_dead([Writer, Device], 1500))
    end) end}.

normal_close_joins_the_file_io_process_test_() ->
    {timeout, 10, fun() -> fixture(fun(Owner, Writer, Device) ->
        {monitors, Monitors} = process_info(Writer, monitors),
        Files = [P || {process, P} <- Monitors, is_pid(P), P =/= Owner, P =/= Device,
                      is_file_process(P)],
        ?assert(length(Files) =:= 1),
        Children = [P || {process, P} <- Monitors, is_pid(P), P =/= Owner],
        ?assert(length(Children) =:= 3),
        ?assert(quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1) =:= {ok, nil}),
        ?assert(quic_core_qlog_ffi:close(Writer) =:= {ok, nil}),
        ?assert(await_dead([Writer | Children], 1000))
    end) end}.

repeated_close_does_not_extend_the_first_deadline_test_() ->
    {timeout, 15, fun() -> fixture(fun(_Owner, Writer, Device) ->
        true = erlang:suspend_process(Device),
        First = make_ref(), Second = make_ref(),
        Writer ! {qlog_call, self(), First, close},
        ?assert(quic_core_qlog_ffi:stats(Writer) =:= {ok, {0, 0, 0}}),
        %% The barrier confirms first-close admission before measuring its
        %% deadline. A later caller cannot buy another flush interval.
        receive after 3000 -> ok end,
        Writer ! {qlog_call, self(), Second, close},
        ?assert(quic_core_qlog_ffi:stats(Writer) =:= {ok, {0, 0, 0}}),
        ?assert(await_dead([Writer, Device], 2200)),
        lists:foreach(fun(Ref) ->
            Replied = receive {qlog_reply, Ref, {error, 6}} -> true
                      after 0 -> false end,
            ?assert(Replied)
        end, [First, Second])
    end) end}.

close_acknowledgement_alone_cannot_claim_child_release_test_() ->
    {timeout, 10, fun() -> fixture(fun(_Owner, Writer, Device) ->
        true = erlang:suspend_process(Device),
        Ref = make_ref(),
        Writer ! {qlog_call, self(), Ref, close},
        %% Inject the protocol acknowledgement before either owned child exits.
        %% The stats round trip is a causal barrier after processing it.
        Writer ! {qlog_device_closed, Device, {ok, nil}},
        ?assert(quic_core_qlog_ffi:stats(Writer) =:= {ok, {0, 0, 0}}),
        Early = receive {qlog_reply, Ref, _} -> true after 0 -> false end,
        ?assert(not Early),
        true = erlang:resume_process(Device),
        Replied = receive {qlog_reply, Ref, {ok, nil}} -> true after 1500 -> false end,
        ?assert(Replied),
        ?assert(await_dead([Writer, Device], 1000))
    end) end}.

close_waiters_have_a_finite_admission_limit_test_() ->
    {timeout, 10, fun() -> fixture(fun(_Owner, Writer, Device) ->
        true = erlang:suspend_process(Device),
        ?assert(quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1) =:= {ok, nil}),
        Refs = [make_ref() || _ <- lists:seq(1, 32)],
        lists:foreach(fun(Ref) -> Writer ! {qlog_call, self(), Ref, close} end, Refs),
        Rejected = make_ref(),
        Writer ! {qlog_call, self(), Rejected, close},
        ?assert(quic_core_qlog_ffi:stats(Writer) =:= {ok, {0, 0, 1}}),
        Full = receive {qlog_reply, Rejected, {error, 3}} -> true after 1000 -> false end,
        ?assert(Full),
        exit(Device, kill),
        Deadline = erlang:monotonic_time(millisecond) + 1500,
        Replied = lists:all(fun(Ref) ->
            Remaining = erlang:max(0, Deadline - erlang:monotonic_time(millisecond)),
            receive {qlog_reply, Ref, {error, 3}} -> true after Remaining -> false end
        end, Refs),
        ?assert(Replied),
        ?assert(await_dead([Writer, Device], 1000))
    end) end}.

call_timeout_is_failure_and_rejects_late_replies_test_() ->
    {timeout, 15, fun() ->
        Controller = self(), Barrier = make_ref(),
        {Peer, Monitor} = spawn_monitor(fun() ->
            receive
                {qlog_call, To, Ref, close} ->
                    receive release ->
                        To ! {qlog_reply, Ref, {ok, nil}},
                        Controller ! {late_reply_sent, Barrier}
                    after 10000 -> ok end
            after 10000 -> ok end
        end),
        try
            ?assert(quic_core_qlog_ffi:close(Peer) =:= {error, 3}),
            Peer ! release,
            Sent = receive {late_reply_sent, Barrier} -> true after 1000 -> false end,
            ?assert(Sent),
            Late = receive {qlog_reply, _, _} -> true after 0 -> false end,
            ?assert(not Late)
        after
            exit(Peer, kill),
            receive {'DOWN', Monitor, process, Peer, _} -> ok
            after 1000 -> erlang:error(qlog_fixture_peer_not_joined) end
        end
    end}.

diagnostic_scalars_cannot_create_unbounded_records_test_() ->
    [{timeout, 10, fun() -> fixture(fun(_Owner, Writer, _Device) ->
        TooLarge = 9223372036854775808,
        Result = case Field of
            event_time -> quic_core_qlog_ffi:event(Writer, 1, TooLarge, 0, 0);
            event_value -> quic_core_qlog_ffi:event(Writer, 1, 0, TooLarge, 0);
            event_auxiliary -> quic_core_qlog_ffi:event(Writer, 1, 0, 0, TooLarge);
            frame_time -> quic_core_qlog_ffi:frame_event(Writer, 12, TooLarge, 0, 1, 0);
            frame_stream -> quic_core_qlog_ffi:frame_event(Writer, 12, 0, 4611686018427387904, 1, 0);
            frame_bytes -> quic_core_qlog_ffi:frame_event(Writer, 12, 0, 0, 1, TooLarge)
        end,
        ?assert(Result =:= {error, 1}),
        ?assert(quic_core_qlog_ffi:close(Writer) =:= {ok, nil})
    end) end} || Field <- [event_time, event_value, event_auxiliary, frame_time, frame_stream, frame_bytes]].

maximum_diagnostic_scalars_remain_usable_test_() ->
    {timeout, 10, fun() -> fixture(fun(_Owner, Writer, _Device) ->
        Maximum = 9223372036854775807,
        ?assert(quic_core_qlog_ffi:event(Writer, 1, Maximum, Maximum, Maximum) =:= {ok, nil}),
        ?assert(quic_core_qlog_ffi:frame_event(Writer, 12, Maximum, 4611686018427387903,
                                            1, Maximum) =:= {ok, nil}),
        ?assert(quic_core_qlog_ffi:close(Writer) =:= {ok, nil})
    end) end}.

admission_exit_reclaims_a_worker_waiting_for_file_io_test_() ->
    {timeout, 10, fun() -> fixture(fun(Owner, Writer, Device) ->
        File = file_process(Owner, Writer, Device),
        true = erlang:suspend_process(File),
        try
            ?assert(quic_core_qlog_ffi:event(Writer, 3, 0, 1, 1) =:= {ok, nil}),
            ?assert(await_file_request(File, erlang:monotonic_time(millisecond) + 1000)),
            exit(Writer, kill),
            ?assert(await_dead([Writer, Device, File], 2000))
        after exit(File, kill), ?assert(await_dead([File], 1000)) end
    end) end}.

owner_exit_reclaims_suspended_admission_test_() ->
    {timeout, 15, fun() -> fixture(fun(Owner, Writer, _Device) ->
        {monitors, Monitors} = process_info(Writer, monitors),
        Children = [P || {process, P} <- Monitors, is_pid(P), P =/= Owner],
        ?assert(length(Children) =:= 3),
        true = erlang:suspend_process(Writer),
        exit(Owner, kill),
        ?assert(await_dead([Writer | Children], 6500))
    end) end}.

bound_connection_exit_reclaims_suspended_admission_test_() ->
    {timeout, 15, fun() -> fixture(fun(Owner, Writer, _Device) ->
        with_bound_actor(fun(Connection) ->
            {monitors, Monitors} = process_info(Writer, monitors),
            Children = [P || {process, P} <- Monitors, is_pid(P), P =/= Owner],
            ?assert(quic_core_qlog_ffi:bind_owner(Writer, Connection) =:= {ok, nil}),
            true = erlang:suspend_process(Writer),
            exit(Connection, kill),
            ?assert(await_dead([Writer | Children], 6500)),
            ?assert(is_process_alive(Owner))
        end)
    end) end}.

binding_requires_the_independent_monitor_acknowledgement_test_() ->
    {timeout, 10, fun() -> fixture(fun(Owner, Writer, Device) ->
        with_bound_actor(fun(Connection) ->
            Guardian = guardian_process(Owner, Writer, Device),
            true = erlang:suspend_process(Guardian),
            Controller = self(), Token = make_ref(),
            {Caller, Monitor} = spawn_monitor(fun() ->
                Result = quic_core_qlog_ffi:bind_owner(Writer, Connection),
                Controller ! {qlog_bound, Token, Result =:= {ok, nil}}
            end),
            try
                ?assert(await_owner_monitor(Connection, Writer,
                    erlang:monotonic_time(millisecond) + 1000)),
                %% Admission has installed its monitor; the guardian has not.
                ?assert(quic_core_qlog_ffi:stats(Writer) =:= {ok, {0, 0, 0}}),
                Early = receive {qlog_bound, Token, _} -> true after 0 -> false end,
                ?assert(not Early),
                true = erlang:resume_process(Guardian),
                Bound = receive {qlog_bound, Token, Value} -> Value after 1000 -> false end,
                ?assert(Bound),
                ?assert(owner_monitored_by(Connection, Guardian)),
                ?assert(quic_core_qlog_ffi:close(Writer) =:= {ok, nil})
            after
                exit(Caller, kill),
                receive {'DOWN', Monitor, process, Caller, _} -> ok
                after 1000 -> erlang:error(qlog_binding_caller_not_joined) end
            end
        end)
    end) end}.

binding_an_exited_connection_fails_and_reclaims_the_writer_test_() ->
    {timeout, 10, fun() -> fixture(fun(Owner, Writer, _Device) ->
        with_bound_actor(fun(Connection) ->
            {monitors, Monitors} = process_info(Writer, monitors),
            Children = [P || {process, P} <- Monitors, is_pid(P), P =/= Owner],
            exit(Connection, kill), ?assert(await_dead([Connection], 1000)),
            ?assert(quic_core_qlog_ffi:bind_owner(Writer, Connection) =:= {error, 3}),
            ?assert(await_dead([Writer | Children], 1500)),
            ?assert(is_process_alive(Owner))
        end)
    end) end}.

one_connection_binding_is_idempotent_and_cannot_be_replaced_test_() ->
    {timeout, 10, fun() -> fixture(fun(_Owner, Writer, _Device) ->
        with_bound_actor(fun(Connection) -> with_bound_actor(fun(Other) ->
            ?assert(quic_core_qlog_ffi:bind_owner(Writer, Connection) =:= {ok, nil}),
            ?assert(quic_core_qlog_ffi:bind_owner(Writer, Connection) =:= {ok, nil}),
            ?assert(quic_core_qlog_ffi:bind_owner(Writer, Other) =:= {error, 3}),
            ?assert(not owner_monitored_by(Other, Writer)),
            exit(Other, kill), ?assert(await_dead([Other], 1000)),
            ?assert(quic_core_qlog_ffi:stats(Writer) =:= {ok, {0, 0, 0}}),
            ?assert(quic_core_qlog_ffi:close(Writer) =:= {ok, nil})
        end) end)
    end) end}.

queued_binding_ack_cannot_qualify_an_exited_guardian_test_() ->
    {timeout, 10, fun() -> fixture(fun(Owner, Writer, Device) ->
        with_bound_actor(fun(Connection) ->
            Guardian = guardian_process(Owner, Writer, Device),
            true = erlang:suspend_process(Guardian),
            with_binding_call(Writer, Connection, fun(Token) ->
                ?assert(await_owner_monitor(Connection, Writer,
                    erlang:monotonic_time(millisecond) + 1000)),
                true = erlang:suspend_process(Writer),
                true = erlang:resume_process(Guardian),
                ?assert(await_mailbox_match(Writer, fun
                    ({qlog_owner_bound, G, _, {ok, nil}}) -> G =:= Guardian;
                    (_) -> false
                end, erlang:monotonic_time(millisecond) + 1000)),
                exit(Guardian, kill), ?assert(await_dead([Guardian], 1000)),
                true = erlang:resume_process(Writer),
                ?assert(binding_failed(Token)),
                ?assert(await_dead([Writer, Device], 1500))
            end)
        end)
    end) end}.

queued_repeat_binding_cannot_qualify_an_exited_connection_test_() ->
    {timeout, 10, fun() -> fixture(fun(_Owner, Writer, Device) ->
        with_bound_actor(fun(Connection) ->
            ?assert(quic_core_qlog_ffi:bind_owner(Writer, Connection) =:= {ok, nil}),
            true = erlang:suspend_process(Writer),
            with_binding_call(Writer, Connection, fun(Token) ->
                ?assert(await_mailbox_match(Writer, fun
                    ({qlog_call, _, _, {bind_owner, C}}) -> C =:= Connection;
                    (_) -> false
                end, erlang:monotonic_time(millisecond) + 1000)),
                exit(Connection, kill), ?assert(await_dead([Connection], 1000)),
                true = erlang:resume_process(Writer),
                ?assert(binding_failed(Token)),
                ?assert(await_dead([Writer, Device], 1500))
            end)
        end)
    end) end}.

with_binding_call(Writer, Connection, Fun) ->
    Controller = self(), Token = make_ref(),
    {Caller, Monitor} = spawn_monitor(fun() ->
        Result = quic_core_qlog_ffi:bind_owner(Writer, Connection),
        Controller ! {qlog_binding_failed, Token, Result =:= {error, 3}}
    end),
    try Fun(Token)
    after
        exit(Caller, kill),
        receive {'DOWN', Monitor, process, Caller, _} -> ok
        after 1000 -> erlang:error(qlog_binding_caller_not_joined) end
    end.

binding_failed(Token) ->
    receive {qlog_binding_failed, Token, Failed} -> Failed after 1500 -> false end.

await_mailbox_match(Writer, Predicate, Deadline) ->
    Found = case process_info(Writer, messages) of
        {messages, Messages} -> lists:any(Predicate, Messages);
        _ -> false
    end,
    case Found of
        true -> true;
        false -> case erlang:monotonic_time(millisecond) >= Deadline of
            true -> false;
            false -> receive after 1 -> await_mailbox_match(Writer, Predicate, Deadline) end
        end
    end.

with_bound_actor(Fun) ->
    {Actor, Monitor} = spawn_monitor(fun() -> receive stop -> ok after 15000 -> ok end end),
    try Fun(Actor)
    after
        exit(Actor, kill),
        receive {'DOWN', Monitor, process, Actor, _} -> ok
        after 1000 -> erlang:error(qlog_bound_actor_not_joined) end
    end.

guardian_process(Owner, Writer, Device) ->
    File = file_process(Owner, Writer, Device),
    {monitors, Monitors} = process_info(Writer, monitors),
    Guardians = [P || {process, P} <- Monitors, is_pid(P),
        P =/= Owner, P =/= Device, P =/= File],
    ?assert(length(Guardians) =:= 1),
    hd(Guardians).

owner_monitored_by(Owner, Watcher) ->
    case process_info(Owner, monitored_by) of
        {monitored_by, Monitors} -> lists:member(Watcher, Monitors);
        _ -> false
    end.

await_owner_monitor(Owner, Watcher, Deadline) ->
    case owner_monitored_by(Owner, Watcher) of
        true -> true;
        false -> case erlang:monotonic_time(millisecond) >= Deadline of
            true -> false;
            false -> receive after 1 -> await_owner_monitor(Owner, Watcher, Deadline) end
        end
    end.

queued_reply_after_absolute_deadline_is_not_success_test_() ->
    {timeout, 20, fun() ->
        Controller = self(), Token = make_ref(),
        {Peer, PeerMonitor} = spawn_monitor(fun() ->
            receive {qlog_call, To, Ref, close} ->
                Controller ! {qlog_call_entered, Token},
                receive release -> To ! {qlog_reply, Ref, {ok, nil}}
                after 10000 -> ok end
            after 10000 -> ok end
        end),
        {Caller, CallerMonitor} = spawn_monitor(fun() ->
            Result = quic_core_qlog_ffi:close(Peer),
            Controller ! {qlog_deadline_result, Token, Result =:= {error, 3}}
        end),
        try
            Entered = receive {qlog_call_entered, Token} -> true after 1000 -> false end,
            ?assert(Entered),
            true = erlang:suspend_process(Caller),
            %% Both completion signals are queued while the caller cannot run.
            %% Resuming it must not turn an expired operation into success.
            receive after 5100 -> ok end,
            Peer ! release,
            ?assert(await_dead([Peer], 1000)),
            true = erlang:resume_process(Caller),
            Expired = receive {qlog_deadline_result, Token, Value} -> Value
                      after 1000 -> false end,
            ?assert(Expired)
        after
            exit(Peer, kill), exit(Caller, kill),
            receive {'DOWN', PeerMonitor, process, Peer, _} -> ok
            after 1000 -> erlang:error(qlog_fixture_peer_not_joined) end,
            receive {'DOWN', CallerMonitor, process, Caller, _} -> ok
            after 1000 -> erlang:error(qlog_fixture_caller_not_joined) end
        end
    end}.

file_process(Owner, Writer, Device) ->
    {monitors, Monitors} = process_info(Writer, monitors),
    Files = [P || {process, P} <- Monitors, is_pid(P), P =/= Owner, P =/= Device,
                  is_file_process(P)],
    ?assert(length(Files) =:= 1),
    [File] = Files,
    File.

is_file_process(Pid) ->
    case process_info(Pid, current_function) of
        {current_function, {file_io_server, _, _}} -> true;
        _ -> false
    end.

await_file_request(File, Deadline) ->
    case process_info(File, message_queue_len) of
        {message_queue_len, N} when N > 0 -> true;
        _ -> case erlang:monotonic_time(millisecond) >= Deadline of
            true -> false;
            false -> receive after 1 -> await_file_request(File, Deadline) end
        end
    end.

fixture(Fun) ->
    qlog_test_ffi:with_directory(fun(Directory) ->
        Controller = self(), Token = make_ref(),
        {Owner, Monitor} = spawn_monitor(fun() ->
            case quic_core_qlog_ffi:open(Directory, 1, 2) of
                {ok, Writer} ->
                    Controller ! {qlog_fixture_ready, Token, Writer},
                    receive stop -> ok after 20000 -> ok end;
                {error, _} -> Controller ! {qlog_fixture_failed, Token}
            end
        end),
        try
            Ready = receive
                {qlog_fixture_ready, Token, W} -> {ok, W};
                {qlog_fixture_failed, Token} -> error
            after 5000 -> error end,
            ?assert(is_tuple(Ready) andalso element(1, Ready) =:= ok),
            {ok, Writer} = Ready,
            DeviceResult = device_writer(Writer, erlang:monotonic_time(millisecond) + 1000),
            ?assert(is_tuple(DeviceResult) andalso element(1, DeviceResult) =:= ok),
            {ok, Device} = DeviceResult,
            {monitors, OwnedMonitors} = process_info(Writer, monitors),
            Children = [P || {process, P} <- OwnedMonitors, is_pid(P), P =/= Owner],
            ?assert(length(Children) =:= 3),
            try Fun(Owner, Writer, Device)
            after
                lists:foreach(fun(P) -> exit(P, kill) end, [Writer | Children]),
                ?assert(await_dead([Writer | Children], 1000))
            end
        after
            exit(Owner, kill),
            receive {'DOWN', Monitor, process, Owner, _} -> ok
            after 1000 -> erlang:error(qlog_fixture_owner_not_joined) end
        end
    end).

device_writer(Writer, Deadline) ->
    Monitors = case process_info(Writer, monitors) of
        {monitors, Found} -> Found;
        _ -> []
    end,
    Candidates = [P || {process, P} <- Monitors, is_pid(P), is_device(P)],
    case Candidates of
        [Pid] -> {ok, Pid};
        _ ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> error;
                false -> receive after 1 -> device_writer(Writer, Deadline) end
            end
    end.

is_device(Pid) ->
    case process_info(Pid, current_function) of
        {current_function, {quic_core_qlog_ffi, device_writer_loop, _}} -> true;
        _ -> false
    end.

await_dead(Pids, Milliseconds) ->
    Monitors = [{P, erlang:monitor(process, P)} || P <- Pids],
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    try lists:all(fun({P, M}) ->
        Remaining = erlang:max(0, Deadline - erlang:monotonic_time(millisecond)),
        receive {'DOWN', M, process, P, _} -> true after Remaining -> false end
    end, Monitors)
    after lists:foreach(fun({_P, M}) -> erlang:demonitor(M, [flush]) end, Monitors) end.
