%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(qlog_startup_tests).
-include_lib("eunit/include/eunit.hrl").
-export([barrier_case/3]).

directory_validation_has_an_absolute_startup_deadline_test_() ->
    {timeout, 20, fun() -> barrier_case(directory, validate, fun expect_timeout/3) end}.

open_directory_check_has_an_absolute_startup_deadline_test_() ->
    {timeout, 20, fun() -> barrier_case(directory, open, fun expect_timeout/3) end}.

file_open_has_an_absolute_startup_deadline_test_() ->
    {timeout, 20, fun() -> barrier_case(open, open, fun expect_timeout/3) end}.

initial_header_has_an_absolute_startup_deadline_test_() ->
    {timeout, 20, fun() -> barrier_case(header, open, fun expect_timeout/3) end}.

validation_probe_open_has_an_absolute_startup_deadline_test_() ->
    {timeout, 20, fun() -> barrier_case(open, validate, fun expect_timeout/3) end}.

validation_probe_close_has_an_absolute_startup_deadline_test_() ->
    {timeout, 20, fun() -> barrier_case(header, validate, fun expect_timeout/3) end}.

owner_exit_during_initial_header_joins_the_opener_and_device_test_() ->
    {timeout, 10, fun() -> barrier_case(header, open,
        fun(_Token, _Operation, {entered, Caller, Requester, Device, _Proxy}) ->
            Family = qlog_family(Requester, Caller),
            ?assert(length(Family) =:= 2),
            exit(Caller, kill),
            ?assert(dead(Caller)),
            ?assert(lists:all(fun dead/1, [Device | Family]))
        end) end}.

owner_exit_before_open_reply_joins_the_created_device_test_() ->
    {timeout, 10, fun() -> barrier_case(untracked, open,
        fun(_Token, _Operation, {entered, Caller, Requester, Device, _Proxy}) ->
            Family = qlog_family(Requester, Caller),
            ?assert(length(Family) =:= 2),
            ?assert(is_process_alive(Device)),
            exit(Caller, kill),
            ?assert(dead(Caller)),
            ?assert(lists:all(fun dead/1, Family)),
            ?assert(dead(Device))
        end) end}.

queued_device_notice_is_recovered_after_the_opener_exits_test_() ->
    {timeout, 10, fun() -> barrier_case(untracked, open,
        fun(Token, _Operation, {entered, Caller, Requester, Device, Proxy}) ->
            Family = qlog_family(Requester, Caller),
            ?assert(length(Family) =:= 2),
            [Guardian] = [P || P <- Family, P =/= Requester],
            true = erlang:suspend_process(Guardian),
            exit(Caller, kill),
            ?assert(dead(Caller)),
            Proxy ! {startup_opener_continue, Token},
            ?assert(await_device_notice(Guardian, Requester, Device,
                                       erlang:monotonic_time(millisecond) + 1000)),
            exit(Requester, kill),
            ?assert(dead(Requester)),
            true = erlang:resume_process(Guardian),
            ?assert(lists:all(fun dead/1, Family)),
            ?assert(dead(Device))
        end) end}.

late_open_success_after_timeout_cannot_leave_a_file_owner_test_() ->
    {timeout, 20, fun() -> barrier_case(open, open,
        fun(Token, Operation, {entered, _Caller, Requester, _Device, Proxy} = Observed) ->
            expect_timeout(Token, Operation, Observed),
            ?assert(dead(Requester)),
            Proxy ! {startup_release, Token},
            Late = receive {startup_late_open, Token, File} -> {opened, File}
                   after 1500 -> missing end,
            ?assert(is_tuple(Late) andalso element(1, Late) =:= opened),
            ?assert(dead(element(2, Late)))
        end) end}.

queued_startup_success_after_deadline_is_rejected_and_joined_test_() ->
    {timeout, 20, fun() -> barrier_case(header, open,
        fun(Token, Operation, {entered, Caller, Requester, Device, Proxy} = Observed) ->
            true = erlang:suspend_process(Caller),
            Proxy ! {startup_continue, Token},
            ?assert(await_ready_message(Caller, erlang:monotonic_time(millisecond) + 1000)),
            Family = qlog_family(Requester, Caller),
            ?assert(length(Family) =:= 3),
            receive after 5100 -> ok end,
            true = erlang:resume_process(Caller),
            expect_timeout(Token, Operation, Observed),
            ?assert(lists:all(fun dead/1, [Device | Family]))
        end) end}.

startup_deadline_progresses_while_the_caller_is_suspended_test_() ->
    {timeout, 15, fun() -> barrier_case(header, open,
        fun(_Token, _Operation, {entered, Caller, Requester, Device, _Proxy}) ->
            Family = qlog_family(Requester, Caller),
            ?assert(length(Family) =:= 2),
            true = erlang:suspend_process(Caller),
            receive after 5100 -> ok end,
            ?assert(lists:all(fun dead/1, [Device | Family])),
            true = erlang:resume_process(Caller)
        end) end}.

opener_is_retained_as_the_runtime_device_writer_test_() ->
    {timeout, 10, fun() -> qlog_test_ffi:with_directory(fun(Directory) ->
        Open = quic_core_qlog_ffi:open(Directory, 1, 2),
        ?assert(is_tuple(Open) andalso element(1, Open) =:= ok),
        {ok, Writer} = Open,
        {monitors, Monitors} = process_info(Writer, monitors),
        Children = [P || {process, P} <- Monitors, is_pid(P), P =/= self()],
        try
            ?assert(length(Children) =:= 3),
            Files = [P || P <- Children, at_module(P, file_io_server)],
            ?assert(length(Files) =:= 1),
            [File] = Files,
            {monitors, FileMonitors} = process_info(File, monitors),
            Workers = [P || {process, P} <- FileMonitors, lists:member(P, Children)],
            ?assert(length(Workers) =:= 1),
            [Worker] = Workers,
            ?assert(await_function(Worker, device_writer_loop,
                                  erlang:monotonic_time(millisecond) + 1000)),
            ?assert(lists:member({process, Worker}, FileMonitors)),
            ?assert(quic_core_qlog_ffi:stats(Writer) =:= {ok, {0, 0, 0}}),
            ?assert(quic_core_qlog_ffi:close(Writer) =:= {ok, nil}),
            ?assert(lists:all(fun dead/1, [Writer | Children]))
        after
            lists:foreach(fun(P) -> exit(P, kill) end, [Writer | Children]),
            ?assert(lists:all(fun dead/1, [Writer | Children]))
        end
    end) end}.

expect_timeout(Token, Operation, {entered, _Caller, Requester, Device, _Proxy}) ->
    Result = receive {startup_result, Token, Value} -> Value after 6500 -> missing end,
    ?assert(Result =:= timeout_result(Operation)),
    ?assert(dead(Requester)),
    ?assert(Device =:= undefined orelse dead(Device)).

timeout_result(validate) -> {error, 2};
timeout_result(open) -> {error, 3}.

%% This scoped intermediary never invents an I/O result. It forwards the
%% original requester PID to the real OTP file server, retaining that process
%% as the actual file_io_server owner. Only a reply alias is substituted so a
%% real opened device can be paused before the caller receives it.
barrier_case(Stage, Operation, Action) ->
    qlog_test_ffi:with_directory(fun(Directory) ->
        ?assert(quic_core_qlog_ffi:validate_directory(Directory) =:= {ok, nil}),
        {module, sys} = code:ensure_loaded(sys),
        {module, gen} = code:ensure_loaded(gen),
        {module, quic_core_process_label_ffi} = code:ensure_loaded(quic_core_process_label_ffi),
        Original = whereis(file_server_2),
        Controller = self(), Token = make_ref(),
        {Proxy, ProxyMonitor} = spawn_monitor(fun() ->
            Watch = erlang:monitor(process, Controller),
            proxy_loop(Original, Controller, Watch, Token, Stage, Directory, false)
        end),
        true = unregister(file_server_2), true = register(file_server_2, Proxy),
        {Caller, CallerMonitor} = spawn_monitor(fun() ->
            Result = case Operation of
                validate -> quic_core_qlog_ffi:validate_directory(Directory);
                open -> quic_core_qlog_ffi:open(Directory, 1, 2);
                accounted -> quic_core_qlog_ffi:open_accounted(Directory, 1, 2)
            end,
            Controller ! {startup_result, Token, Result},
            receive stop -> ok after 12000 -> ok end
        end),
        try
            Observed = receive {startup_barrier, Token, Requester, Device} ->
                {entered, Caller, Requester, Device, Proxy}
            after 2000 -> missing end,
            ?assert(is_tuple(Observed) andalso element(1, Observed) =:= entered),
            %% A paused open result alone is not a header/close barrier. Wait
            %% until the real operation has reached the already-tracked device.
            case Stage of
                header -> ?assert(await_device_request(element(4, Observed),
                                     erlang:monotonic_time(millisecond) + 1000));
                _ -> ok
            end,
            try Action(Token, Operation, Observed)
            after
                {entered, _, Requester0, Device0, _} = Observed,
                Family = qlog_family(Requester0, Caller),
                Owned = lists:usort([P || P <- [Device0 | Family], is_pid(P), P =/= Caller]),
                lists:foreach(fun(P) -> exit(P, kill) end, Owned),
                ?assert(lists:all(fun dead/1, Owned))
            end
        after
            %% Restore the process-global name before any cleanup file call.
            restore_file_server(Original, Proxy),
            exit(Caller, kill),
            ?assert(join(Caller, CallerMonitor, 1000)),
            Proxy ! {startup_release, Token},
            Proxy ! {startup_stop, Token},
            ?assert(join(Proxy, ProxyMonitor, 1500)),
            ?assert(whereis(file_server_2) =:= Original),
            %% Same-server ordering drains a released, potentially late open.
            ?assert(is_tuple(gen_server:call(Original, get_cwd, 1000)))
        end
    end).

proxy_loop(Original, Controller, Watch, Token, Stage, Directory, Used) ->
    receive
        {'$gen_call', From, Request} = Message ->
            case not Used andalso selected_request(Stage, Directory, Request) of
                true ->
                    proxy_barrier(Original, Controller, Watch, Token, Stage, From, Request),
                    proxy_loop(Original, Controller, Watch, Token, Stage, Directory, true);
                false -> Original ! Message,
                    proxy_loop(Original, Controller, Watch, Token, Stage, Directory, Used)
            end;
        {startup_stop, Token} -> ok;
        {startup_release, Token} ->
            proxy_loop(Original, Controller, Watch, Token, Stage, Directory, Used);
        {'DOWN', Watch, process, Controller, _} -> restore_file_server(Original, self());
        Other -> Original ! Other,
            proxy_loop(Original, Controller, Watch, Token, Stage, Directory, Used)
    after 12000 -> restore_file_server(Original, self())
    end.

selected_request(directory, Directory, {read_file_info, Name}) ->
    unicode:characters_to_binary(Name) =:= Directory;
selected_request(Stage, Directory, {open, Name, _})
    when Stage =:= open; Stage =:= header; Stage =:= untracked ->
    unicode:characters_to_binary(filename:dirname(Name)) =:= Directory;
selected_request(_, _, _) -> false.

proxy_barrier(Original, Controller, Watch, Token, Stage, {Owner, _} = From, Request) ->
    case Stage of
        OpenStage when OpenStage =:= header; OpenStage =:= untracked ->
            Alias = erlang:alias([reply]),
            Original ! {'$gen_call', {Owner, [alias | Alias]}, Request},
            Open = receive {[alias | Alias], Reply} -> Reply after 2000 -> missing end,
            erlang:unalias(Alias),
            case Open of
                {ok, Device} when is_pid(Device) ->
                    true = erlang:suspend_process(Device),
                    case Stage of
                        untracked -> true = erlang:suspend_process(Owner);
                        _ -> ok
                    end,
                    gen:reply(From, Open),
                    Controller ! {startup_barrier, Token, Owner, Device},
                    Release = case Stage of
                        untracked -> await_untracked_release(Controller, Watch, Token, Owner);
                        _ -> await_release(Controller, Watch, Token)
                    end,
                    case Release of
                        continue -> true = erlang:resume_process(Device);
                        stop -> exit(Device, kill), true = dead(Device)
                    end;
                _ -> gen:reply(From, Open)
            end;
        open ->
            Controller ! {startup_barrier, Token, Owner, undefined},
            await_release(Controller, Watch, Token),
            Alias = erlang:alias([reply]),
            Original ! {'$gen_call', {Owner, [alias | Alias]}, Request},
            Open = receive {[alias | Alias], Reply} -> Reply after 2000 -> missing end,
            erlang:unalias(Alias), gen:reply(From, Open),
            case Open of
                {ok, Device} when is_pid(Device) -> Controller ! {startup_late_open, Token, Device};
                _ -> ok
            end;
        directory ->
            Controller ! {startup_barrier, Token, Owner, undefined},
            await_release(Controller, Watch, Token),
            Original ! {'$gen_call', From, Request}
    end.

await_release(Controller, Watch, Token) ->
    receive
        {startup_release, Token} -> stop;
        {startup_continue, Token} -> continue;
        {'DOWN', Watch, process, Controller, _} -> stop
    after 10000 -> stop
    end.

await_untracked_release(Controller, Watch, Token, Owner) ->
    receive
        {startup_opener_continue, Token} ->
            true = erlang:resume_process(Owner),
            await_release(Controller, Watch, Token);
        {startup_release, Token} -> stop;
        {startup_continue, Token} -> true = erlang:resume_process(Owner), continue;
        {'DOWN', Watch, process, Controller, _} -> stop
    after 10000 -> stop
    end.

restore_file_server(Original, Proxy) ->
    case whereis(file_server_2) of
        Proxy -> true = unregister(file_server_2), true = register(file_server_2, Original), ok;
        Original -> ok;
        _ -> erlang:error(qlog_fixture_file_service_identity)
    end.

join(Pid, Monitor, Timeout) ->
    receive {'DOWN', Monitor, process, Pid, _} -> true after Timeout -> false end.

dead(Pid) -> join(Pid, erlang:monitor(process, Pid), 1000).

qlog_family(Pid, Owner) ->
    First = [P || P <- [Pid | related(Pid)], P =/= Owner, at_module(P, quic_core_qlog_ffi)],
    lists:usort(First ++ [P || Parent <- First, P <- related(Parent), P =/= Owner,
                             at_module(P, quic_core_qlog_ffi)]).

related(Pid) ->
    Links = case process_info(Pid, links) of {links, Values} -> Values; _ -> [] end,
    Monitors = case process_info(Pid, monitors) of
        {monitors, Watched} -> [P || {process, P} <- Watched, is_pid(P)];
        _ -> []
    end,
    Links ++ Monitors.

at_module(Pid, Module) ->
    case process_info(Pid, current_stacktrace) of
        {current_stacktrace, Frames} -> lists:any(fun({M, _, _, _}) -> M =:= Module end, Frames);
        _ -> false
    end.

at_function(Pid, Module, Function) ->
    case process_info(Pid, current_function) of
        {current_function, {Module, Function, _}} -> true;
        _ -> false
    end.

await_device_request(Pid, Deadline) ->
    Found = case process_info(Pid, messages) of
        {messages, Messages} -> lists:any(fun
            ({io_request, _, _, _}) -> true;
            ({file_request, _, _, _}) -> true;
            (_) -> false
        end, Messages);
        _ -> false
    end,
    case Found orelse erlang:monotonic_time(millisecond) >= Deadline of
        true -> Found;
        false -> receive after 1 -> await_device_request(Pid, Deadline) end
    end.

await_device_notice(Guardian, Worker, Device, Deadline) ->
    Found = case process_info(Guardian, messages) of
        {messages, Messages} -> lists:any(fun
            ({qlog_startup_device, Pid, _, File}) -> Pid =:= Worker andalso File =:= Device;
            (_) -> false
        end, Messages);
        _ -> false
    end,
    case Found orelse erlang:monotonic_time(millisecond) >= Deadline of
        true -> Found;
        false -> receive after 1 -> await_device_notice(Guardian, Worker, Device, Deadline) end
    end.

await_function(Pid, Function, Deadline) ->
    Ready = at_function(Pid, quic_core_qlog_ffi, Function),
    case Ready orelse erlang:monotonic_time(millisecond) >= Deadline of
        true -> Ready;
        false -> receive after 1 -> await_function(Pid, Function, Deadline) end
    end.

await_ready_message(Pid, Deadline) ->
    Found = case process_info(Pid, messages) of
        {messages, Messages} -> lists:any(fun
            ({qlog_startup_reply, _, {ok, Writer}}) when is_pid(Writer) -> true;
            (_) -> false
        end, Messages);
        _ -> false
    end,
    case Found orelse erlang:monotonic_time(millisecond) >= Deadline of
        true -> Found;
        false -> receive after 1 -> await_ready_message(Pid, Deadline) end
    end.
