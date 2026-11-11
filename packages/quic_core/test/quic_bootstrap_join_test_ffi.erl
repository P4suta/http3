%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
%% Test-only ownership barrier; only fixed booleans leave this helper.
-module(quic_bootstrap_join_test_ffi).
-export([timeout_join/1, suspended_until/3]).

suspended_until(Pid, Deadline, Callback) ->
    true = erlang:suspend_process(Pid),
    try
        Callback(),
        Wait = max(0, Deadline-quic_core_udp_ffi:monotonic_millisecond()+1),
        true = Wait =< 5000,
        receive after Wait -> true end
    after
        erlang:resume_process(Pid)
    end.

timeout_join(Prepare) ->
    {ok, Socket} = gen_udp:open(0, [binary, {active,false}, {ip,{127,0,0,1}}]),
    try timeout_join_socket(Prepare, Socket)
    after gen_udp:close(Socket) end.

timeout_join_socket(Prepare, Socket) ->
    Parent = self(),
    Ref = make_ref(),
    {ok, {_, Port}} = inet:sockname(Socket),
    %% Certificate-store and OTP service preparation is outside the public
    %% connect operation. Complete it before timing the ownership barrier.
    Connect = Prepare(Port),
    {Caller, CallerMonitor} = spawn_monitor(fun() -> Parent ! {Ref, Connect()} end),
    try
        %% The assertion concerns the public bootstrap's ownership barrier.
        %% First packet arrival also depends on cold TLS/code loading and DNS,
        %% so it is not a synchronization point for that ownership contract.
        Guardian = find_bootstrap_guardian(Caller, erlang:monotonic_time(millisecond)+1500),
        GuardianMonitor = monitor(process, Guardian),
        true = erlang:suspend_process(Guardian),
        %% Freeze admitted callbacks too. A callback still asking for admission
        %% has its own finite group_call deadline; letting that expire would
        %% kill the guardian before the public total deadline is under test.
        %% With the guardian suspended, its finite monitor set cannot grow.
        {monitors, OwnedMonitors} = process_info(Guardian, monitors),
        Owned = lists:usort([Pid || {process, Pid} <- OwnedMonitors,
                                   is_pid(Pid), Pid =/= Caller]),
        true = length(Owned) > 0 andalso length(Owned) =< 19,
        [try erlang:suspend_process(Pid) catch error:badarg -> false end || Pid <- Owned],
        try
            Early = receive {Ref, Result} -> {early, Result} after 2200 -> pending end,
            true = erlang:resume_process(Guardian),
            Timeout = case Early of
                {early, Value} -> Value;
                pending -> receive {Ref, Value} -> Value after 2500 -> false end
            end,
            Joined = receive {'DOWN',GuardianMonitor,process,Guardian,_} -> true after 1500 -> false end,
            {Early =/= pending, Timeout, Joined}
        after
            try erlang:resume_process(Guardian) catch _:_ -> false end,
            [try erlang:resume_process(Pid) catch error:badarg -> false end || Pid <- Owned],
            demonitor(GuardianMonitor, [flush])
        end
    after
        exit(Caller, kill),
        receive {'DOWN',CallerMonitor,process,Caller,_} -> ok
        after 1500 -> error(bootstrap_caller_cleanup_timeout) end
    end.

find_bootstrap_guardian(Caller, Deadline) ->
    Matches = [Pid || Pid <- processes(), guardian_for(Pid, Caller)],
    case {Matches, awaiting_bootstrap(Caller)} of
        {[Pid], true} -> Pid;
        _ -> case erlang:monotonic_time(millisecond) < Deadline of
            true -> receive after 1 -> find_bootstrap_guardian(Caller, Deadline) end;
            false -> error(missing_bootstrap_ownership_barrier)
        end
    end.

awaiting_bootstrap(Caller) ->
    case process_info(Caller, current_stacktrace) of
        {current_stacktrace, Frames} -> lists:any(fun
            ({'quic_core@internal@runtime@client_worker', await_bootstrap, 4, _}) -> true;
            (_) -> false
        end, Frames);
        _ -> false
    end.

-spec guardian_for(pid(), pid()) -> boolean().
guardian_for(Pid, Caller) ->
    case process_info(Pid, [dictionary, monitors, trap_exit]) of
        [{dictionary, Dictionary}, {monitors, Monitors}, {trap_exit, true}] ->
            proplists:get_value('$process_label', Dictionary) =:= <<"quic_core.connect_supervisor">>
                andalso lists:member({process, Caller}, Monitors);
        _ -> false
    end.
