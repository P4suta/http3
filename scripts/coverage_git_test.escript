#!/usr/bin/env escript
%%! +S 2:2 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-compile(nowarn_unused_function).
-include("command_capture.hrl").
-include("diagnostic_failure.hrl").

main([]) ->
    output_limit = command_exit_outcome(
        <<"supervisor_output_limit">>, false, 125),
    deadline = command_exit_outcome(<<"supervisor_deadline">>, false, 124),
    exit_failure = command_exit_outcome(none, false, 125),
    SyntheticLimitProof = command_proof(
        new_command_state(erlang:monotonic_time(millisecond), 1000,
                          16777216, undefined),
        output_limit, 125, true),
    true = maps:get(output_limit_exceeded, SyntheticLimitProof),
    false = maps:get(output_digest_complete, SyntheticLimitProof),
    Root = filename:absname("build/coverage-git-tests/" ++
        binary_to_list(hex(crypto:strong_rand_bytes(16)))),
    try
        ok = filelib:ensure_dir(filename:join(Root, "placeholder")),
        Tests = [{full, 5000, 1048576}, {stream, 1500, 65536},
                 {stall, 1500, 65536}, {flood, 5000, 65536},
                 {private, 5000, 65536}, {late, 5000, 65536}],
        Rows = [control(Mode, Timeout, Limit, Root) || {Mode, Timeout, Limit} <- Tests],
        Missing = command_capture(filename:join(Root, "absent-program"), [], Root,
                                  1000, 65536, []),
        MissingObserved = case Missing of
            {ok, _, P0} -> P0;
            {error, P0} -> P0
        end,
        ok = file:write_file(filename:join(Root, "startup-failure.json"),
            json:encode(maps:without([process_supervisor], MissingObserved))),
        {error, MissingProof = #{outcome := exit_failure, exit_status := 127,
                                child_exit_observed := true,
                                process_supervisor_failure_code :=
                                    <<"child_start_failed">>}} = Missing,
        false = command_success_verified(MissingProof),
        false = process_completion_verified(MissingProof),
        false = process_completion_attestation_verified(MissingProof#{
            process_supervisor_failure_code => <<"unregistered_failure">>}),
        true = lists:all(fun(#{passed := Passed}) -> Passed end, Rows),
        ok = file:write_file(filename:join(Root, "result.json"),
            json:encode(#{passed => true, controls => Rows, startup_failure_rejected => true})),
        io:format("Git command controls passed=7 actual_children_joined=6~n")
    catch Class:Reason:Stack ->
        Failure = #{stage => case get(control_stage) of undefined -> none; Stage -> Stage end,
            failure => control_failure(Reason),
            diagnostic => diagnostic_failure_details(Class, Reason, Stack),
            process => case get(control_proof) of
                undefined -> null; P -> P end},
        _ = file:write_file(filename:join(Root, "failure.json"), json:encode(Failure)),
        io:format(standard_error, "Git command control failed~n", []), halt(1)
    end.

control(Mode, Timeout, Limit, Root) ->
    put(control_stage, Mode), erase(control_proof),
    {ok, Listener} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127,0,0,1}}]),
    Nonce = hex(crypto:strong_rand_bytes(16)), Parent = self(),
    {Observer, Monitor} = spawn_monitor(fun() ->
        try observe_exit(Parent, Listener, Nonce, Timeout, Mode)
        catch _:_ -> Parent ! {native_exit_failed, self()} end
    end),
    try
        {ok, {_, Port}} = inet:sockname(Listener),
        control_observed(Mode, Timeout, Limit, Root, {Observer, Monitor}, Port, Nonce)
    after
        case is_process_alive(Observer) of
            true -> exit(Observer, kill),
                receive {'DOWN', Monitor, process, Observer, _} -> ok after 1000 -> ok end;
            false -> ok
        end,
        demonitor(Monitor, [flush]), gen_tcp:close(Listener)
    end.

control_observed(Mode, Timeout, Limit, Root, Observation, Port, Nonce) ->
    Marker = filename:join(Root, atom_to_list(Mode) ++ ".entered"),
    Prelude = lists:flatten(io_lib:format(
        "spawn(fun()->receive after 10000->halt(124) end end),"
        "{ok,S}=gen_tcp:connect({127,0,0,1},~B,[binary,{active,false}],1000),"
        "ok=gen_tcp:send(S,~0tp),{ok,<<1>>}=gen_tcp:recv(S,1,1000),"
        "ok=file:write_file(~0tp,~0tp,[exclusive]),",
        [Port, Nonce, Marker, Nonce])),
    Code = Prelude ++ case Mode of
        full -> "io:put_chars(binary:copy(<<97>>,262144)),halt(0).";
        stream -> "F=fun Loop(0)->halt(0);Loop(N)->io:put_chars(\"x\"),receive after 20->Loop(N-1) end end,F(150).";
        stall -> "receive never->halt(0) after 4000->halt(0) end.";
        flood -> "F=fun Loop(0)->halt(0);Loop(N)->io:put_chars(binary:copy(<<98>>,32768)),Loop(N-1) end,F(64).";
        private -> "io:put_chars(standard_error,\"coverage-git-private-control\"),halt(7).";
        late -> "halt(0)."
    end,
    Erl = filename:join([code:root_dir(), "bin", case os:type() of {win32, _} -> "erl.exe"; _ -> "erl" end]),
    Arguments = ["+S", "1:1", "+SDcpu", "1", "+SDio", "1", "+A", "1",
        "+hmax", "33554432", "+hmaxib", "true", "+hmaxk", "true", "+hmaxel", "false",
        "-noshell", "-noinput", "-eval", Code],
    Environment = [{"ERL_AFLAGS", false}, {"ERL_FLAGS", false}, {"ERL_ZFLAGS", false},
        {"ERL_CRASH_DUMP_BYTES", "0"}, {"ERL_CRASH_DUMP_SECONDS", "0"}],
    Result = case Mode of
        late -> queued_late_exit(Erl, Arguments, Root, Environment, Observation);
        _ -> command_capture(Erl, Arguments, Root, Timeout, Limit, Environment)
    end,
    Returned = erlang:monotonic_time(millisecond),
    Proof = case Result of {ok, _, P} -> P; {error, P} -> P end,
    SafeProof = maps:with([schema, outcome, exit_status, deadline_ms, elapsed_ms,
                          output_bytes, output_limit_bytes, child_exit_observed,
                          process_supervisor, process_supervisor_protocol_valid,
                          process_supervisor_failure_code,
                          process_supervisor_attestation_failure,
                          process_supervisor_reported_status,
                          process_supervisor_observed_status, native_tree_empty,
                          native_console_isolated,
                          native_descendant_outlived,
                          native_termination_requested], Proof),
    put(control_proof, SafeProof),
    {ok, Nonce} = file:read_file(Marker),
    ExitedAtReturn = actual_exit(Observation, Returned),
    true = process_completion_attestation_verified(Proof),
    true = maps:get(elapsed_ms, Proof) < Timeout + 11000,
    Passed = case {Mode, Result} of
        {full, {ok, Bytes, #{outcome := ok, exit_status := 0,
                            output_bytes := 262144} = FullProof}} ->
            command_success_verified(FullProof) andalso byte_size(Bytes) =:= 262144
                andalso Bytes =:= binary:copy(<<97>>, 262144);
        {stream, {error, #{outcome := deadline, output_bytes := Count}}} -> Count > 0;
        {stall, {error, #{outcome := deadline}}} -> true;
        {flood, {error, #{outcome := output_limit, output_bytes := Count}}} -> Count > Limit;
        {private, {error, #{outcome := exit_failure, exit_status := 7}}} ->
            binary:match(iolist_to_binary(json:encode(Proof)), <<"coverage-git-private-control">>) =:= nomatch;
        {late, {error, #{outcome := deadline}}} -> true;
        _ -> false
    end,
    Row = #{mode => Mode, passed => Passed andalso ExitedAtReturn, proof => SafeProof,
            actual_entry_verified => true, independent_exit_verified => ExitedAtReturn},
    ok = file:write_file(filename:join(Root, atom_to_list(Mode) ++ ".json"), json:encode(Row)),
    Row.

observe_exit(Parent, Listener, Nonce, Timeout, Mode) ->
    {ok, Socket} = gen_tcp:accept(Listener, Timeout),
    try
        {ok, Nonce} = gen_tcp:recv(Socket, byte_size(Nonce), 1000),
        case Mode of
            late -> Parent ! {native_ready, self()},
                receive release_native -> ok after 5000 -> error(release_not_received) end;
            _ -> ok
        end,
        ok = gen_tcp:send(Socket, <<1>>),
        End = gen_tcp:recv(Socket, 1, 15000),
        true = End =:= {error, closed} orelse End =:= {error, econnreset},
        Parent ! {native_exit, self(), erlang:monotonic_time(millisecond)}
    after gen_tcp:close(Socket) end.

actual_exit({Observer, Monitor}, Returned) ->
    Exited = receive {native_exit, Observer, At} -> At;
                     {native_exit_failed, Observer} -> error(native_observer_failed)
             after 16000 -> error(native_fixture_not_reaped) end,
    receive {'DOWN', Monitor, process, Observer, normal} -> ok
    after 1000 -> error(observer_not_joined) end,
    Exited =< Returned + 200.

control_failure({badmatch, {error, enoent}}) -> entry_not_observed;
control_failure({badmatch, {error, timeout}}) -> fixture_timeout;
control_failure({badmatch, false}) -> assertion_failed;
control_failure(_) -> control_failed.

queued_late_exit(Erl, Arguments, Root, Environment, {Observer, _}) ->
    Parent = self(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Now = erlang:monotonic_time(millisecond),
        {Port, Identity} = open_owned_process(Erl, Arguments, Root, Environment,
                                              Now + 500),
        Parent ! {collector_ready, self(), Port, Now + 500},
        Result = command_collect(Port,
            new_command_state(Now, 500, 65536, Identity)),
        Parent ! {collector_result, self(), Result}
    end),
    {Port, Deadline} = receive {collector_ready, Worker, P, D} -> {P, D}
                      after 1000 -> error(collector_not_started) end,
    try
        true = await_receive(Worker, erlang:monotonic_time(millisecond) + 400),
        true = erlang:suspend_process(Worker),
        receive {native_ready, Observer} -> Observer ! release_native
        after 5000 -> error(native_not_ready) end,
        receive {native_exit, Observer, At} -> self() ! {native_exit, Observer, At}
        after 5000 -> error(native_not_exited) end,
        receive never -> ok after max(0, Deadline - erlang:monotonic_time(millisecond) + 20) -> ok end,
        true = erlang:resume_process(Worker),
        Result = receive {collector_result, Worker, R} -> R
                 after 1000 -> error(collector_no_result) end,
        receive {'DOWN', Monitor, process, Worker, normal} -> ok
        after 1000 -> error(collector_not_joined) end,
        Result
    after
        case process_info(Worker, status) of
            {status, suspended} -> erlang:resume_process(Worker);
            _ -> ok
        end,
        case is_process_alive(Worker) of
            true -> kill_owned_child(Port),
                receive {'DOWN', Monitor, process, Worker, _} -> ok after 6000 -> exit(Worker, kill) end;
            false -> ok
        end,
        demonitor(Monitor, [flush])
    end.

await_receive(Worker, Deadline) ->
    case {process_info(Worker, status), process_info(Worker, current_function)} of
        {{status, waiting}, {current_function, {_, command_collect, 2}}} -> true;
        _ -> case erlang:monotonic_time(millisecond) >= Deadline of
            true -> false;
            false -> receive never -> false after 1 -> await_receive(Worker, Deadline) end
        end
    end.
hex(B) -> binary:encode_hex(B).
