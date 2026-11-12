%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_COMMAND_CAPTURE_HRL).
-define(HTTP_COMMAND_CAPTURE_HRL, true).
-include("process_runner.hrl").

%% Retain complete stdout/stderr only for a successful command. Failed command
%% bytes and arguments never enter its proof or exception. A diagnostic caller
%% may supply a finite projector plus an independent schema validator; only the
%% validated projection leaves this function. The finite full buffer is
%% intentional: a Git diff may exceed the diagnostic tail size.
command_capture(Executable, Arguments, Directory, Timeout, Limit, Environment)
  when is_integer(Timeout), Timeout > 0,
       Timeout =< 5400000,
       is_integer(Limit), Limit > 0, Limit =< 16777216 ->
    command_capture_internal(Executable, Arguments, Directory, Timeout, Limit,
                             Environment, none).

command_capture_projected(Executable, Arguments, Directory, Timeout, Limit,
                          Environment, Projector, Validator)
  when is_integer(Timeout), Timeout > 0,
       Timeout =< 5400000,
       is_integer(Limit), Limit > 0, Limit =< 16777216,
       is_function(Projector, 1), is_function(Validator, 1) ->
    command_capture_internal(Executable, Arguments, Directory, Timeout, Limit,
                             Environment, {Projector, Validator}).

command_capture_internal(Executable, Arguments, Directory, Timeout, Limit,
                         Environment, Projection) ->
    Started = erlang:monotonic_time(millisecond),
    State = (new_command_state(Started, Timeout, Limit, undefined))
        #{failure_projection => Projection},
    CrashDirectory = filename:absname(filename:join("build/process-runner",
        "command-crash-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(16), lowercase)))),
    CrashPath = filename:join(CrashDirectory, "erl_crash.dump"),
    ok = filelib:ensure_dir(CrashPath),
    CleanupKey = {command_capture_cleanup, make_ref()},
    put(CleanupKey, no_child),
    try
        CommandEnvironment = command_capture_environment(Environment, CrashPath),
        Opened = try open_owned_process(Executable, Arguments, Directory,
                                        CommandEnvironment, Started + Timeout) of
            Value -> {ok, Value}
        catch
            error:process_supervisor_start_unconfirmed ->
                %% Activation failed, but final tree emptiness was attested.
                put(CleanupKey, confirmed),
                start_failed;
            error:child_exit_unconfirmed ->
                %% Preserve the private crash location while the autonomous
                %% supervisor deadline remains the containment backstop.
                put(CleanupKey, running),
                start_failed;
            error:_ -> start_failed
        end,
        Result = case Opened of
            start_failed -> command_failure_result(State,
                command_proof(State, start_failed, null, false));
            {ok, {Port, Identity}} ->
                put(CleanupKey, running),
                Active = State#{supervisor_identity => Identity},
                try command_collect(Port, Active)
                catch Class:Reason:Stack ->
                    case get({process_runner_owned_tree, Port}) of
                        undefined -> erlang:raise(Class, Reason, Stack);
                        _ -> command_stop(Port, Active#{chunks => []},
                                          collector_failure)
                    end
                end
        end,
        Proof = case Result of
            {ok, _, P} -> P;
            {error, P} -> P;
            {error, _, P} -> P
        end,
        case maps:get(child_exit_observed, Proof, false) of
            true -> put(CleanupKey, confirmed);
            false -> ok
        end,
        Result
    after
        cleanup_child_artifacts(CrashPath, CrashDirectory, erase(CleanupKey))
    end.

command_capture_environment(Environment, CrashPath) ->
    Fixed = ["ERL_CRASH_DUMP", "ERL_CRASH_DUMP_BYTES",
             "ERL_CRASH_DUMP_SECONDS"],
    Filtered = [Entry || Entry = {Name, _} <- Environment,
                         not lists:member(Name, Fixed)],
    [{"ERL_CRASH_DUMP", CrashPath}, {"ERL_CRASH_DUMP_BYTES", "0"},
     {"ERL_CRASH_DUMP_SECONDS", "0"} | Filtered].

new_command_state(Started, Timeout, Limit, Identity) ->
    #{started => Started, deadline => Started + Timeout,
      timeout => Timeout, limit => Limit, bytes => 0, chunks => [],
      supervisor_identity => Identity, supervisor_final => undefined,
      supervisor_failure_code => none,
      supervisor_attestation_failure => none,
      supervisor_protocol_valid => true}.

command_collect(Port, State = #{deadline := Deadline}) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true -> command_stop(Port, State, deadline);
        false ->
            receive
                {Port, {data, Bytes}} when is_binary(Bytes) ->
                    case command_supervisor_packet(Bytes, State) of
                        {output, Next} ->
                            case maps:get(bytes, Next) > maps:get(limit, Next) of
                                true -> command_stop(Port, Next#{chunks => []}, output_limit);
                                false -> command_collect(Port, Next)
                            end;
                        {control, Next} -> command_collect(Port, Next);
                        {error, Next} -> command_stop(Port, Next#{chunks => []},
                                                      supervisor_protocol)
                    end;
                {Port, {exit_status, Status}} when is_integer(Status) ->
                    %% A queued completion cannot make a suspended collector
                    %% accept success after the absolute eligibility deadline.
                    FailureCode = maps:get(supervisor_failure_code, State, none),
                    Outcome = command_exit_outcome(FailureCode,
                        erlang:monotonic_time(millisecond) >= Deadline, Status),
                    case attest_owned_exit(Port, Status, State) of
                        {ok, Attested} ->
                            unregister_owned_tree(Port),
                            Raw = iolist_to_binary(lists:reverse(
                                maps:get(chunks, Attested))),
                            {Semantic, Removed} = command_semantic_output(Raw),
                            Sanitized = Attested#{
                                terminal_control_bytes_removed => Removed},
                            Proof = command_proof(
                                Sanitized, Outcome, Status, true),
                            case Outcome of
                                ok -> command_capture_success_result(
                                    Sanitized, Semantic, Proof);
                                _ -> command_failure_result(Sanitized, Proof)
                            end;
                        {error, Unattested} ->
                            unregister_owned_tree(Port),
                            command_failure_result(Unattested,
                                command_proof(Unattested,
                                    supervisor_unconfirmed, null, false))
                    end
            after Remaining -> command_stop(Port, State, deadline)
            end
    end.

command_exit_outcome(<<"supervisor_output_limit">>, _, 125) -> output_limit;
command_exit_outcome(<<"supervisor_deadline">>, _, 124) -> deadline;
command_exit_outcome(_, true, _) -> deadline;
command_exit_outcome(_, false, 0) -> ok;
command_exit_outcome(_, false, _) -> exit_failure.

command_count(Bytes, State) ->
    State#{bytes => min(9223372036854775807,
                        maps:get(bytes, State) + byte_size(Bytes)),
           chunks => [binary:copy(Bytes) | maps:get(chunks, State)]}.

command_supervisor_packet(<<"O", Bytes/binary>>, State) ->
    {output, command_count(Bytes, State)};
command_supervisor_packet(Packet, State) when byte_size(Packet) =< 64 ->
    case {parse_supervisor_final(Packet), parse_supervisor_error(Packet)} of
        {{ok, Final}, _} ->
            case maps:get(supervisor_final, State, undefined) of
                undefined -> {control, State#{supervisor_final => Final}};
                _ -> {error, State#{supervisor_protocol_valid => false}}
            end;
        {error, {ok, Code}} ->
            {control, State#{supervisor_failure_code => Code}};
        _ -> {error, State#{supervisor_protocol_valid => false}}
    end;
command_supervisor_packet(_, State) ->
    {error, State#{supervisor_protocol_valid => false}}.

command_stop(Port, State, Outcome) ->
    %% STOP asks the pinned supervisor to terminate its process group / Job.
    %% Keep the supervisor port open until its final attestation and exit.
    kill_owned_child(Port),
    StopDeadline = erlang:monotonic_time(millisecond) + 5000,
    command_reap(Port, State#{chunks => []}, Outcome, StopDeadline).

command_reap(Port, State, Outcome, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true -> close_owned_port(Port),
            command_failure_result(State,
                command_proof(State, reap_failed, null, false));
        false ->
            receive
                {Port, {data, Bytes}} when is_binary(Bytes) ->
                    case command_supervisor_packet(Bytes, State) of
                        {output, Next} ->
                            command_reap(Port, Next#{chunks => []}, Outcome, Deadline);
                        {control, Next} -> command_reap(Port, Next, Outcome, Deadline);
                        {error, Next} -> command_reap(Port, Next#{chunks => []},
                                                     supervisor_protocol, Deadline)
                    end;
                {Port, {exit_status, Status}} when is_integer(Status) ->
                    case attest_owned_exit(Port, Status, State) of
                        {ok, Attested} ->
                            unregister_owned_tree(Port),
                            command_failure_result(Attested,
                                command_proof(Attested, Outcome, Status, true));
                        {error, Unattested} ->
                            unregister_owned_tree(Port),
                            command_failure_result(Unattested,
                                command_proof(Unattested,
                                    supervisor_unconfirmed, null, false))
                    end
            after Remaining ->
                close_owned_port(Port),
                command_failure_result(State,
                    command_proof(State, reap_failed, null, false))
            end
    end.

command_failure_result(State, Proof) ->
    Raw = iolist_to_binary(lists:reverse(maps:get(chunks, State))),
    {Semantic, Removed} = command_semantic_output(Raw),
    SafeProof = Proof#{terminal_control_bytes_removed => Removed},
    case {maps:get(failure_projection, State, none),
          maps:get(outcome, SafeProof, invalid)} of
        {none, _} -> {error, SafeProof};
        {_, Outcome} when Outcome =/= exit_failure ->
            {error, no_failure_projection, SafeProof};
        {{Projector, Validator}, exit_failure} ->
            Projection = try Projector(Semantic)
            catch _:_ -> invalid_failure_projection
            end,
            case try Validator(Projection) catch _:_ -> false end of
                true -> {error, Projection, SafeProof};
                false -> {error, invalid_failure_projection, SafeProof}
            end
    end.

%% A native child can exit with status zero while a separately attested
%% completion invariant rejects the run.  This boundary must never turn that
%% disagreement into an assertion after the owned process tree has already
%% been unregistered: callers still need a finite, typed failure from which
%% they can publish current-source evidence.  Semantic output is deliberately
%% discarded on this path.
command_capture_success_result(_State, Semantic, Proof) ->
    case command_success_verified(Proof) of
        true -> {ok, Semantic, Proof};
        false -> {error, Proof}
    end.

%% Windows ConPTY is the no-window containment boundary for native children,
%% but it also injects terminal setup, title, and teardown controls into the
%% byte stream.  Consumers need the program's semantic output, while resource
%% accounting must continue to use the larger raw stream.  Strip complete CSI
%% and OSC controls only after the raw output has been bounded and retained.
%% An unterminated control consumes the finite remainder so its payload (often
%% an executable path in OSC 0) cannot escape through a diagnostic projector.
command_semantic_output(Bytes) when is_binary(Bytes) ->
    command_semantic_output(Bytes, [], 0).

command_semantic_output(<<>>, Chunks, Removed) ->
    {iolist_to_binary(lists:reverse(Chunks)), Removed};
command_semantic_output(Bytes, Chunks, Removed) ->
    case binary:match(Bytes, <<27>>) of
        nomatch ->
            {iolist_to_binary(lists:reverse([Bytes | Chunks])), Removed};
        {Offset, 1} ->
            <<Prefix:Offset/binary, 27, Rest/binary>> = Bytes,
            NextChunks = case Prefix of
                <<>> -> Chunks;
                _ -> [Prefix | Chunks]
            end,
            command_semantic_escape(Rest, NextChunks, Removed + 1)
    end.

command_semantic_escape(<<>>, Chunks, Removed) ->
    command_semantic_output(<<>>, Chunks, Removed);
command_semantic_escape(<<"[", Rest/binary>>, Chunks, Removed) ->
    {Tail, ControlBytes} = command_semantic_csi(Rest, 1),
    command_semantic_output(Tail, Chunks, Removed + ControlBytes);
command_semantic_escape(<<"]", Rest/binary>>, Chunks, Removed) ->
    {Tail, ControlBytes} = command_semantic_osc(Rest),
    command_semantic_output(Tail, Chunks, Removed + 1 + ControlBytes);
command_semantic_escape(<<_Escape, Rest/binary>>, Chunks, Removed) ->
    command_semantic_output(Rest, Chunks, Removed + 1).

command_semantic_csi(<<>>, Count) -> {<<>>, Count};
command_semantic_csi(<<Byte, Rest/binary>>, Count)
  when Byte >= 16#40, Byte =< 16#7e ->
    {Rest, Count + 1};
command_semantic_csi(<<Byte, Rest/binary>>, Count)
  when Byte >= 16#20, Byte =< 16#3f ->
    command_semantic_csi(Rest, Count + 1);
command_semantic_csi(Rest, Count) -> {Rest, Count}.

command_semantic_osc(Bytes) ->
    Bell = binary:match(Bytes, <<7>>),
    StringTerminator = binary:match(Bytes, <<27, $\\>>),
    case command_first_terminal(Bell, StringTerminator) of
        none -> {<<>>, byte_size(Bytes)};
        {bell, Offset} ->
            <<_Payload:Offset/binary, 7, Rest/binary>> = Bytes,
            {Rest, Offset + 1};
        {st, Offset} ->
            <<_Payload:Offset/binary, 27, $\\, Rest/binary>> = Bytes,
            {Rest, Offset + 2}
    end.

command_first_terminal(nomatch, nomatch) -> none;
command_first_terminal({Bell, 1}, nomatch) -> {bell, Bell};
command_first_terminal(nomatch, {St, 2}) -> {st, St};
command_first_terminal({Bell, 1}, {St, 2}) when Bell =< St -> {bell, Bell};
command_first_terminal({_Bell, 1}, {St, 2}) -> {st, St}.

command_proof(State, Outcome, Exit, Joined) ->
    Base = #{schema => 1, outcome => Outcome, exit_status => Exit,
      deadline_ms => maps:get(timeout, State),
      elapsed_ms => max(0, erlang:monotonic_time(millisecond) - maps:get(started, State)),
      output_bytes => maps:get(bytes, State), output_limit_bytes => maps:get(limit, State),
      output_limit_exceeded => Outcome =:= output_limit,
      output_digest_complete => Outcome =/= output_limit,
      terminal_control_bytes_removed =>
          maps:get(terminal_control_bytes_removed, State, 0),
      timed_out => Outcome =:= deadline,
      child_exit_observed => Joined},
    command_supervisor_proof(Base, State).

command_supervisor_proof(Base, #{supervisor_identity := undefined}) -> Base;
command_supervisor_proof(Base, State) ->
    Final = case maps:get(supervisor_final, State, undefined) of
        Value when is_map(Value) -> Value;
        _ -> #{}
    end,
    Base#{process_supervisor => maps:get(supervisor_identity, State),
          process_supervisor_protocol_valid =>
              maps:get(supervisor_protocol_valid, State, false),
          process_supervisor_failure_code =>
              maps:get(supervisor_failure_code, State, none),
          process_supervisor_attestation_failure =>
              maps:get(supervisor_attestation_failure, State, none),
          process_supervisor_reported_status =>
              case Final of
                  #{status := ReportedStatus} -> ReportedStatus;
                  _ -> -1
              end,
          process_supervisor_observed_status =>
              maps:get(supervisor_observed_status, State, -1),
          native_tree_empty => maps:get(tree_empty, Final, false),
          native_console_isolated =>
              maps:get(console_isolated, Final, false),
          native_descendant_outlived =>
              maps:get(descendant_outlived, Final, false),
          native_termination_requested =>
              maps:get(termination_requested, Final, false)}.

command_success_verified(Proof) when is_map(Proof) ->
    maps:get(outcome, Proof, invalid) =:= ok
        andalso maps:get(exit_status, Proof, -1) =:= 0
        andalso process_completion_verified(Proof)
        andalso not maps:get(native_descendant_outlived, Proof, true)
        andalso not maps:get(native_termination_requested, Proof, true);
command_success_verified(_) -> false.

-endif.
