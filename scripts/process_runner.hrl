%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PROCESS_RUNNER_HRL).
-define(HTTP_PROCESS_RUNNER_HRL, true).
-compile({nowarn_unused_function, [
    {run_child_boot, 4},
    {collect_eunit_with_deadline_stop, 4},
    {collect_before_deadline_with_stop, 4},
    {process_status_verified, 3},
    {process_deadline_verified, 2},
    {process_output_limit_verified, 2},
    {bounded_file_sha256_with_hook, 3},
    {process_file_snapshot, 2},
    {process_file_snapshot_with_hook, 3},
    {process_verify_snapshot, 2},
    {new_output, 0},
    {output_tail, 1}
]}).

run_child_evaluation(Directory, Paths, Evaluation, Milliseconds) ->
    run_process_runner_worker(fun() ->
        true = is_integer(Milliseconds) andalso Milliseconds > 0 andalso
            Milliseconds =< 5400000,
        %% Windows rejects sufficiently long CreateProcess command lines. Keep
        %% the executable argument small; bind the finite input bytes before
        %% evaluating them in the owned VM. The worker owns this file too, so
        %% caller death cannot strand evaluation text containing private paths.
        Input = unicode:characters_to_binary(Evaluation),
        true = byte_size(Input) =< 2097152,
        case child_evaluation_starts_external_process(Input) of
            true -> erlang:error(child_evaluation_external_process_forbidden);
            false -> ok
        end,
        InputPath = filename:absname(filename:join("build/process-runner",
            "evaluation-" ++ binary_to_list(binary:encode_hex(
                crypto:strong_rand_bytes(16))) ++ ".erl")),
        ok = filelib:ensure_dir(InputPath),
        ok = file:write_file(InputPath, Input, [exclusive]),
        Digest = binary:encode_hex(crypto:hash(sha256, Input)),
        Boot = lists:flatten(io_lib:format(
            "{ok,F}=file:open(~0tp,[read,binary,raw]),"
            "{ok,B}=file:read(F,2097153),ok=file:close(F),"
            "true=byte_size(B)=<2097152,"
            "~0tp=binary:encode_hex(crypto:hash(sha256,B)),"
            "{ok,T,_}=erl_scan:string(unicode:characters_to_list(B)),"
            "{ok,E}=erl_parse:parse_exprs(T),erl_eval:exprs(E,[]).",
            [InputPath, Digest])),
        try run_child_boot_owned(Directory, Paths, Boot, Milliseconds)
        after
            case file:delete(InputPath) of
                ok -> ok;
                {error, enoent} -> ok;
                _ -> erlang:error(cannot_remove_child_evaluation)
            end
        end
    end, Milliseconds).

run_child_boot(Directory, Paths, Evaluation, Milliseconds) ->
    %% Never change the caller's exit-signal semantics.  open_port/2 links the
    %% port to its connected Erlang process, so the short-lived trap_exit state
    %% required to reconcile an EXIT/exit_status race belongs to an otherwise
    %% unlinked worker.  In particular, an unrelated process linked to the
    %% caller must still terminate that caller while a native suite is running.
    true = is_integer(Milliseconds) andalso Milliseconds > 0 andalso
        Milliseconds =< 5400000,
    run_process_runner_worker(fun() ->
        run_child_boot_owned(Directory, Paths, Evaluation, Milliseconds)
    end, Milliseconds).

run_process_runner_worker(Operation, Milliseconds) ->
    true = is_function(Operation, 0),
    true = is_integer(Milliseconds) andalso Milliseconds > 0 andalso
        Milliseconds =< 5400000,
    Owner = self(),
    Token = make_ref(),
    WorkerDeadline = erlang:monotonic_time(millisecond) +
        (Milliseconds + 15000),
    Worker = spawn(fun() -> process_runner_worker(Owner, Token, Operation) end),
    Monitor = erlang:monitor(process, Worker),
    await_process_runner_worker(Worker, Monitor, Token, WorkerDeadline).

process_runner_worker(Owner, Token, Operation) ->
    put(process_runner_owner_token, Token),
    Worker = self(),
    Guard = spawn(fun() -> process_runner_owner_guard(Owner, Worker, Token) end),
    receive
        {process_runner_owner_guard_ready, Token, Guard} -> ok
    after 5000 -> exit(process_runner_owner_guard_start_failed)
    end,
    Outcome = try Operation() of
        Value -> {return, Value}
    catch
        Class:Reason:Stack -> {raise, Class, Reason, Stack}
    end,
    Owner ! {process_runner_worker_result, Token, Outcome},
    Guard ! {process_runner_worker_done, Token},
    erase(process_runner_owner_token),
    ok.

process_runner_owner_guard(Owner, Worker, Token) ->
    OwnerMonitor = erlang:monitor(process, Owner),
    WorkerMonitor = erlang:monitor(process, Worker),
    Worker ! {process_runner_owner_guard_ready, Token, self()},
    receive
        {process_runner_worker_done, Token} ->
            erlang:demonitor(OwnerMonitor, [flush]),
            erlang:demonitor(WorkerMonitor, [flush]),
            ok;
        {'DOWN', OwnerMonitor, process, Owner, _} ->
            %% Ask the worker to drive the normal STOP/final/tree-empty path.
            %% A fixed kill fallback exists only for a worker unable to reach
            %% any of its bounded receive points after its owner disappeared.
            Worker ! {process_runner_owner_cancel, Token},
            receive
                {'DOWN', WorkerMonitor, process, Worker, _} -> ok
            after 15000 ->
                exit(Worker, kill),
                receive
                    {'DOWN', WorkerMonitor, process, Worker, _} -> ok
                after 5000 -> ok
                end
            end;
        {'DOWN', WorkerMonitor, process, Worker, _} ->
            erlang:demonitor(OwnerMonitor, [flush]),
            ok
    end.

await_process_runner_worker(Worker, Monitor, Token, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true -> cancel_process_runner_worker(Worker, Monitor, Token);
        false ->
            receive
                {process_runner_worker_result, Token, Outcome} ->
                    case await_process_runner_worker_down(
                             Worker, Monitor,
                             erlang:monotonic_time(millisecond) + 5000) of
                        confirmed -> process_runner_worker_outcome(Outcome);
                        unconfirmed ->
                            erlang:error(process_runner_worker_exit_unconfirmed)
                    end;
                {'DOWN', Monitor, process, Worker, _} ->
                    %% Result is sent before the normal worker exit. Erlang
                    %% preserves signal order from one sender, so observing
                    %% DOWN first proves that no result can be accepted.
                    erlang:error(process_runner_worker_failed)
            after Remaining ->
                cancel_process_runner_worker(Worker, Monitor, Token)
            end
    end.

await_process_runner_worker_down(Worker, Monitor, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true ->
            exit(Worker, kill),
            unconfirmed;
        false ->
            receive
                {'DOWN', Monitor, process, Worker, normal} -> confirmed;
                {'DOWN', Monitor, process, Worker, _} -> unconfirmed
            after Remaining ->
                exit(Worker, kill),
                receive
                    {'DOWN', Monitor, process, Worker, _} -> ok
                after 5000 -> ok
                end,
                unconfirmed
            end
    end.

cancel_process_runner_worker(Worker, Monitor, Token) ->
    Worker ! {process_runner_owner_cancel, Token},
    CleanupDeadline = erlang:monotonic_time(millisecond) + 10000,
    cancel_process_runner_worker_wait(Worker, Monitor, Token, CleanupDeadline).

cancel_process_runner_worker_wait(Worker, Monitor, Token, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true ->
            exit(Worker, kill),
            receive
                {'DOWN', Monitor, process, Worker, _} -> ok
            after 5000 -> ok
            end,
            erlang:error(process_runner_worker_timeout);
        false ->
            receive
                {process_runner_worker_result, Token, _Outcome} ->
                    cancel_process_runner_worker_wait(
                        Worker, Monitor, Token, Deadline);
                {'DOWN', Monitor, process, Worker, _} ->
                    erlang:error(process_runner_worker_timeout)
            after Remaining ->
                cancel_process_runner_worker_wait(
                    Worker, Monitor, Token, Deadline)
            end
    end.

process_runner_worker_outcome({return, Value}) -> Value;
process_runner_worker_outcome({raise, Class, Reason, Stack}) ->
    erlang:raise(Class, Reason, Stack);
process_runner_worker_outcome(_) ->
    erlang:error(process_runner_worker_protocol_invalid).

run_child_boot_owned(Directory, Paths, Evaluation, Milliseconds) ->
    %% The evidence records this VM's runtime. A different `erl` earlier on
    %% PATH must not silently execute the suite with another OTP installation.
    Executable = case os:type() of {win32, _} -> "erl.exe"; _ -> "erl" end,
    Erl = filename:join([code:root_dir(), "bin", Executable]),
    true = filelib:is_regular(Erl),
    %% The child's independent watchdog survives a blocked test and guarantees
    %% normal deadline teardown even when closing stdin would leave BEAM alive.
    WatchdogMilliseconds = Milliseconds + 5000,
    Guarded = lists:flatten([
        "spawn(fun()->receive stop->ok after ", integer_to_list(WatchdogMilliseconds),
        "->erlang:halt(124) end end),", Evaluation
    ]),
    PathArguments = case Paths of
        [] -> [];
        _ -> ["-pa" | Paths]
    end,
    %% EUnit captures ordinary test I/O internally, before it reaches this
    %% port's output limit. Bound those actors' heaps and referenced binaries.
    Arguments = ["+hmax", "33554432", "+hmaxib", "true", "+hmaxk", "true",
                 "+hmaxel", "false", "-noshell", "-noinput"] ++
                 PathArguments ++ ["-eval", Guarded],
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    CrashDumpPath = filename:absname(filename:join([
        "build/process-runner",
        "crash-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(16), lowercase)),
        "erl_crash.dump"])),
    CrashDumpDirectory = filename:dirname(CrashDumpPath),
    ok = filelib:ensure_dir(CrashDumpPath),
    CleanupKey = {process_runner_crash_cleanup, make_ref()},
    put(CleanupKey, no_child),
    try
        %% `hide` is applied to the one pinned supervisor. It owns the complete
        %% native process tree and reports a final tree-empty attestation.
        Environment = [{"ERL_CRASH_DUMP", CrashDumpPath},
                       {"ERL_CRASH_DUMP_BYTES", "0"},
                       {"ERL_CRASH_DUMP_SECONDS", "0"},
                       {"ERL_AFLAGS", false}, {"ERL_FLAGS", false},
                       {"ERL_ZFLAGS", false}],
        Opened = try open_owned_process(
            Erl, Arguments, Directory, Environment, Deadline) of
            Value -> Value
        catch
            error:process_supervisor_start_unconfirmed ->
                %% START delivery was uncertain, but the supervisor proved its
                %% final state and native-tree emptiness before returning here.
                put(CleanupKey, confirmed),
                erlang:error(process_supervisor_start_unconfirmed);
            error:child_exit_unconfirmed ->
                %% The supervisor has its own finite deadline, but without its
                %% final frame the private crash directory must remain intact.
                put(CleanupKey, running),
                erlang:error(child_exit_unconfirmed)
        end,
        {Port, SupervisorIdentity} = Opened,
        put(CleanupKey, running),
        {Status, Output} = collect_eunit(
            Port, new_output(SupervisorIdentity), Deadline),
        case maps:get(child_exit_observed, Output) of
            true ->
                unregister_owned_tree(Port),
                put(CleanupKey, confirmed),
                {Status, Output};
            false ->
                io:format(standard_error,
                          "process supervisor completion unconfirmed: ~p~n",
                          [#{failure_code => maps:get(
                                process_supervisor_failure_code, Output,
                                missing_final_attestation),
                             protocol_valid => maps:get(
                                process_supervisor_protocol_valid, Output, false),
                             attestation_failure => maps:get(
                                process_supervisor_attestation_failure, Output,
                                unknown),
                             tree_empty => maps:get(native_tree_empty,
                                                    Output, false),
                             console_isolated => maps:get(
                                native_console_isolated, Output, false),
                             descendant_outlived => maps:get(
                                native_descendant_outlived, Output, false),
                             reported_status => maps:get(
                                process_supervisor_reported_status, Output, -1),
                             observed_status => maps:get(
                                process_supervisor_observed_status, Output, -1)}]),
                erlang:error(child_exit_unconfirmed)
        end
    after
        cleanup_child_artifacts(CrashDumpPath, CrashDumpDirectory,
                                erase(CleanupKey))
    end.

process_supervisor_sha256() ->
    <<"c75f5c426e03a5935e666a348321fd79dc2ae3083402a505979f8d9e6666fb54">>.

process_supervisor_isolation() ->
    case os:type() of
        {win32, _} -> <<"conpty-v1">>;
        _ -> <<"session-v1">>
    end.

open_owned_process(Executable, Arguments, Directory, Environment, Deadline) ->
    Script = filename:absname("scripts/process_supervisor.py"),
    Expected = process_supervisor_sha256(),
    ScriptSnapshot = process_file_snapshot(Script, 131072),
    Expected = maps:get(sha256, ScriptSnapshot),
    Python = process_supervisor_python(),
    PythonSnapshot = process_file_snapshot(Python, 134217728),
    PythonSha = maps:get(sha256, PythonSnapshot),
    %% This literal is part of the independently parsed console-safety contract.
    %% Keep it aligned with process_supervisor.py and windows_console_audit.escript.
    SupervisorDuration = erlang:max(1, erlang:min(
        5400000, Deadline - erlang:monotonic_time(millisecond))),
    SupervisorOutputLimit = 16777216,
    SupervisorArguments = ["-I", "-B", Script, "--expected-sha256",
                           binary_to_list(Expected),
                           "--expected-python-sha256",
                           binary_to_list(PythonSha), "--deadline-ms",
                           integer_to_list(SupervisorDuration),
                           "--output-limit-bytes",
                           integer_to_list(SupervisorOutputLimit),
                           "--", Executable |
                           Arguments],
    SupervisorEnvironment = supervisor_environment(Environment),
    ok = acquire_owned_port_trap(),
    Port = try open_port({spawn_executable, Python},
                         [binary, exit_status, use_stdio, stderr_to_stdout,
                          hide, {packet, 4}, {args, SupervisorArguments},
                          {cd, Directory}, {env, SupervisorEnvironment}])
    catch error:Reason ->
        release_owned_port_trap(),
        erlang:error({child_start_failed, child_start_category(Reason)})
    end,
    ProvisionalIdentity = #{source_sha256 => Expected,
        python_executable_sha256 => PythonSha,
        console_isolation => process_supervisor_isolation(),
        python_implementation => <<"pending">>, python_version => <<>>},
    put({process_runner_owned_tree, Port},
        #{supervisor_identity => ProvisionalIdentity,
          os_pid => unavailable, termination_requested => false,
          trap_acquired => true}),
    case try_register_owned_tree(Port, ProvisionalIdentity) of
        ok -> ok;
        error ->
            %% The Port itself is still an exact ownership token even when
            %% the OS pid cannot be queried.  Record that bounded token before
            %% asking the pre-START supervisor to prove its empty tree.
            put({process_runner_owned_tree, Port},
                #{supervisor_identity => ProvisionalIdentity,
                  os_pid => unavailable, termination_requested => false,
                  trap_acquired => true}),
            case recover_owned_supervisor(
                     Port, ProvisionalIdentity, fun close_owned_port/1) of
                confirmed ->
                    erlang:error(process_supervisor_registration_failed);
                unconfirmed -> erlang:error(child_exit_unconfirmed)
            end
    end,
    HandshakeDeadline = erlang:min(Deadline,
        erlang:monotonic_time(millisecond) + 5000),
    case await_supervisor_handshake(Port, Expected, PythonSha,
                                    SupervisorDuration,
                                    SupervisorOutputLimit,
                                    HandshakeDeadline) of
        {ok, Runtime} ->
            Identity = Runtime,
            try
                ok = process_verify_snapshot(ScriptSnapshot, 131072),
                ok = process_verify_snapshot(PythonSnapshot, 134217728)
            catch _:_ ->
                case recover_owned_supervisor(
                         Port, ProvisionalIdentity,
                         fun close_owned_port/1) of
                    confirmed ->
                        erlang:error(process_supervisor_identity_changed);
                    unconfirmed -> erlang:error(child_exit_unconfirmed)
                end
            end,
            ok = activate_process_supervisor(Port, Identity, Deadline,
                fun register_owned_tree/2,
                fun(P) -> port_command(P, <<"START">>) end,
                fun close_owned_port/1),
            {Port, Identity};
        {error, Category} ->
            case recover_owned_supervisor(
                     Port, ProvisionalIdentity, fun close_owned_port/1) of
                confirmed -> erlang:error(Category);
                unconfirmed -> erlang:error(child_exit_unconfirmed)
            end
    end.

process_supervisor_python() ->
    case os:getenv("HTTP_PROCESS_SUPERVISOR_PYTHON") of
        Override when is_list(Override), Override =/= [] ->
            Path = filename:absname(Override),
            case filelib:is_regular(Path) of
                true -> Path;
                false -> erlang:error(process_supervisor_runtime_missing)
            end;
        _ ->
            case os:find_executable("python3") of
                Python3 when is_list(Python3) ->
                    process_runtime_executable(Python3, 32);
                false ->
                    case os:find_executable("python") of
                        Python when is_list(Python) ->
                            process_runtime_executable(Python, 32);
                        false -> erlang:error(process_supervisor_runtime_missing)
                    end
            end
    end.

-spec process_runtime_executable(string(), non_neg_integer()) -> string().
process_runtime_executable(Path0, Remaining) when Remaining > 0 ->
    Path = filename:absname(Path0),
    case file:read_link_info(Path) of
        {ok, Info} when element(3, Info) =:= regular -> Path;
        {ok, Info} when element(3, Info) =:= symlink ->
            case file:read_link(Path) of
                {ok, Target} ->
                    process_runtime_executable(
                        filename:absname(Target, filename:dirname(Path)),
                        Remaining - 1);
                _ -> erlang:error(process_supervisor_runtime_missing)
            end;
        _ -> erlang:error(process_supervisor_runtime_missing)
    end;
process_runtime_executable(_, _) ->
    erlang:error(process_supervisor_runtime_missing).

supervisor_environment(Environment) ->
    FixedNames = ["PYTHONDONTWRITEBYTECODE", "PYTHONUTF8"],
    Filtered = [Entry || Entry = {Name, _} <- Environment,
                         not lists:member(Name, FixedNames)],
    [{"PYTHONDONTWRITEBYTECODE", "1"}, {"PYTHONUTF8", "1"} | Filtered].

bounded_file_sha256(Path, Limit) ->
    maps:get(sha256, process_file_snapshot(Path, Limit)).

bounded_file_sha256_with_hook(Path, Limit, Hook) ->
    maps:get(sha256, process_file_snapshot_with_hook(Path, Limit, Hook)).

process_file_snapshot(Path, Limit) ->
    process_file_snapshot_with_hook(Path, Limit, fun() -> ok end).

process_file_snapshot_with_hook(Path0, Limit, Hook)
  when is_integer(Limit), Limit >= 0, is_function(Hook, 0) ->
    Path = filename:absname(Path0),
    Initial = process_regular_info(Path),
    Size = element(2, Initial),
    process_file_ensure(Size >= 0 andalso Size =< Limit,
                        file_size_rejected),
    process_file_ensure(element(9, Initial) =:= 1,
                        file_hardlink_rejected),
    File = case file:open(Path, [read, binary, raw]) of
        {ok, Handle} -> Handle;
        {error, _} -> process_file_error(file_read_failed)
    end,
    {Bytes, Finished} = try
        Opened = process_handle_info(File),
        process_file_ensure(element(3, Opened) =:= regular andalso
                            element(9, Opened) =:= 1 andalso
                            process_file_identity(Initial) =:=
                                process_file_identity(Opened),
                            file_changed_while_reading),
        ok = Hook(),
        Captured = process_read_bounded(File, Size, []),
        FinalHandle = process_handle_info(File),
        process_file_ensure(process_file_identity(Opened) =:=
                                process_file_identity(FinalHandle) andalso
                            byte_size(Captured) =:= Size,
                            file_changed_while_reading),
        {Captured, FinalHandle}
    after
        ok = file:close(File)
    end,
    FinalPath = process_regular_info(Path),
    process_file_ensure(process_file_identity(Finished) =:=
                            process_file_identity(FinalPath),
                        file_changed_while_reading),
    #{path => Path, bytes => Bytes,
      sha256 => binary:encode_hex(crypto:hash(sha256, Bytes), lowercase),
      identity => process_file_identity(Finished)};
process_file_snapshot_with_hook(_, _, _) ->
    process_file_error(file_size_rejected).

process_verify_snapshot(#{path := Path, sha256 := Expected,
                          identity := Identity}, Limit) ->
    Current = process_file_snapshot(Path, Limit),
    process_file_ensure(maps:get(sha256, Current) =:= Expected andalso
                        maps:get(identity, Current) =:= Identity,
                        file_changed_while_reading),
    ok;
process_verify_snapshot(_, _) -> process_file_error(file_changed_while_reading).

process_read_bounded(File, Remaining, Acc) when Remaining >= 0 ->
    Request = erlang:min(Remaining + 1, 65536),
    case file:read(File, Request) of
        eof -> iolist_to_binary(lists:reverse(Acc));
        {ok, Chunk} when byte_size(Chunk) > 0,
                         byte_size(Chunk) =< Remaining ->
            process_read_bounded(File, Remaining - byte_size(Chunk),
                                 [Chunk | Acc]);
        {ok, _} -> process_file_error(file_changed_while_reading);
        {error, _} -> process_file_error(file_read_failed)
    end.

process_regular_info(Path) ->
    process_regular_components(filename:split(filename:absname(Path)), "").

process_regular_components([Name], Parent) ->
    Current = process_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= regular -> Info;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            process_file_error(file_link_rejected);
        {ok, _} -> process_file_error(file_special_file_rejected);
        {error, enoent} -> process_file_error(file_missing);
        {error, _} -> process_file_error(file_inspection_failed)
    end;
process_regular_components([Name | Rest], Parent) ->
    Current = process_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            process_regular_components(Rest, Current);
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            process_file_error(file_parent_link_rejected);
        {ok, _} -> process_file_error(file_parent_rejected);
        {error, enoent} -> process_file_error(file_missing);
        {error, _} -> process_file_error(file_inspection_failed)
    end;
process_regular_components([], _) -> process_file_error(file_path_rejected).

process_handle_info(File) ->
    case file:read_file_info(File) of
        {ok, Info} -> Info;
        {error, _} -> process_file_error(file_inspection_failed)
    end.

process_file_identity(Info) ->
    %% atime is intentionally excluded because the verification read itself
    %% can update it.  Link count, device, inode and change times remain bound.
    {element(2, Info), element(3, Info), element(4, Info), element(6, Info),
     element(7, Info), element(8, Info), element(9, Info), element(10, Info),
     element(11, Info), element(12, Info)}.

process_join_component("", Name) -> Name;
process_join_component(Parent, Name) -> filename:join(Parent, Name).

process_file_ensure(true, _) -> ok;
process_file_ensure(false, Reason) -> process_file_error(Reason).

process_file_error(Reason) -> erlang:error({process_file_rejected, Reason}).

await_supervisor_handshake(Port, Expected, ExpectedPython, Duration,
                           OutputLimit, Deadline) ->
    OwnerToken = get(process_runner_owner_token),
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true -> {error, process_supervisor_handshake_timeout};
        false ->
            receive
                {Port, {data, Packet}} ->
                    parse_supervisor_handshake(Packet, Expected,
                                               ExpectedPython, Duration,
                                               OutputLimit);
                {Port, {exit_status, _}} ->
                    {error, process_supervisor_start_failed};
                {'EXIT', Port, _} ->
                    {error, process_supervisor_start_failed};
                {process_runner_owner_cancel, OwnerToken}
                  when is_reference(OwnerToken) ->
                    {error, process_runner_owner_terminated}
            after Remaining -> {error, process_supervisor_handshake_timeout}
            end
    end.

parse_supervisor_handshake(Packet, Expected, ExpectedPython, Duration,
                           OutputLimit)
  when is_binary(Packet), byte_size(Packet) =< 256 ->
    case binary:split(Packet, <<"|">>, [global]) of
        [<<"H">>, Expected, ExpectedPython, <<"CPython">>, Version,
         DurationBytes,
         OutputLimitBytes, Isolation] ->
            VersionValid = re:run(Version,
                <<"^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$">>,
                [{capture, none}]) =:= match,
            case {VersionValid, bounded_decimal(DurationBytes, 1, 5400000),
                  bounded_decimal(OutputLimitBytes, 1, 16777216),
                  Isolation =:= process_supervisor_isolation()} of
                {true, {ok, Duration}, {ok, OutputLimit}, true} ->
                    {ok, #{source_sha256 => Expected,
                           python_executable_sha256 => ExpectedPython,
                           python_implementation => <<"CPython">>,
                           python_version => Version,
                           console_isolation => Isolation}};
                _ -> {error, process_supervisor_identity_invalid}
            end;
        _ -> {error, process_supervisor_identity_invalid}
    end;
parse_supervisor_handshake(_, _, _, _, _) ->
    {error, process_supervisor_identity_invalid}.

bounded_decimal(Bytes, Minimum, Maximum) when is_binary(Bytes) ->
    case re:run(Bytes, <<"^[0-9]{1,9}$">>, [{capture, none}]) of
        match ->
            Value = binary_to_integer(Bytes),
            case Value >= Minimum andalso Value =< Maximum of
                true -> {ok, Value};
                false -> error
            end;
        nomatch -> error
    end.

activate_process_supervisor(Port, Identity, Deadline, Register, Start, Close) ->
    ensure_owned_identity(Port, Identity),
    Registered = try Register(Port, Identity) of
        ok -> true;
        _ -> false
    catch _:_ -> false
    end,
    case Registered of
        false ->
            case recover_owned_supervisor(Port, Identity, Close) of
                confirmed ->
                    erlang:error(process_supervisor_registration_failed);
                unconfirmed -> erlang:error(child_exit_unconfirmed)
            end;
        true ->
            Started = try Start(Port) of true -> true; _ -> false
                      catch _:_ -> false
                      end,
            case Started of
                true -> ok;
                false ->
                    %% A false return or exception does not prove that START
                    %% was not delivered. Keep ownership registered, send STOP,
                    %% and require the same final/exit/tree attestation as every
                    %% other teardown before classifying the activation error.
                    case recover_uncertain_supervisor_start(
                             Port, Identity, Deadline, Close) of
                        confirmed ->
                            erlang:error(process_supervisor_start_unconfirmed);
                        unconfirmed -> erlang:error(child_exit_unconfirmed)
                    end
            end
    end.

recover_uncertain_supervisor_start(Port, Identity, Deadline, Close) ->
    %% The operation deadline cannot erase the independent cleanup budget.
    %% It is accepted here to preserve the public helper shape checked by the
    %% console audit, while teardown always uses its own absolute deadline.
    true = is_integer(Deadline),
    recover_owned_supervisor(Port, Identity, Close).

recover_owned_supervisor(Port, Identity, Close) ->
    TeardownDeadline = erlang:monotonic_time(millisecond) + 5000,
    Result = try
        _ = kill_owned_child(Port),
        await_child_exit(Port, new_output(Identity), TeardownDeadline)
    catch _:_ -> {pending, undefined}
    end,
    case Result of
        {exited, _Attested} ->
            unregister_owned_tree(Port),
            safe_close_callback(Close, Port),
            confirmed;
        _ ->
            %% Closing the exact owned Port is the bounded containment fallback.
            %% The failure remains unconfirmed; retiring the exact token only
            %% restores the caller's trap state and cannot convert it to success.
            retire_unconfirmed_owned_tree(Port, Close),
            unconfirmed
    end.

safe_close_callback(Close, Port) ->
    try Close(Port) of _ -> ok catch _:_ -> ok end.

register_owned_tree(Port, Identity) ->
    case erlang:port_info(Port, os_pid) of
        {os_pid, OsPid} when is_integer(OsPid), OsPid > 0 ->
            Existing = case get({process_runner_owned_tree, Port}) of
                Value when is_map(Value) -> Value;
                _ -> #{}
            end,
            put({process_runner_owned_tree, Port},
                Existing#{supervisor_identity => Identity, os_pid => OsPid,
                          termination_requested => false,
                          trap_acquired => maps:get(
                              trap_acquired, Existing, false)}),
            ok;
        _ -> erlang:error(child_process_identity_unavailable)
    end.

try_register_owned_tree(Port, Identity) ->
    try register_owned_tree(Port, Identity) of
        ok -> ok
    catch _:_ -> error
    end.

ensure_owned_identity(Port, Identity) ->
    case get({process_runner_owned_tree, Port}) of
        #{os_pid := OsPid} = Ownership ->
            put({process_runner_owned_tree, Port},
                Ownership#{supervisor_identity => Identity,
                           os_pid => OsPid}),
            ok;
        _ ->
            put({process_runner_owned_tree, Port},
                #{supervisor_identity => Identity, os_pid => unavailable,
                  termination_requested => false,
                  trap_acquired => false}),
            ok
    end.

unregister_owned_tree(Port) ->
    Ownership = erase({process_runner_owned_tree, Port}),
    try unlink(Port) of _ -> ok catch error:badarg -> ok end,
    flush_owned_port_messages(Port),
    case Ownership of
        #{trap_acquired := true} -> release_owned_port_trap();
        _ -> ok
    end,
    ok.

acquire_owned_port_trap() ->
    Key = process_runner_owned_port_trap,
    case get(Key) of
        #{count := Count} = State when Count > 0 ->
            put(Key, State#{count => Count + 1}),
            true = process_flag(trap_exit, true),
            ok;
        undefined ->
            Previous = process_flag(trap_exit, true),
            put(Key, #{count => 1, previous => Previous}),
            ok;
        _ -> erlang:error(process_supervisor_trap_state_invalid)
    end.

release_owned_port_trap() ->
    Key = process_runner_owned_port_trap,
    case get(Key) of
        #{count := 1, previous := Previous} ->
            erase(Key),
            _ = process_flag(trap_exit, Previous),
            ok;
        #{count := Count} = State when Count > 1 ->
            put(Key, State#{count => Count - 1}),
            ok;
        undefined -> ok;
        _ -> erlang:error(process_supervisor_trap_state_invalid)
    end.

flush_owned_port_messages(Port) ->
    receive
        {'EXIT', Port, _} -> flush_owned_port_messages(Port);
        {Port, {exit_status, _}} -> flush_owned_port_messages(Port);
        {Port, {data, _}} -> flush_owned_port_messages(Port)
    after 0 -> ok
    end.

%% The lexical check catches accidental direct port use in evaluation strings.
%% It is not a security boundary: repository BEAM modules loaded via `Paths`
%% can start native descendants. The pinned supervisor is the authoritative
%% teardown boundary on both POSIX and Windows.
child_evaluation_starts_external_process(Input) ->
    re:run(Input,
        <<"(?:^|[^A-Za-z0-9_])(?:open_port|erlang:open_port|os:cmd|"
          "os:find_executable)\\s*\\(">>,
        [{capture, none}, unicode]) =:= match.

cleanup_child_artifacts(_CrashDumpPath, _CrashDumpDirectory, running) ->
    %% The isolated directory remains private and discoverable by the residue
    %% audit. A child whose exit was not observed must never race its deletion.
    ok;
cleanup_child_artifacts(CrashDumpPath, CrashDumpDirectory, State)
  when State =:= no_child; State =:= confirmed ->
    case file:delete(CrashDumpPath) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_remove_child_crash_dump)
    end,
    case file:del_dir(CrashDumpDirectory) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_remove_child_crash_directory)
    end;
cleanup_child_artifacts(_CrashDumpPath, _CrashDumpDirectory, _) ->
    erlang:error(invalid_child_cleanup_state).

child_start_category(eacces) -> access_or_command_limit;
child_start_category(enoent) -> executable_missing;
child_start_category(emfile) -> descriptor_limit;
child_start_category(enfile) -> descriptor_limit;
child_start_category(system_limit) -> resource_limit;
child_start_category(_) -> operating_system_failure.

collect_eunit(Port, Output, Deadline) ->
    case output_exceeded(Output) of
        true -> stop_output_flood(Port, Output);
        false -> collect_before_deadline(Port, Output, Deadline)
    end.

collect_before_deadline(Port, Output, Deadline) ->
    OwnerToken = get(process_runner_owner_token),
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true -> stop_child(Port, Output);
        false ->
            receive
                {Port, {data, Bytes}} ->
                    case owned_port_packet(Port, Bytes, Output) of
                        {output, Next} -> collect_eunit(Port, Next, Deadline);
                        {control, Next} -> collect_eunit(Port, Next, Deadline);
                        {error, Next} -> stop_protocol_failure(Port, Next)
                    end;
                {Port, {exit_status, Status}} ->
                    case attest_owned_exit(Port, Status, Output) of
                        {ok, Attested} ->
                            DeadlineExpired =
                                erlang:monotonic_time(millisecond) >= Deadline,
                            finish_exit_status(Status, Attested, DeadlineExpired);
                        {error, Unattested} ->
                            {127, finish_output(Unattested, false, false)}
                    end;
                {'EXIT', Port, _Reason} ->
                    %% A linked Port may deliver EXIT before its numeric
                    %% exit_status.  Keep the independent five-second cleanup
                    %% budget and require the latter before attesting equality.
                    await_exit_status_after_signal(Port, Output, Deadline);
                {process_runner_owner_cancel, OwnerToken}
                  when is_reference(OwnerToken) ->
                    stop_child(Port, Output)
            after Remaining -> stop_child(Port, Output)
            end
    end.

%% The collector's clock and accounting are testable without teaching the
%% production teardown path to accept an unowned token. The injected callback
%% is used only by an in-VM deterministic control; native executions continue
%% through collect_eunit/3 and stop_child/2 above.
collect_eunit_with_deadline_stop(Port, Output, Deadline, DeadlineStop) ->
    case output_exceeded(Output) of
        true -> stop_output_flood(Port, Output);
        false -> collect_before_deadline_with_stop(
            Port, Output, Deadline, DeadlineStop)
    end.

collect_before_deadline_with_stop(Port, Output, Deadline, DeadlineStop) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true -> DeadlineStop(Port, Output);
        false ->
            receive
                {Port, {data, Bytes}} ->
                    Next = append_output(Bytes, Output),
                    collect_eunit_with_deadline_stop(
                        Port, Next, Deadline, DeadlineStop);
                {Port, {exit_status, Status}} ->
                    DeadlineExpired =
                        erlang:monotonic_time(millisecond) >= Deadline,
                    finish_exit_status(Status, Output, DeadlineExpired);
                {'EXIT', Port, _} ->
                    DeadlineStop(Port, Output)
            after Remaining -> DeadlineStop(Port, Output)
            end
    end.

finish_exit_status(_Status, Output, true) ->
    {124, finish_output(Output, true, true)};
finish_exit_status(Status, Output, false) ->
    {Status, finish_output(Output, Status =:= 124, true)}.

process_completion_verified(Output) when is_map(Output) ->
    process_completion_attestation_verified(Output)
        andalso maps:get(process_supervisor_failure_code, Output, none) =:= none;
process_completion_verified(_) -> false.

process_completion_attestation_verified(Output) when is_map(Output) ->
    Identity = maps:get(process_supervisor, Output, #{}),
    PythonSha = case is_map(Identity) of
        true -> maps:get(python_executable_sha256, Identity, <<>>);
        false -> <<>>
    end,
    Reported = maps:get(process_supervisor_reported_status, Output, -1),
    Observed = maps:get(process_supervisor_observed_status, Output, -1),
    FailureCode = maps:get(process_supervisor_failure_code, Output, invalid),
    FailureCodeValid = FailureCode =:= none orelse
        (is_binary(FailureCode) andalso
         lists:member(FailureCode, supervisor_failure_codes())),
    maps:get(child_exit_observed, Output, false)
        andalso maps:get(process_supervisor_protocol_valid, Output, false)
        andalso maps:get(native_tree_empty, Output, false)
        andalso maps:get(native_console_isolated, Output, false)
        andalso maps:get(process_supervisor_attestation_failure, Output, none)
            =:= none
        andalso FailureCodeValid
        andalso is_map(Identity)
        andalso maps:get(source_sha256, Identity, <<>>)
            =:= process_supervisor_sha256()
        andalso maps:get(console_isolation, Identity, <<>>)
            =:= process_supervisor_isolation()
        andalso is_binary(PythonSha) andalso byte_size(PythonSha) =:= 64
        andalso is_integer(Reported) andalso Reported >= 0
        andalso Reported =:= Observed;
process_completion_attestation_verified(_) -> false.

process_status_verified(Status, Expected, Output) ->
    Status =:= Expected
        andalso process_completion_verified(Output)
        andalso not maps:get(timed_out, Output, true)
        andalso not maps:get(output_limit_exceeded, Output, true)
        andalso not maps:get(native_termination_requested, Output, true)
        andalso not maps:get(native_descendant_outlived, Output, true).

process_deadline_verified(124, Output) ->
    process_completion_attestation_verified(Output)
        andalso lists:member(maps:get(process_supervisor_failure_code, Output,
                                      invalid),
                             [none, <<"supervisor_deadline">>])
        andalso maps:get(timed_out, Output, false)
        andalso not maps:get(output_limit_exceeded, Output, true)
        andalso maps:get(native_termination_requested, Output, false)
        andalso not maps:get(native_descendant_outlived, Output, true);
process_deadline_verified(_, _) -> false.

process_output_limit_verified(125, Output) ->
    process_completion_attestation_verified(Output)
        andalso lists:member(maps:get(process_supervisor_failure_code, Output,
                                      invalid),
                             [none, <<"supervisor_output_limit">>])
        andalso not maps:get(timed_out, Output, true)
        andalso maps:get(output_limit_exceeded, Output, false)
        andalso maps:get(native_termination_requested, Output, false)
        andalso not maps:get(native_descendant_outlived, Output, true);
process_output_limit_verified(_, _) -> false.

new_output() -> new_output(undefined).

new_output(SupervisorIdentity) ->
    #{tail => <<>>, bytes => 0, hashed_bytes => 0,
      limit => 8388608, digest => crypto:hash_init(sha256),
      supervisor_identity => SupervisorIdentity,
      supervisor_final => undefined,
      supervisor_failure_code => none,
      supervisor_output_limit_seen => false,
      supervisor_attestation_failure => none,
      supervisor_protocol_valid => true}.

append_output(Bytes, #{tail := Before, bytes := Count, digest := Digest,
                       hashed_bytes := Hashed, limit := Limit} = Output) ->
    %% binary:copy prevents a tiny retained tail from retaining a large chunk.
    Combined = case byte_size(Bytes) >= 65536 of
        true -> Bytes;
        false -> <<Before/binary, Bytes/binary>>
    end,
    Size = byte_size(Combined),
    TailSize = erlang:min(Size, 65536),
    HashSize = erlang:min(byte_size(Bytes), Limit - Hashed),
    Output#{tail => binary:copy(binary:part(Combined, Size - TailSize, TailSize)),
            bytes => erlang:min(9223372036854775807, Count + byte_size(Bytes)),
            hashed_bytes => Hashed + HashSize,
            digest => crypto:hash_update(Digest, binary:part(Bytes, 0, HashSize))}.

output_exceeded(#{bytes := Count, limit := Limit}) -> Count > Limit.

finish_output(#{tail := Tail, bytes := Count, digest := Digest,
                hashed_bytes := Hashed, limit := Limit} = State,
              Timeout, Exited) ->
    SupervisorLimited = maps:get(supervisor_output_limit_seen, State, false),
    Output = #{tail => Tail, output_bytes => Count,
      output_sha256 => binary:encode_hex(crypto:hash_final(Digest), lowercase),
      output_hashed_bytes => Hashed, output_limit_bytes => Limit,
      output_digest_complete => Count =< Limit andalso not SupervisorLimited,
      output_limit_exceeded => Count > Limit orelse SupervisorLimited,
      vm_process_heap_words => 33554432,
      vm_heap_includes_shared_binaries => true,
      crash_dumps_disabled => true,
      timed_out => Timeout, child_exit_observed => Exited},
    finish_supervisor_observation(Output, State).

finish_supervisor_observation(Output,
        #{supervisor_identity := undefined}) -> Output;
finish_supervisor_observation(Output,
        #{supervisor_identity := Identity, supervisor_final := Final,
          supervisor_protocol_valid := ProtocolValid} = State) ->
    Observation = case Final of
        #{tree_empty := TreeEmpty, descendant_outlived := Outlived,
          termination_requested := Requested,
          console_isolated := ConsoleIsolated} ->
            #{tree_empty => TreeEmpty, descendant_outlived => Outlived,
              termination_requested => Requested,
              console_isolated => ConsoleIsolated};
        _ -> #{tree_empty => false, descendant_outlived => false,
               termination_requested => false, console_isolated => false}
    end,
    Output#{process_supervisor => Identity,
            process_supervisor_protocol_valid => ProtocolValid,
            process_supervisor_failure_code =>
                maps:get(supervisor_failure_code, State, none),
            process_supervisor_attestation_failure =>
                maps:get(supervisor_attestation_failure, State, none),
            process_supervisor_reported_status => case Final of
                #{status := ReportedStatus} -> ReportedStatus;
                _ -> -1
            end,
            process_supervisor_observed_status =>
                maps:get(supervisor_observed_status, State, -1),
            native_tree_empty => maps:get(tree_empty, Observation),
            native_console_isolated => maps:get(console_isolated, Observation),
            native_descendant_outlived => maps:get(descendant_outlived,
                                                    Observation),
            native_termination_requested => maps:get(termination_requested,
                                                      Observation)}.

output_tail(#{tail := Tail}) -> Tail;
output_tail(Bytes) when is_binary(Bytes) -> Bytes.

stop_output_flood(Port, Output) ->
    %% Output exhaustion is independent of the operation deadline. Reap the
    %% owned VM immediately; retain only a finite tail while observing its exit.
    _ = kill_owned_child(Port),
    case await_child_exit(Port, Output,
                          erlang:monotonic_time(millisecond) + 5000) of
        {exited, Final} -> {125, finish_output(Final, false, true)};
        {pending, Final} ->
            retire_unconfirmed_owned_tree(Port, fun close_owned_port/1),
            {125, finish_output(Final, false, false)}
    end.

stop_child(Port, Output) ->
    %% STOP is consumed by the supervisor while it still owns the complete OS
    %% process group / Windows Job Object.
    _ = kill_owned_child(Port),
    case await_child_exit(Port, Output,
                         erlang:monotonic_time(millisecond) + 5000) of
        {exited, Final} -> {124, finish_output(Final, true, true)};
        {pending, Pending} ->
            retire_unconfirmed_owned_tree(Port, fun close_owned_port/1),
            {124, finish_output(Pending, true, false)}
    end.

await_child_exit(Port, Output, Deadline) ->
    OwnerToken = get(process_runner_owner_token),
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true -> {pending, Output};
        false ->
            receive
                {Port, {data, Bytes}} ->
                    case owned_port_packet(Port, Bytes, Output) of
                        {output, Next} -> await_child_exit(Port, Next, Deadline);
                        {control, Next} -> await_child_exit(Port, Next, Deadline);
                        {error, Next} -> await_child_exit(Port, Next, Deadline)
                    end;
                {Port, {exit_status, Status}} ->
                    case attest_owned_exit(Port, Status, Output) of
                        {ok, Attested} -> {exited, Attested};
                        {error, Unattested} -> {pending, Unattested}
                    end;
                {'EXIT', Port, _Reason} ->
                    await_child_exit(Port,
                        Output#{supervisor_exit_signal_seen => true}, Deadline);
                {process_runner_owner_cancel, OwnerToken}
                  when is_reference(OwnerToken) ->
                    _ = kill_owned_child(Port),
                    await_child_exit(Port, Output, Deadline)
            after Remaining -> {pending, Output}
            end
    end.

owned_port_packet(Port, Packet, Output) ->
    case get({process_runner_owned_tree, Port}) of
        undefined -> {output, append_output(Packet, Output)};
        _ -> supervisor_packet(Packet, Output)
    end.

supervisor_packet(<<"O", Bytes/binary>>, Output) ->
    {output, append_output(Bytes, Output)};
supervisor_packet(Packet, Output) when byte_size(Packet) =< 64 ->
    case {parse_supervisor_final(Packet), parse_supervisor_error(Packet)} of
        {{ok, Final}, _} ->
            case maps:get(supervisor_final, Output, undefined) of
                undefined -> {control, Output#{supervisor_final => Final}};
                _ -> {error, Output#{supervisor_protocol_valid => false}}
            end;
        {error, {ok, Code}} ->
            %% A fixed runtime failure can be followed by a final tree-empty
            %% attestation. It blocks success without invalidating framing.
            {control, Output#{supervisor_failure_code => Code,
                supervisor_output_limit_seen =>
                    Code =:= <<"supervisor_output_limit">> orelse
                    maps:get(supervisor_output_limit_seen, Output, false)}};
        _ -> {error, Output#{supervisor_protocol_valid => false}}
    end;
supervisor_packet(_, Output) ->
    {error, Output#{supervisor_protocol_valid => false}}.

parse_supervisor_final(Packet) ->
    case binary:split(Packet, <<"|">>, [global]) of
        [<<"F">>, StatusBytes, TreeBytes, OutlivedBytes, RequestedBytes,
         ConsoleBytes] ->
            case {safe_status(StatusBytes), safe_boolean(TreeBytes),
                  safe_boolean(OutlivedBytes), safe_boolean(RequestedBytes),
                  safe_boolean(ConsoleBytes)} of
                {{ok, Status}, {ok, Tree}, {ok, Outlived}, {ok, Requested},
                 {ok, Console}} ->
                    {ok, #{status => Status, tree_empty => Tree,
                           descendant_outlived => Outlived,
                           termination_requested => Requested,
                           console_isolated => Console}};
                _ -> error
            end;
        _ -> error
    end.

parse_supervisor_error(Packet) ->
    case binary:split(Packet, <<"|">>, [global]) of
        [<<"E">>, Code] ->
            case lists:member(Code, supervisor_failure_codes()) of
                true -> {ok, Code};
                false -> error
            end;
        _ -> error
    end.

supervisor_failure_codes() ->
    [<<"child_start_failed">>, <<"child_wait_failed">>,
     <<"child_abnormal_exit">>, <<"child_access_denied">>,
     <<"child_access_violation">>, <<"child_assertion_failure">>,
     <<"child_controlled_interrupt">>, <<"child_dependency_missing">>,
     <<"child_entrypoint_missing">>, <<"child_fast_fail">>,
     <<"child_fatal_application_exit">>, <<"child_heap_corruption">>,
     <<"child_illegal_instruction">>, <<"child_initialization_failed">>,
     <<"child_invalid_handle">>, <<"child_invalid_parameter">>,
     <<"child_invalid_crt_parameter">>, <<"child_invalid_image">>,
     <<"child_no_memory">>, <<"child_runtime_abort">>,
     <<"child_stack_overflow">>,
     <<"group_query_failed">>, <<"group_termination_failed">>,
     <<"job_assign_failed">>, <<"job_create_failed">>,
     <<"job_query_failed">>, <<"job_resume_failed">>,
     <<"job_set_limits_failed">>, <<"job_termination_failed">>,
      <<"console_attribute_failed">>, <<"console_child_start_failed">>,
      <<"console_create_failed">>, <<"console_output_join_failed">>,
      <<"console_output_setup_failed">>, <<"console_pipe_failed">>,
      <<"console_prestart_cleanup_failed">>,
      <<"console_prestart_setup_failed">>,
      <<"console_isolation_unconfirmed">>,
      <<"prestart_reap_unconfirmed">>, <<"group_reap_unconfirmed">>,
     <<"protocol_failure">>, <<"python_identity_failed">>,
     <<"source_identity_failed">>,
     <<"supervisor_deadline">>, <<"supervisor_output_limit">>,
     <<"supervisor_failure">>].

safe_status(Bytes) ->
    try binary_to_integer(Bytes) of
        Status when Status >= 0, Status =< 255 -> {ok, Status};
        _ -> error
    catch _:_ -> error
    end.

safe_boolean(<<"0">>) -> {ok, false};
safe_boolean(<<"1">>) -> {ok, true};
safe_boolean(_) -> error.

attest_owned_exit(Port, Status, Output) ->
    case get({process_runner_owned_tree, Port}) of
        undefined -> {ok, Output};
        #{supervisor_identity := ExpectedIdentity} ->
            Observed = Output#{supervisor_observed_status => Status},
            Final = maps:get(supervisor_final, Observed, undefined),
            Protocol = maps:get(supervisor_protocol_valid, Observed, false),
            Identity = maps:get(supervisor_identity, Observed, undefined)
                =:= ExpectedIdentity,
            HasFinal = is_map(Final),
            StatusMatches = HasFinal andalso maps:get(status, Final, -1) =:= Status,
            TreeEmpty = HasFinal andalso maps:get(tree_empty, Final, false),
            ConsoleIsolated = HasFinal andalso
                maps:get(console_isolated, Final, false),
            LifecycleConfirmed = Identity andalso HasFinal andalso
                StatusMatches andalso TreeEmpty andalso ConsoleIsolated,
            case LifecycleConfirmed of
                true when Protocol -> {ok, Observed};
                true ->
                    %% A malformed application packet blocks success, but a
                    %% later well-formed final frame plus OS exit still proves
                    %% that the owned native tree is empty.
                    {ok, Observed#{supervisor_attestation_failure =>
                                      protocol_invalid}};
                false ->
                    Failure = supervisor_attestation_failure(
                        Protocol, Identity, HasFinal, StatusMatches, TreeEmpty,
                        ConsoleIsolated),
                    {error, Observed#{supervisor_protocol_valid => false,
                                    supervisor_attestation_failure => Failure}}
            end
    end.

await_exit_status_after_signal(Port, Output, OperationDeadline) ->
    CleanupDeadline = erlang:monotonic_time(millisecond) + 5000,
    case await_child_exit(Port,
            Output#{supervisor_exit_signal_seen => true}, CleanupDeadline) of
        {exited, Attested} ->
            Status = maps:get(status, maps:get(supervisor_final, Attested)),
            Expired = erlang:monotonic_time(millisecond) >= OperationDeadline,
            finish_exit_status(Status, Attested, Expired);
        {pending, Unattested} ->
            retire_unconfirmed_owned_tree(Port, fun close_owned_port/1),
            {127, finish_output(
                Unattested#{supervisor_protocol_valid => false,
                            supervisor_attestation_failure =>
                                exit_status_missing}, false, false)}
    end.

supervisor_attestation_failure(false, _, _, _, _, _) -> protocol_invalid;
supervisor_attestation_failure(_, false, _, _, _, _) -> identity_mismatch;
supervisor_attestation_failure(_, _, false, _, _, _) -> final_missing;
supervisor_attestation_failure(_, _, _, false, _, _) -> status_mismatch;
supervisor_attestation_failure(_, _, _, _, false, _) -> tree_not_empty;
supervisor_attestation_failure(_, _, _, _, _, false) ->
    console_isolation_unconfirmed.

stop_protocol_failure(Port, Output) ->
    _ = kill_owned_child(Port),
    case await_child_exit(Port, Output,
                          erlang:monotonic_time(millisecond) + 5000) of
        {exited, Final} -> {127, finish_output(Final, false, true)};
        {pending, Final} ->
            retire_unconfirmed_owned_tree(Port, fun close_owned_port/1),
            {127, finish_output(Final, false, false)}
    end.

kill_owned_child(Port) ->
    case get({process_runner_owned_tree, Port}) of
        #{supervisor_identity := _} = Ownership ->
            Requested = try port_command(Port, <<"STOP">>)
                        catch error:badarg -> false
                        end,
            put({process_runner_owned_tree, Port},
                Ownership#{termination_requested => Requested}),
            Requested;
        undefined -> erlang:error(unowned_native_process)
    end.

close_owned_port(Port) ->
    try port_close(Port) of
        true -> ok
    catch error:badarg -> ok
    end.

retire_unconfirmed_owned_tree(Port, Close) ->
    %% Failure remains unconfirmed, but the exact Port token can still be
    %% detached and its trap_exit state restored after bounded containment.
    safe_close_callback(Close, Port),
    unregister_owned_tree(Port),
    ok.

-endif.
