#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-compile(nowarn_unused_function).
-include("command_capture.hrl").
-include("execution_beam_identity.hrl").

main(Arguments) ->
    execution_beam_with_owned_platform_observer(
        fun execution_beam_self_test_capture/4,
        fun() -> execution_beam_identity_self_test(Arguments) end).

execution_beam_identity_self_test([]) ->
    Root = filename:dirname(filename:dirname(
        filename:absname(escript:script_name()))),
    ok = file:set_cwd(Root),
    Base = "build/execution-beam-identity-self-test",
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    true = try execution_beam_reserve_attempt(Base, Nonce), false
           catch error:execution_beam_attempt_conflict -> true end,
    RunnerDirectory = filename:join(maps:get(root, Lease), "runner"),
    ok = file:make_dir(RunnerDirectory),
    RunnerSource = filename:join(
        RunnerDirectory, "qualification_eunit_listener.erl"),
    ok = execution_beam_publish_new(RunnerSource,
        <<"-module(qualification_eunit_listener).\n"
          "-export([run_invocation/7]).\n"
          "run_invocation(B,S,I,L,SS,RS,IS)->"
          "S=binary:encode_hex(crypto:hash(sha256,B),lowercase),"
          "true=is_binary(I),true=is_binary(L),true=is_binary(SS),"
          "true=is_binary(RS),true=is_binary(IS),{called,byte_size(B)}.\n">>,
        4096),
    {ok, qualification_eunit_listener, RunnerBinary, []} = compile:file(
        RunnerSource, [binary, return_errors, return_warnings]),
    RunnerBeam = filename:join(
        RunnerDirectory, "qualification_eunit_listener.beam"),
    ok = execution_beam_publish_new(RunnerBeam, RunnerBinary, 4194304),
    true = code:add_patha(RunnerDirectory),
    Payload = binary:copy(<<"bounded-invocation-payload">>, 32768),
    RunnerSha = binary:encode_hex(
        crypto:hash(sha256, RunnerBinary), lowercase),
    SourceSha = binary:encode_hex(crypto:hash(sha256, Payload), lowercase),
    InventorySha = binary:copy(<<"1">>, 64),
    Inventory = #{sha256 => InventorySha, entries => []},
    Units = [#{payload => Payload}],
    Evaluation = execution_beam_bootstrap_evaluation(
        Lease, run_attested,
        [Units, "unused", <<"unit">>, RunnerSha, "unused", Inventory],
        RunnerSha, SourceSha, 126),
    EvaluationBytes = unicode:characters_to_binary(Evaluation),
    true = byte_size(EvaluationBytes) > 0 andalso
        byte_size(EvaluationBytes) =< 4096,
    nomatch = binary:match(EvaluationBytes, Payload),
    InvocationDirectory = filename:join(maps:get(root, Lease), "invocations"),
    {ok, [InvocationName]} = file:list_dir(InvocationDirectory),
    InvocationPath = filename:join(InvocationDirectory, InvocationName),
    InvocationBytes = execution_beam_read(InvocationPath, 16777216),
    {ok, Invocation} = canonical_etf_decode(
        InvocationBytes, 16777216, 64, 2000000),
    {execution_beam_invocation_v2, InvocationNonce,
     LeaseNonce, SourceSha, RunnerSha, InventorySha,
     {run_attested, Units, "unused", <<"unit">>, "unused", Inventory}} =
        Invocation,
    true = execution_beam_digest(InvocationNonce, 32),
    LeaseNonce = maps:get(nonce, Lease),
    InvocationSha = binary:encode_hex(
        crypto:hash(sha256, InvocationBytes), lowercase),
    {_, _} = binary:match(EvaluationBytes, InvocationSha),
    {ok, Tokens, _} = erl_scan:string(Evaluation),
    {ok, Expressions} = erl_parse:parse_exprs(Tokens),
    {value, {called, InvocationByteCount}, _} = erl_eval:exprs(
        Expressions, erl_eval:new_bindings()),
    InvocationByteCount = byte_size(InvocationBytes),
    true = code:del_path(RunnerDirectory),
    _ = code:purge(qualification_eunit_listener),
    true = code:delete(qualification_eunit_listener),
    _ = code:purge(qualification_eunit_listener),
    false = code:is_loaded(qualification_eunit_listener),
    owner_receipt_self_test(Lease),
    windows_owner_observer_self_test(Base),
    ok = execution_beam_release_attempt(Lease),
    true = execution_beam_path_absent(maps:get(root, Lease)),
    cleanup_rejection_self_test(Base),
    owner_replacement_self_test(Base),
    delete_failure_self_test(Base),
    root_delete_failure_self_test(Base),
    operation_lock_self_test(Base),
    operation_lock_contamination_self_test(Base),
    operation_lock_replacement_self_test(Base),
    root_replacement_self_test(Base),
    terminal_alias_self_test(Base),
    operation_directory_alias_self_test(Base),
    entry_type_self_test(Base),
    stale_recovery_self_test(Base),
    unavailable_recovery_self_test(Base),
    legacy_recovery_self_test(Base),
    io:format("execution_beam invocation_staged=verified "
              "command_line_bounded=verified conflict=rejected "
              "cleanup_transaction=verified root_identity=verified "
              "reserved_names=verified owner_identity=verified "
              "windows_owner_observer=verified stale_recovery=verified~n"),
    ok;
execution_beam_identity_self_test(_) ->
    erlang:error(invalid_execution_beam_self_test_arguments).

execution_beam_self_test_capture(Executable, Arguments, Timeout, Limit) ->
    try command_capture(Executable, Arguments, filename:absname("."),
                        Timeout, Limit, []) of
        {ok, Output, Proof} when is_binary(Output) ->
            true = command_success_verified(Proof),
            {ok, Output};
        _ -> {error, owner_identity_capture_failed}
    catch _:_ -> {error, owner_identity_capture_failed}
    end.

cleanup_rejection_self_test(Base) ->
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    External = filename:join(Base,
        "cleanup-source-" ++ binary_to_list(Nonce) ++ ".bin"),
    Link = filename:join(maps:get(root, Lease), "zzz-hardlink.bin"),
    ok = execution_beam_publish_new(External, <<"cleanup">>, 1024),
    ok = file:make_link(External, Link),
    true = try execution_beam_release_attempt(Lease), false
           catch error:execution_beam_attempt_special_file_rejected -> true end,
    _ = execution_beam_directory_info(maps:get(root, Lease)),
    ok = execution_beam_equal_or_error(maps:get(owner_bytes, Lease),
        execution_beam_read(maps:get(owner, Lease),
                            ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    true = execution_beam_path_absent(filename:join(
        maps:get(root, Lease), ".terminal-operation")),
    ok = file:delete(Link),
    ok = execution_beam_release_attempt(Lease),
    ok = file:delete(External),
    true = execution_beam_path_absent(maps:get(root, Lease)),
    ok.

owner_receipt_self_test(Lease) ->
    Nonce = maps:get(nonce, Lease),
    Receipt = execution_beam_decode_owner_receipt(
        maps:get(owner_bytes, Lease), Nonce),
    true = execution_beam_owner_receipt_valid(Receipt, Nonce),
    Owner = maps:get(<<"owner">>, Receipt),
    true = execution_beam_decimal(maps:get(<<"os_pid">>, Owner)),
    true = is_map(maps:get(<<"host_identity">>, Owner)),
    true = is_map(maps:get(<<"process_start_identity">>, Owner)),
    true = lists:member(maps:get(<<"proof_status">>, Owner),
                        [<<"Available">>, <<"Unavailable">>]),
    case os:type() of
        {win32, nt} -> <<"Available">> = maps:get(<<"proof_status">>, Owner);
        _ -> ok
    end,
    ok.

windows_owner_observer_self_test(Base) ->
    case os:type() of
        {win32, nt} ->
            Pid = unicode:characters_to_binary(os:getpid()),
            {ok, Host, {live, Start}} =
                execution_beam_platform_observation(Pid),
            <<"windows_machineguid_boot_time">> = maps:get(kind, Host),
            <<"windows_process_start_ticks">> = maps:get(kind, Start),
            true = execution_beam_host_identity_valid(Host, atom_keys),
            true = execution_beam_start_identity_valid(Start, atom_keys),
            Nonce = execution_beam_test_nonce(),
            Receipt0 = execution_beam_owner_receipt(Nonce),
            Receipt = json:decode(iolist_to_binary(json:encode(Receipt0))),
            true = try execution_beam_owner_death_proof(Receipt), false
                   catch error:execution_beam_owner_active -> true end,
            Owner = maps:get(<<"owner">>, Receipt),
            ExpectedStart = maps:get(<<"process_start_identity">>, Owner),
            ReusedStart = ExpectedStart#{<<"sha256">> =>
                execution_beam_sha256(<<"definitely-stale-start">>)},
            ReusedReceipt = Receipt#{<<"owner">> => Owner#{
                <<"process_start_identity">> => ReusedStart}},
            #{kind := pid_reused} =
                execution_beam_owner_death_proof(ReusedReceipt),
            Powershell = execution_beam_windows_powershell(),
            Guard = execution_beam_open_system_executable_guard(Powershell),
            DeadPid = try
                {ok, DeadPid0} = execution_beam_self_test_capture(
                    Powershell,
                    ["-NoLogo", "-NoProfile", "-NonInteractive",
                     "-Command", "[Console]::Out.Write($PID);exit 0"],
                    15000, 4096),
                ok = execution_beam_verify_system_executable_guard(Guard),
                execution_beam_trim(DeadPid0)
            after
                ok = execution_beam_close_system_executable_guard(Guard)
            end,
            true = execution_beam_decimal(DeadPid),
            true = DeadPid =/= Pid,
            {ok, DeadHost, dead} = execution_beam_windows_owned_observation(
                DeadPid, fun execution_beam_self_test_capture/4),
            Host = DeadHost,
            windows_owner_recovery_self_test(
                Base, Pid, Host, Start, DeadPid),
            {error, owner_identity_capture_failed} =
                execution_beam_windows_owned_observation(DeadPid,
                    fun(_, _, _, _) ->
                        {error, simulated_diagnostic_sink_failure}
                    end),
            {error, owner_identity_observation_invalid} =
                execution_beam_windows_capture_result({ok, <<"{}">>}),
            execution_beam_with_owned_platform_observer(
                fun(_, _, _, _) ->
                    {error, simulated_diagnostic_sink_failure}
                end,
                fun() ->
                    SinkNonce = execution_beam_test_nonce(),
                    SinkLease = execution_beam_reserve_attempt(
                        Base, SinkNonce),
                    SinkReceipt = execution_beam_decode_owner_receipt(
                        maps:get(owner_bytes, SinkLease), SinkNonce),
                    SinkOwner = maps:get(<<"owner">>, SinkReceipt),
                    <<"Unavailable">> = maps:get(
                        <<"proof_status">>, SinkOwner),
                    <<"owner_identity_capture_failed">> = maps:get(
                        <<"failure_code">>, SinkOwner),
                    SinkSnapshot = filename:join(Base,
                        "sink-failure-snapshot-" ++
                        binary_to_list(SinkNonce) ++ ".json"),
                    true = try execution_beam_recover_stale_attempt(
                        Base, SinkNonce, SinkSnapshot), false
                    catch error:execution_beam_owner_unverifiable -> true end,
                    false = filelib:is_regular(SinkSnapshot),
                    _ = execution_beam_regular_info(maps:get(owner, SinkLease)),
                    ok = execution_beam_release_attempt(SinkLease),
                    true = execution_beam_path_absent(
                        maps:get(root, SinkLease)),
                    ok
                end),
            ok;
        _ -> ok
    end.

windows_owner_recovery_self_test(Base, Pid, Host, Start, DeadPid) ->
    ActiveNonce = execution_beam_test_nonce(),
    ActiveLease = execution_beam_reserve_attempt(Base, ActiveNonce),
    ActiveSnapshot = filename:join(Base,
        "windows-active-snapshot-" ++ binary_to_list(ActiveNonce) ++ ".json"),
    true = try execution_beam_recover_stale_attempt(
        Base, ActiveNonce, ActiveSnapshot), false
    catch error:execution_beam_owner_active -> true end,
    false = filelib:is_regular(ActiveSnapshot),
    _ = execution_beam_regular_info(maps:get(owner, ActiveLease)),
    ok = execution_beam_release_attempt(ActiveLease),

    ReusedNonce = execution_beam_test_nonce(),
    ReusedReceipt0 = execution_beam_owner_receipt(ReusedNonce),
    ReusedOwner0 = maps:get(owner, ReusedReceipt0),
    Start = maps:get(process_start_identity, ReusedOwner0),
    ReusedStart = Start#{sha256 =>
        execution_beam_sha256(<<"deterministic-stale-process-start">>)},
    ReusedReceipt = ReusedReceipt0#{owner => ReusedOwner0#{
        os_pid => Pid, host_identity => Host,
        process_start_identity => ReusedStart}},
    ReusedLease = execution_beam_reserve_attempt_owner(
        Base, ReusedNonce, ReusedReceipt),
    ReusedMarker = filename:join(
        maps:get(root, ReusedLease), "reused-owner-marker.bin"),
    ok = execution_beam_publish_new(ReusedMarker, <<"reused">>, 64),
    ReusedSnapshot = filename:join(Base,
        "windows-reused-snapshot-" ++ binary_to_list(ReusedNonce) ++ ".json"),
    #{status := recovered, death_proof := pid_reused} =
        execution_beam_recover_stale_attempt(
            Base, ReusedNonce, ReusedSnapshot),
    true = execution_beam_path_absent(maps:get(root, ReusedLease)),
    true = execution_beam_recovery_snapshot_valid(
        json:decode(execution_beam_read(ReusedSnapshot, 65536)),
        ReusedNonce, maps:get(owner_bytes, ReusedLease)),
    ok = file:delete(ReusedSnapshot),

    DeadNonce = execution_beam_test_nonce(),
    DeadReceipt0 = execution_beam_owner_receipt(DeadNonce),
    DeadOwner0 = maps:get(owner, DeadReceipt0),
    DeadReceipt = DeadReceipt0#{owner => DeadOwner0#{
        os_pid => DeadPid, host_identity => Host,
        process_start_identity => Start}},
    DeadLease = execution_beam_reserve_attempt_owner(
        Base, DeadNonce, DeadReceipt),
    DeadMarker = filename:join(
        maps:get(root, DeadLease), "dead-owner-marker.bin"),
    ok = execution_beam_publish_new(DeadMarker, <<"dead">>, 64),
    DeadSnapshot = filename:join(Base,
        "windows-dead-snapshot-" ++ binary_to_list(DeadNonce) ++ ".json"),
    #{status := recovered, death_proof := pid_absent} =
        execution_beam_recover_stale_attempt(Base, DeadNonce, DeadSnapshot),
    true = execution_beam_path_absent(maps:get(root, DeadLease)),
    true = execution_beam_recovery_snapshot_valid(
        json:decode(execution_beam_read(DeadSnapshot, 65536)),
        DeadNonce, maps:get(owner_bytes, DeadLease)),
    ok = file:delete(DeadSnapshot),
    ok.

owner_replacement_self_test(Base) ->
    Nonce = execution_beam_test_nonce(),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    Root = maps:get(root, Lease),
    Owner = maps:get(owner, Lease),
    Marker = filename:join(Root, "zzz-owner-swap-marker.bin"),
    ok = execution_beam_publish_new(Marker, <<"preserve">>, 64),
    Hooks = (execution_beam_release_hooks())#{after_preflight => fun(_) ->
        ok = file:delete(Owner),
        execution_beam_publish_new(Owner, <<"{\"mutant\":true}\n">>,
                                   ?EXECUTION_BEAM_OWNER_MAXIMUM)
    end},
    true = try execution_beam_terminal_operation(
        Root, Owner, maps:get(owner_bytes, Lease), <<"release">>, Hooks, none),
        false
    catch error:execution_beam_owner_changed -> true end,
    true = filelib:is_regular(Marker),
    <<"{\"mutant\":true}\n">> = execution_beam_read(
        Owner, ?EXECUTION_BEAM_OWNER_MAXIMUM),
    true = execution_beam_path_absent(filename:join(
        Root, ".terminal-operation")),
    ok = file:delete(Owner),
    ok = execution_beam_publish_new(
        Owner, maps:get(owner_bytes, Lease), ?EXECUTION_BEAM_OWNER_MAXIMUM),
    ok = execution_beam_release_attempt(Lease),
    true = execution_beam_path_absent(Root),
    ok.

delete_failure_self_test(Base) ->
    Nonce = execution_beam_test_nonce(),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    Root = maps:get(root, Lease),
    Marker = filename:join(Root, "zzz-delete-failure.bin"),
    ok = execution_beam_publish_new(Marker, <<"preserve">>, 64),
    Hooks = (execution_beam_release_hooks())#{delete_file =>
        fun(_) -> {error, eacces} end},
    true = try execution_beam_terminal_operation(Root, maps:get(owner, Lease),
        maps:get(owner_bytes, Lease), <<"release">>, Hooks, none), false
    catch error:execution_beam_attempt_cleanup_failed -> true end,
    true = filelib:is_regular(Marker),
    ok = execution_beam_equal_or_error(maps:get(owner_bytes, Lease),
        execution_beam_read(maps:get(owner, Lease),
                            ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    true = execution_beam_path_absent(filename:join(
        Root, ".terminal-operation")),
    ok = execution_beam_release_attempt(Lease),
    true = execution_beam_path_absent(Root),
    ok.

root_delete_failure_self_test(Base) ->
    Nonce = execution_beam_test_nonce(),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    Root = maps:get(root, Lease),
    Hooks = (execution_beam_release_hooks())#{delete_root =>
        fun(_) -> {error, eacces} end},
    true = try execution_beam_terminal_operation(Root, maps:get(owner, Lease),
        maps:get(owner_bytes, Lease), <<"release">>, Hooks, none), false
    catch error:execution_beam_attempt_root_delete_failed -> true end,
    ok = execution_beam_equal_or_error(maps:get(owner_bytes, Lease),
        execution_beam_read(maps:get(owner, Lease),
                            ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    true = execution_beam_path_absent(filename:join(
        Root, ".terminal-operation")),
    ok = execution_beam_release_attempt(Lease),
    true = execution_beam_path_absent(Root),
    ok.

operation_lock_self_test(Base) ->
    Nonce = execution_beam_test_nonce(),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    Root = maps:get(root, Lease),
    Lock = execution_beam_acquire_operation(
        Root, maps:get(owner, Lease), maps:get(owner_bytes, Lease),
        <<"release">>),
    true = try execution_beam_release_attempt(Lease), false
           catch error:execution_beam_attempt_busy -> true end,
    ok = execution_beam_equal_or_error(maps:get(owner_bytes, Lease),
        execution_beam_read(maps:get(owner, Lease),
                            ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    ok = execution_beam_release_operation_if_owned(Lock),
    ok = execution_beam_release_attempt(Lease),
    true = execution_beam_path_absent(Root),
    ok.

operation_lock_contamination_self_test(Base) ->
    Nonce = execution_beam_test_nonce(),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    Root = maps:get(root, Lease),
    Lock = execution_beam_acquire_operation(
        Root, maps:get(owner, Lease), maps:get(owner_bytes, Lease),
        <<"release">>),
    Contaminant = filename:join(
        maps:get(directory, Lock), "zzz-unowned-entry.bin"),
    ok = execution_beam_publish_new(Contaminant, <<"preserve">>, 64),
    true = try execution_beam_preflight_tree(
        Root, maps:get(owner, Lease), maps:get(owner_bytes, Lease), Lock), false
        catch error:execution_beam_operation_lock_changed -> true end,
    ok = execution_beam_equal_or_error(maps:get(owner_bytes, Lease),
        execution_beam_read(maps:get(owner, Lease),
                            ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    ok = file:delete(Contaminant),
    ok = execution_beam_release_operation_if_owned(Lock),
    ok = execution_beam_release_attempt(Lease),
    true = execution_beam_path_absent(Root),
    ok.

operation_lock_replacement_self_test(Base) ->
    Nonce = execution_beam_test_nonce(),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    Root = maps:get(root, Lease),
    Marker = filename:join(Root, "operation-lock-marker.bin"),
    ok = execution_beam_publish_new(Marker, <<"preserve">>, 64),
    Lock = execution_beam_acquire_operation(
        Root, maps:get(owner, Lease), maps:get(owner_bytes, Lease),
        <<"release">>),
    LockPath = maps:get(path, Lock),
    case file:delete(LockPath) of
        {error, Reason} when Reason =:= einval; Reason =:= eacces;
                             Reason =:= eperm ->
            %% A platform may deny unlink while the exact guard is open. The
            %% fixed directory independently excludes a second operation.
            true = try execution_beam_release_attempt(Lease), false
                   catch error:execution_beam_attempt_busy -> true end,
            ok = execution_beam_verify_operation_guard(Lock),
            ok = execution_beam_release_operation_if_owned(Lock);
        ok ->
            %% Windows and Unix may allow unlinking an open receipt. The fixed
            %% directory must still exclude a second legitimate operation,
            %% even when an attacker restores byte-identical receipt content.
            true = try execution_beam_release_attempt(Lease), false
                   catch error:execution_beam_attempt_busy -> true end,
            ok = execution_beam_publish_new(
                LockPath, maps:get(bytes, Lock),
                ?EXECUTION_BEAM_OWNER_MAXIMUM),
            case try execution_beam_verify_operation_guard(Lock), verified
                 catch error:execution_beam_operation_guard_changed -> changed end of
                verified ->
                    ok = execution_beam_release_operation_if_owned(Lock);
                changed ->
                    %% The self-test owns both fixture identities, so it may
                    %% close and remove the deliberate substitute directly.
                    ok = execution_beam_close_operation_guard(Lock),
                    ok = execution_beam_equal_or_error(maps:get(bytes, Lock),
                        execution_beam_read(
                            LockPath, ?EXECUTION_BEAM_OWNER_MAXIMUM),
                        execution_beam_operation_lock_changed),
                    ok = file:delete(LockPath),
                    ok = file:del_dir(maps:get(directory, Lock))
            end
    end,
    true = execution_beam_path_absent(maps:get(directory, Lock)),
    true = filelib:is_regular(Marker),
    ok = execution_beam_release_attempt(Lease),
    true = execution_beam_path_absent(Root),
    ok.

root_replacement_self_test(Base) ->
    Nonce = execution_beam_test_nonce(),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    Root = maps:get(root, Lease),
    Owner = maps:get(owner, Lease),
    Marker = filename:join(Root, "root-identity-marker.bin"),
    ok = execution_beam_publish_new(Marker, <<"preserve">>, 64),
    Lock = execution_beam_acquire_operation(
        Root, Owner, maps:get(owner_bytes, Lease), <<"release">>),
    Moved = Root ++ ".moved",
    case file:rename(Root, Moved) of
        {error, Reason} when Reason =:= einval; Reason =:= eacces;
                             Reason =:= eperm ->
            %% Windows holds the operation-lock handle without delete sharing,
            %% so the directory cannot be exchanged while cleanup is active.
            ok;
        ok ->
            %% Unix permits renaming an open file's parent; the retained
            %% device/inode identity must then reject an exact-byte substitute.
            ok = file:make_dir(Root),
            ReplacementOwner = filename:join(Root, "owner.json"),
            ReplacementLockDirectory = execution_beam_operation_directory(Root),
            ReplacementLock = execution_beam_operation_owner_path(
                ReplacementLockDirectory),
            ok = execution_beam_publish_new(ReplacementOwner,
                maps:get(owner_bytes, Lease), ?EXECUTION_BEAM_OWNER_MAXIMUM),
            ok = file:make_dir(ReplacementLockDirectory),
            ok = execution_beam_publish_new(ReplacementLock,
                maps:get(bytes, Lock), ?EXECUTION_BEAM_OWNER_MAXIMUM),
            true = try execution_beam_verify_terminal_owners(
                Root, ReplacementOwner, maps:get(owner_bytes, Lease), Lock),
                false
            catch error:execution_beam_attempt_root_changed -> true end,
            true = filelib:is_regular(filename:join(Moved,
                "root-identity-marker.bin")),
            true = filelib:is_regular(ReplacementLock),
            ok = file:delete(ReplacementLock),
            ok = file:del_dir(ReplacementLockDirectory),
            ok = file:delete(ReplacementOwner),
            ok = file:del_dir(Root),
            ok = file:rename(Moved, Root)
    end,
    ok = execution_beam_release_operation_if_owned(Lock),
    ok = execution_beam_release_attempt(Lease),
    true = execution_beam_path_absent(Root),
    ok.

terminal_alias_self_test(Base) ->
    true = execution_beam_terminal_alias(
        filename:join(Base, "OWNER.JSON"),
        filename:join(Base, "owner.json")),
    false = execution_beam_terminal_alias(
        filename:join(Base, "owner-copy.json"),
        filename:join(Base, "owner.json")),
    Nonce = execution_beam_test_nonce(),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    Root = maps:get(root, Lease),
    Owner = maps:get(owner, Lease),
    Alias = filename:join(Root, "OWNER.JSON"),
    Intermediate = filename:join(Root, "owner.rename-in-progress"),
    Lock = execution_beam_acquire_operation(
        Root, Owner, maps:get(owner_bytes, Lease), <<"release">>),
    ok = file:rename(Owner, Intermediate),
    ok = file:rename(Intermediate, Alias),
    true = try execution_beam_preflight_tree(
        Root, Owner, maps:get(owner_bytes, Lease), Lock), false
    catch
        error:execution_beam_owner_changed -> true;
        error:execution_beam_missing -> true
    end,
    ok = file:rename(Alias, Intermediate),
    ok = file:rename(Intermediate, Owner),
    ok = execution_beam_release_operation_if_owned(Lock),
    ok = execution_beam_release_attempt(Lease),
    true = execution_beam_path_absent(Root),
    ok.

operation_directory_alias_self_test(Base) ->
    Nonce = execution_beam_test_nonce(),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    Root = maps:get(root, Lease),
    Alias = filename:join(Root, ".TERMINAL-OPERATION"),
    ok = file:make_dir(Alias),
    true = try execution_beam_release_attempt(Lease), false
           catch error:execution_beam_attempt_busy -> true end,
    ok = execution_beam_equal_or_error(maps:get(owner_bytes, Lease),
        execution_beam_read(maps:get(owner, Lease),
                            ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    ok = file:del_dir(Alias),
    ok = execution_beam_release_attempt(Lease),
    true = execution_beam_path_absent(Root),
    ok.

entry_type_self_test(Base) ->
    Nonce = execution_beam_test_nonce(),
    Lease = execution_beam_reserve_attempt(Base, Nonce),
    External = filename:join(Base,
        "entry-kind-" ++ binary_to_list(Nonce) ++ ".bin"),
    ok = execution_beam_publish_new(External, <<"kind">>, 64),
    Info = execution_beam_regular_info(External),
    true = try execution_beam_entry_kind(setelement(3, Info, symlink)), false
           catch error:execution_beam_attempt_link_rejected -> true end,
    true = try execution_beam_entry_kind(setelement(3, Info, device)), false
           catch error:execution_beam_attempt_special_file_rejected -> true end,
    ok = execution_beam_release_attempt(Lease),
    ok = file:delete(External),
    ok.

stale_recovery_self_test(Base) ->
    Previous = get(execution_beam_owner_observation_provider),
    Host = execution_beam_host_identity(
        <<"fixture_host_boot">>, <<"fixture-machine">>, <<"fixture-boot">>),
    LiveStart = execution_beam_start_identity(
        <<"fixture_process_start">>, <<"fixture-live">>),
    ReusedStart = execution_beam_start_identity(
        <<"fixture_process_start">>, <<"fixture-reused">>),
    Active = fun(_) -> {ok, Host, {live, LiveStart}} end,
    Reused = fun(_) -> {ok, Host, {live, ReusedStart}} end,
    put(execution_beam_owner_observation_provider, Active),
    try
        Nonce = execution_beam_test_nonce(),
        Lease = execution_beam_reserve_attempt(Base, Nonce),
        Root = maps:get(root, Lease),
        Marker = filename:join(Root, "zzz-recovery-marker.bin"),
        ok = execution_beam_publish_new(Marker, <<"recover">>, 64),
        ActiveSnapshot = filename:join(Base,
            "active-snapshot-" ++ binary_to_list(Nonce) ++ ".json"),
        true = try execution_beam_recover_stale_attempt(
            Base, Nonce, ActiveSnapshot), false
        catch error:execution_beam_owner_active -> true end,
        false = filelib:is_regular(ActiveSnapshot),
        ok = execution_beam_equal_or_error(maps:get(owner_bytes, Lease),
        execution_beam_read(maps:get(owner, Lease),
                            ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
        put(execution_beam_owner_observation_provider, Reused),
        ok = execution_beam_publish_new(ActiveSnapshot, <<"occupied">>, 64),
        true = try execution_beam_recover_stale_attempt(
            Base, Nonce, ActiveSnapshot), false
        catch error:execution_beam_recovery_snapshot_exists -> true end,
        true = filelib:is_regular(Marker),
        ok = file:delete(ActiveSnapshot),
        Snapshot = filename:join(Base,
            "stale-snapshot-" ++ binary_to_list(Nonce) ++ ".json"),
        Hooks = (execution_beam_release_hooks())#{
            before_delete => fun(_) ->
                true = filelib:is_regular(Snapshot), ok
            end,
            delete_file => fun(_) -> {error, eacces} end},
        Receipt = execution_beam_decode_owner_receipt(
            maps:get(owner_bytes, Lease), Nonce),
        DeathProof = execution_beam_owner_death_proof(Receipt),
        true = try execution_beam_terminal_operation(Root,
            maps:get(owner, Lease), maps:get(owner_bytes, Lease),
            <<"stale_recovery">>, Hooks,
            #{snapshot_path => Snapshot, death_proof => DeathProof,
              owner_receipt => Receipt, nonce => Nonce, hooks => Hooks}), false
        catch error:execution_beam_attempt_cleanup_failed -> true end,
        true = filelib:is_regular(Snapshot),
        ok = execution_beam_equal_or_error(maps:get(owner_bytes, Lease),
        execution_beam_read(maps:get(owner, Lease),
                            ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
        RetrySnapshot = filename:join(Base,
            "stale-retry-snapshot-" ++ binary_to_list(Nonce) ++ ".json"),
        #{status := recovered, death_proof := pid_reused} =
            execution_beam_recover_stale_attempt(Base, Nonce, RetrySnapshot),
        true = execution_beam_path_absent(Root),
        SnapshotBytes = execution_beam_read(Snapshot, 65536),
        true = execution_beam_recovery_snapshot_valid(
            json:decode(SnapshotBytes), Nonce, maps:get(owner_bytes, Lease)),
        nomatch = binary:match(SnapshotBytes, <<"os_pid">>),
        nomatch = binary:match(SnapshotBytes, <<"process_start_identity">>),
        nomatch = binary:match(SnapshotBytes,
                               unicode:characters_to_binary(Root)),
        RetryBytes = execution_beam_read(RetrySnapshot, 65536),
        true = execution_beam_recovery_snapshot_valid(
            json:decode(RetryBytes), Nonce, maps:get(owner_bytes, Lease)),
        ok = file:delete(Snapshot),
        ok = file:delete(RetrySnapshot)
    after
        execution_beam_restore_provider(Previous)
    end,
    ok.

unavailable_recovery_self_test(Base) ->
    Previous = get(execution_beam_owner_observation_provider),
    erase(execution_beam_owner_observation_provider),
    try
        Nonce = execution_beam_test_nonce(),
        Lease = execution_beam_reserve_attempt(Base, Nonce),
        Receipt = execution_beam_decode_owner_receipt(
            maps:get(owner_bytes, Lease), Nonce),
        Owner = maps:get(<<"owner">>, Receipt),
        Snapshot = filename:join(Base,
            "unavailable-snapshot-" ++ binary_to_list(Nonce) ++ ".json"),
        case maps:get(<<"proof_status">>, Owner) of
            <<"Unavailable">> ->
                true = try execution_beam_recover_stale_attempt(
                    Base, Nonce, Snapshot), false
                catch error:execution_beam_owner_unverifiable -> true end;
            <<"Available">> ->
                true = try execution_beam_recover_stale_attempt(
                    Base, Nonce, Snapshot), false
                catch error:execution_beam_owner_active -> true end
        end,
        false = filelib:is_regular(Snapshot),
        ok = execution_beam_release_attempt(Lease),
        true = execution_beam_path_absent(maps:get(root, Lease))
    after
        execution_beam_restore_provider(Previous)
    end,
    ok.

legacy_recovery_self_test(Base) ->
    Nonce = execution_beam_test_nonce(),
    Root = filename:join(Base, binary_to_list(Nonce)),
    ok = file:make_dir(Root),
    Owner = filename:join(Root, "owner.json"),
    OwnerBytes = iolist_to_binary([json:encode(#{schema => 1,
        kind => <<"execution_beam_attempt">>, nonce => Nonce,
        status => <<"Running">>}), $\n]),
    ok = execution_beam_publish_new(
        Owner, OwnerBytes, ?EXECUTION_BEAM_OWNER_MAXIMUM),
    Snapshot = filename:join(Base,
        "legacy-snapshot-" ++ binary_to_list(Nonce) ++ ".json"),
    true = try execution_beam_recover_stale_attempt(Base, Nonce, Snapshot), false
           catch error:execution_beam_owner_unverifiable -> true end,
    false = filelib:is_regular(Snapshot),
    OwnerBytes = execution_beam_read(Owner, ?EXECUTION_BEAM_OWNER_MAXIMUM),
    ok = execution_beam_release_attempt(
        #{root => Root, owner => Owner, owner_bytes => OwnerBytes,
          nonce => Nonce}),
    true = execution_beam_path_absent(Root),
    ok.

execution_beam_restore_provider(undefined) ->
    erase(execution_beam_owner_observation_provider), ok;
execution_beam_restore_provider(Previous) ->
    put(execution_beam_owner_observation_provider, Previous), ok.

execution_beam_test_nonce() ->
    binary:encode_hex(crypto:strong_rand_bytes(16), lowercase).
