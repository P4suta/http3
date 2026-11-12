%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_EXECUTION_BEAM_IDENTITY_HRL).
-define(HTTP_EXECUTION_BEAM_IDENTITY_HRL, true).
-include("evidence_publication.hrl").
-include("canonical_etf_wire.hrl").
-define(EXECUTION_BEAM_OWNER_MAXIMUM, 16384).
-define(EXECUTION_BEAM_ENTRY_MAXIMUM, 16777216).
-define(EXECUTION_BEAM_TREE_MAXIMUM, 268435456).
-define(EXECUTION_BEAM_ENTRY_COUNT_MAXIMUM, 100000).
-define(EXECUTION_BEAM_OBSERVER_OUTPUT_MAXIMUM, 16384).
-define(EXECUTION_BEAM_SYSTEM_EXECUTABLE_MAXIMUM, 16777216).
-compile({nowarn_unused_function, [
    {execution_beam_inventory, 3},
    {execution_beam_directory_entries, 3},
    {execution_beam_inventory_digest, 1},
    {execution_beam_loaded_attestation, 3},
    {execution_beam_expected_digest, 2},
    {execution_beam_loaded_entry, 4},
    {execution_beam_loaded_from_root, 2},
    {execution_beam_runner_loaded, 1},
    {execution_beam_attestation_valid, 3},
    {execution_beam_bootstrap_evaluation, 6},
    {execution_beam_closed_invocation, 3},
    {execution_beam_publish_new, 3},
    {execution_beam_reserve_attempt, 2},
    {execution_beam_reserve_attempt_owner, 3},
    {execution_beam_release_attempt, 1},
    {execution_beam_recover_stale_attempt, 3},
    {execution_beam_terminal_operation, 6},
    {execution_beam_acquire_operation, 4},
    {execution_beam_operation_directory, 1},
    {execution_beam_operation_owner_path, 1},
    {execution_beam_no_operation_claim, 1},
    {execution_beam_operation_claim_exact, 2},
    {execution_beam_operation_directory_exact, 1},
    {execution_beam_open_operation_guard, 2},
    {execution_beam_verify_operation_guard, 1},
    {execution_beam_close_operation_guard, 1},
    {execution_beam_release_operation_if_owned, 1},
    {execution_beam_release_operation_required, 1},
    {execution_beam_release_operation_directory, 1},
    {execution_beam_restore_operation_receipt, 1},
    {execution_beam_release_locked, 6},
    {execution_beam_restore_owner, 4},
    {execution_beam_release_hooks, 0},
    {execution_beam_hook, 3},
    {execution_beam_preflight_tree, 4},
    {execution_beam_preflight_directory, 8},
    {execution_beam_preflight_entry, 6},
    {execution_beam_preflight_nonterminal, 8},
    {execution_beam_entry_kind, 1},
    {execution_beam_names_unique, 1},
    {execution_beam_directory_identity, 1},
    {execution_beam_relative_path_sha256, 2},
    {execution_beam_relative_depth, 2},
    {execution_beam_removal_entries, 1},
    {execution_beam_remove_entry, 6},
    {execution_beam_delete_result, 1},
    {execution_beam_verify_terminal_owners, 4},
    {execution_beam_only_terminal_entries, 3},
    {execution_beam_terminal_alias, 2},
    {execution_beam_capture_recovery, 6},
    {execution_beam_tree_summary, 1},
    {execution_beam_recovery_snapshot_valid, 3},
    {execution_beam_tree_summary_valid, 1},
    {execution_beam_path_within, 2},
    {execution_beam_owner_receipt, 1},
    {execution_beam_process_owner_identity, 0},
    {execution_beam_owner_receipt_valid, 2},
    {execution_beam_process_owner_valid, 2},
    {execution_beam_process_owner_fields, 6},
    {execution_beam_host_identity_valid, 2},
    {execution_beam_start_identity_valid, 2},
    {execution_beam_runtime_identity, 0},
    {execution_beam_runtime_identity_valid, 2},
    {execution_beam_source_identity, 0},
    {execution_beam_source_file_identity, 2},
    {execution_beam_source_identity_valid, 2},
    {execution_beam_decode_owner_receipt, 2},
    {execution_beam_owner_death_proof, 1},
    {execution_beam_process_death_proof, 2},
    {execution_beam_normalize_host, 1},
    {execution_beam_normalize_start, 1},
    {execution_beam_with_owned_platform_observer, 2},
    {execution_beam_restore_observation_provider, 1},
    {execution_beam_platform_observation, 1},
    {execution_beam_provider_observation, 1},
    {execution_beam_builtin_platform_observation, 1},
    {execution_beam_linux_observation, 1},
    {execution_beam_linux_start, 1},
    {execution_beam_windows_observation, 1},
    {execution_beam_windows_owned_observation, 2},
    {execution_beam_windows_capture, 2},
    {execution_beam_windows_capture_arguments, 1},
    {execution_beam_windows_capture_script, 1},
    {execution_beam_windows_capture_result, 1},
    {execution_beam_windows_observation_decode, 1},
    {execution_beam_windows_powershell, 0},
    {execution_beam_open_system_executable_guard, 1},
    {execution_beam_verify_system_executable_guard, 1},
    {execution_beam_close_system_executable_guard, 1},
    {execution_beam_macos_observation, 1},
    {execution_beam_host_identity, 3},
    {execution_beam_start_identity, 2},
    {execution_beam_system_file, 2},
    {execution_beam_trim, 1},
    {execution_beam_weak_host_identity, 0},
    {execution_beam_weak_start_identity, 0},
    {execution_beam_decimal, 1},
    {execution_beam_timestamp, 1},
    {execution_beam_finite_system_time, 0},
    {execution_beam_safe_code, 1},
    {execution_beam_safe_text, 1},
    {execution_beam_sha256, 1},
    {execution_beam_equal_or_error, 3},
    {execution_beam_read, 2},
    {execution_beam_read_chunks, 3},
    {execution_beam_regular_info, 1},
    {execution_beam_file_identity, 1},
    {execution_beam_path_absent, 1}
]}).

%% The parent inventories the complete set of BEAM files reachable through the
%% build/dev code paths before starting the child.  The listener later checks
%% both the code-server filename and the loaded module MD5.  Re-reading the
%% object bytes supplies a SHA-256 check as an additional, fail-closed TOCTOU
%% guard: a file changed after it was loaded cannot turn a mismatch into Ready.
execution_beam_inventory(CodePaths0, BuildRoot0, Read)
  when is_list(CodePaths0), is_function(Read, 1) ->
    true = CodePaths0 =/= [] andalso length(CodePaths0) =< 4096,
    BuildRoot = execution_beam_absolute(BuildRoot0),
    _ = execution_beam_directory_info(BuildRoot),
    CodePaths = lists:sort([execution_beam_absolute(Path) || Path <- CodePaths0]),
    true = length(CodePaths) =:= length(lists:usort(CodePaths)),
    true = execution_beam_no_case_collisions(CodePaths),
    Entries0 = lists:append([
        execution_beam_directory_entries(Path, BuildRoot, Read)
        || Path <- CodePaths]),
    true = Entries0 =/= [] andalso length(Entries0) =< 20000,
    Entries = execution_beam_validated_entries(Entries0),
    #{schema => 1, entries => Entries, count => length(Entries),
      sha256 => execution_beam_inventory_digest(Entries)}.

execution_beam_directory_entries(Path, BuildRoot, Read) ->
    _ = execution_beam_relative(BuildRoot, Path),
    Before = execution_beam_directory_info(Path),
    {ok, Names0} = file:list_dir(Path),
    true = length(Names0) =< 20000,
    Names = lists:sort(Names0),
    true = execution_beam_no_case_collisions(Names),
    Entries = lists:foldl(fun(Name, Acc) ->
        true = Name =/= "" andalso Name =/= "." andalso Name =/= "..",
        Member = filename:join(Path, Name),
        case file:read_link_info(Member) of
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= regular ->
                case filename:extension(Name) of
                    ".beam" ->
                        Bytes = Read(Member),
                        true = is_binary(Bytes) andalso byte_size(Bytes) > 0
                            andalso byte_size(Bytes) =< 67108864,
                        {ok, {Module, Md5}} = beam_lib:md5(Bytes),
                        ModuleName = atom_to_binary(Module),
                        true = execution_beam_module(ModuleName),
                        ModuleName = unicode:characters_to_binary(
                            filename:basename(Name, ".beam")),
                        Relative = execution_beam_relative(BuildRoot, Member),
                        [#{module => ModuleName,
                           path => unicode:characters_to_binary(Relative),
                           sha256 => binary:encode_hex(
                               crypto:hash(sha256, Bytes), lowercase),
                           beam_md5 => binary:encode_hex(Md5, lowercase)} | Acc];
                    _ -> Acc
                end;
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= symlink ->
                erlang:error(execution_beam_link_rejected);
            {ok, _} -> erlang:error(execution_beam_special_file_rejected);
            {error, enoent} -> erlang:error(execution_beam_inventory_changed);
            {error, _} -> erlang:error(execution_beam_inspection_failed)
        end
    end, [], Names),
    After = execution_beam_directory_info(Path),
    true = execution_beam_file_identity(Before) =:=
        execution_beam_file_identity(After),
    Entries.

execution_beam_inventory_digest(Entries0) when is_list(Entries0) ->
    Entries = execution_beam_validated_entries(Entries0),
    Material = [<<"http3-execution-beam-inventory-v1", 0,
                  (length(Entries)):64/unsigned-big>> |
        [execution_beam_entry_frame(Entry) || Entry <- Entries]],
    binary:encode_hex(crypto:hash(sha256, Material), lowercase).

execution_beam_validated_entries(Entries0) ->
    true = length(Entries0) =< 20000,
    true = lists:all(fun execution_beam_entry_valid/1, Entries0),
    Entries = lists:sort(fun(A, B) ->
        {maps:get(module, A), maps:get(path, A)} =<
            {maps:get(module, B), maps:get(path, B)}
    end, Entries0),
    Modules = [maps:get(module, Entry) || Entry <- Entries],
    Paths = [maps:get(path, Entry) || Entry <- Entries],
    true = length(Modules) =:= length(lists:usort(Modules)),
    true = execution_beam_no_binary_case_collisions(Modules),
    true = length(Paths) =:= length(lists:usort(Paths)),
    true = execution_beam_no_binary_case_collisions(Paths),
    Entries.

execution_beam_entry_valid(Entry) when is_map(Entry) ->
    try
        true = lists:sort(maps:keys(Entry)) =:=
            [beam_md5, module, path, sha256],
        true = execution_beam_module(maps:get(module, Entry)),
        true = execution_beam_relative_path(maps:get(path, Entry)),
        true = execution_beam_digest(maps:get(sha256, Entry), 64),
        true = execution_beam_digest(maps:get(beam_md5, Entry), 32),
        true
    catch _:_ -> false end;
execution_beam_entry_valid(_) -> false.

execution_beam_entry_frame(Entry) ->
    Module = maps:get(module, Entry),
    Path = maps:get(path, Entry),
    Sha = binary:decode_hex(maps:get(sha256, Entry)),
    Md5 = binary:decode_hex(maps:get(beam_md5, Entry)),
    <<(byte_size(Module)):16/unsigned-big, Module/binary,
      (byte_size(Path)):32/unsigned-big, Path/binary, Sha/binary, Md5/binary>>.

%% Called by the exact listener after EUnit has joined all test processes.
%% Only aggregate, path-free values leave the child report.
execution_beam_loaded_attestation(Expected, BuildRoot0, RequiredModules0) ->
    EmptyDigest = execution_beam_inventory_digest([]),
    try
        true = is_map(Expected),
        true = lists:sort(maps:keys(Expected)) =:=
            [count, entries, schema, sha256],
        1 = maps:get(schema, Expected),
        Entries = execution_beam_validated_entries(maps:get(entries, Expected)),
        ExpectedCount = maps:get(count, Expected),
        true = length(Entries) =:= ExpectedCount,
        ExpectedDigest = execution_beam_inventory_digest(Entries),
        ExpectedDigest = maps:get(sha256, Expected),
        BuildRoot = execution_beam_absolute(BuildRoot0),
        _ = execution_beam_directory_info(BuildRoot),
        RequiredModules = lists:usort(RequiredModules0),
        true = RequiredModules =/= [] andalso length(RequiredModules) =< 10000,
        true = lists:all(fun execution_beam_module/1, RequiredModules),
        ByModule = maps:from_list([
            {maps:get(module, Entry), Entry} || Entry <- Entries]),
        Loaded0 = [execution_beam_loaded_entry(Module, File, BuildRoot, ByModule)
            || {Module, File} <- code:all_loaded(),
               execution_beam_loaded_from_root(File, BuildRoot)],
        Loaded = execution_beam_validated_entries(Loaded0),
        LoadedModules = [maps:get(module, Entry) || Entry <- Loaded],
        true = lists:all(fun(Module) -> lists:member(Module, LoadedModules) end,
                         RequiredModules),
        true = Loaded =/= [],
        #{runner_sha256 => null,
          expected_inventory_sha256 => ExpectedDigest,
          loaded_beam_sha256 => execution_beam_inventory_digest(Loaded),
          loaded_beam_count => length(Loaded),
          loaded_beams_verified => true}
    catch _:_ ->
        SafeExpectedDigest = execution_beam_expected_digest(Expected, EmptyDigest),
        #{runner_sha256 => null,
          expected_inventory_sha256 => SafeExpectedDigest,
          loaded_beam_sha256 => EmptyDigest, loaded_beam_count => 0,
          loaded_beams_verified => false}
    end.

execution_beam_expected_digest(#{sha256 := Digest}, _Fallback) ->
    case execution_beam_digest(Digest, 64) of
        true -> Digest;
        false -> execution_beam_inventory_digest([])
    end;
execution_beam_expected_digest(_, Fallback) -> Fallback.

execution_beam_loaded_entry(Module, File, BuildRoot, ByModule) ->
    ModuleName = atom_to_binary(Module),
    Expected = maps:get(ModuleName, ByModule),
    Relative = unicode:characters_to_binary(execution_beam_relative(
        BuildRoot, execution_beam_absolute(File))),
    Relative = maps:get(path, Expected),
    ExpectedMd5 = binary:decode_hex(maps:get(beam_md5, Expected)),
    ExpectedMd5 = Module:module_info(md5),
    {Module, ObjectBytes, ObjectFile} = code:get_object_code(Module),
    true = is_binary(ObjectBytes) andalso byte_size(ObjectBytes) > 0
        andalso byte_size(ObjectBytes) =< 67108864,
    ObjectBytes = execution_beam_read(ObjectFile, 67108864),
    Relative = unicode:characters_to_binary(execution_beam_relative(
        BuildRoot, execution_beam_absolute(ObjectFile))),
    ExpectedSha = maps:get(sha256, Expected),
    ExpectedSha = binary:encode_hex(
        crypto:hash(sha256, ObjectBytes), lowercase),
    {ok, {Module, ExpectedMd5}} = beam_lib:md5(ObjectBytes),
    Expected.

execution_beam_loaded_from_root(File, BuildRoot)
  when is_list(File); is_binary(File) ->
    try
        _ = execution_beam_relative(BuildRoot, execution_beam_absolute(File)),
        true
    catch _:_ -> false end;
execution_beam_loaded_from_root(_, _) -> false.

%% Recheck the listener after EUnit has joined the test processes.  This binds
%% the report-writing callback to the same runner bytes that the bootstrap
%% accepted, including the case where its path is swapped and restored while
%% the VM keeps different code loaded.
execution_beam_runner_loaded(ExpectedSha) ->
    try
        true = execution_beam_digest(ExpectedSha, 64),
        {qualification_eunit_listener, Bytes, ObjectFile} =
            code:get_object_code(qualification_eunit_listener),
        true = is_binary(Bytes) andalso byte_size(Bytes) > 0
            andalso byte_size(Bytes) =< 4194304,
        Bytes = execution_beam_read(ObjectFile, 4194304),
        ExpectedSha = binary:encode_hex(
            crypto:hash(sha256, Bytes), lowercase),
        {ok, {qualification_eunit_listener, Md5}} = beam_lib:md5(Bytes),
        Md5 = qualification_eunit_listener:module_info(md5),
        true
    catch _:_ -> false end.

execution_beam_attestation_valid(Attestation, RunnerSha, InventorySha) ->
    try
        true = is_map(Attestation),
        true = lists:sort(maps:keys(Attestation)) =:= lists:sort([
            runner_sha256, expected_inventory_sha256, loaded_beam_sha256,
            loaded_beam_count, loaded_beams_verified]),
        RunnerSha = maps:get(runner_sha256, Attestation),
        InventorySha = maps:get(expected_inventory_sha256, Attestation),
        true = execution_beam_digest(RunnerSha, 64),
        true = execution_beam_digest(InventorySha, 64),
        true = execution_beam_digest(maps:get(loaded_beam_sha256, Attestation), 64),
        Count = maps:get(loaded_beam_count, Attestation),
        true = is_integer(Count) andalso Count > 0 andalso Count =< 20000,
        true = maps:get(loaded_beams_verified, Attestation),
        true
    catch _:_ -> false end.

%% Keep the complete unit and BEAM inventory out of the OS command line.  A
%% realistic Windows suite easily exceeds CreateProcess' finite argument
%% limit.  The parent publishes a nonce-unique external term and retains its
%% digest; the bootstrap accepts those exact bytes only after loading the
%% already-hash-checked listener.
execution_beam_bootstrap_evaluation(Lease, Function, Arguments, RunnerSha,
                                    SourceSha, FailureStatus)
  when is_map(Lease), is_atom(Function), is_list(Arguments),
       is_integer(FailureStatus), FailureStatus >= 2, FailureStatus =< 255 ->
    true = lists:member(Function, [run_attested, run_units_attested]),
    true = execution_beam_digest(RunnerSha, 64),
    true = execution_beam_digest(SourceSha, 64),
    Root = maps:get(root, Lease),
    LeaseNonce = maps:get(nonce, Lease),
    true = execution_beam_digest(LeaseNonce, 32),
    ExpectedOwner = maps:get(owner_bytes, Lease),
    ok = execution_beam_equal_or_error(ExpectedOwner,
        execution_beam_read(maps:get(owner, Lease),
                            ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    InvocationDirectory = filename:join(Root, "invocations"),
    _ = evidence_publication_ensure_directory(InvocationDirectory),
    InvocationNonce = binary:encode_hex(
        crypto:strong_rand_bytes(16), lowercase),
    InvocationPath = filename:join(InvocationDirectory,
        binary_to_list(InvocationNonce) ++ ".etf"),
    {Dispatch, InventorySha} = execution_beam_closed_invocation(
        Function, Arguments, RunnerSha),
    InvocationTerm = {execution_beam_invocation_v2,
        InvocationNonce, LeaseNonce, SourceSha, RunnerSha, InventorySha,
        Dispatch},
    InvocationBytes = term_to_binary(
        InvocationTerm, [{minor_version, 2}]),
    true = byte_size(InvocationBytes) > 0 andalso
        byte_size(InvocationBytes) =< 16777216,
    ok = execution_beam_publish_new(
        InvocationPath, InvocationBytes, 16777216),
    InvocationBytes = execution_beam_read(InvocationPath, 16777216),
    InvocationSha = binary:encode_hex(
        crypto:hash(sha256, InvocationBytes), lowercase),
    lists:flatten(io_lib:format(
        "case code:get_object_code(qualification_eunit_listener) of "
        "{qualification_eunit_listener,RB,_} when byte_size(RB)>0,"
        "byte_size(RB)=<4194304 -> case binary:encode_hex(crypto:hash(sha256,RB),lowercase) of "
        "~0tp -> case code:load_binary(qualification_eunit_listener,"
        "\"attested://qualification_eunit_listener\",RB) of "
        "{module,qualification_eunit_listener} -> "
        "IR=(fun()->case file:open(~0tp,[read,binary,raw]) of "
        "{ok,IH}->try case file:read(IH,16777217) of "
        "{ok,IB0} when byte_size(IB0)>0,byte_size(IB0)=<16777216 -> "
        "case file:read(IH,1) of eof->{ok,IB0};_->error end;_->error end "
        "after ok=file:close(IH) end;_->error end end)(),case IR of {ok,IB} -> "
        "case binary:encode_hex(crypto:hash(sha256,IB),lowercase) of "
        "~0tp -> try qualification_eunit_listener:run_invocation("
        "IB,~0tp,~0tp,~0tp,~0tp,~0tp,~0tp) "
        "catch _:_ -> erlang:halt(~B) end; _ -> erlang:halt(~B) end; "
        "_ -> erlang:halt(~B) end; _ -> erlang:halt(~B) end; "
        "_ -> erlang:halt(~B) end; _ -> erlang:halt(~B) end.",
        [RunnerSha, InvocationPath, InvocationSha,
         InvocationSha, InvocationNonce, LeaseNonce, SourceSha, RunnerSha,
         InventorySha, FailureStatus, FailureStatus, FailureStatus,
         FailureStatus, FailureStatus, FailureStatus])).

execution_beam_closed_invocation(
  run_attested,
  [Units, Path, RunNonce, RunnerSha, BuildRoot, Inventory], RunnerSha)
  when is_list(Units), is_list(Path), is_binary(RunNonce),
       is_list(BuildRoot), is_map(Inventory) ->
    InventorySha = maps:get(sha256, Inventory),
    true = execution_beam_digest(InventorySha, 64),
    {{run_attested, Units, Path, RunNonce, BuildRoot, Inventory}, InventorySha};
execution_beam_closed_invocation(
  run_units_attested,
  [Units, Path, RunNonce, Seconds, RunnerSha, BuildRoot, Inventory], RunnerSha)
  when is_list(Units), is_list(Path), is_binary(RunNonce),
       is_integer(Seconds), Seconds >= 5, Seconds =< 3600,
       Seconds rem 5 =:= 0, is_list(BuildRoot), is_map(Inventory) ->
    InventorySha = maps:get(sha256, Inventory),
    true = execution_beam_digest(InventorySha, 64),
    {{run_units_attested, Units, Path, RunNonce, Seconds, BuildRoot,
      Inventory}, InventorySha}.

execution_beam_publish_new(Path0, Bytes, Maximum)
  when is_binary(Bytes), is_integer(Maximum), Maximum > 0 ->
    evidence_publish_new(Path0, Bytes, Maximum).

execution_beam_reserve_attempt(Base0, Nonce) ->
    execution_beam_reserve_attempt_owner(
        Base0, Nonce, execution_beam_owner_receipt(Nonce)).

execution_beam_reserve_attempt_owner(Base0, Nonce, OwnerReceipt) ->
    true = execution_beam_digest(Nonce, 32),
    Base = filename:absname(Base0),
    _ = evidence_publication_ensure_directory(Base),
    _ = execution_beam_directory_info(Base),
    Root = filename:join(Base, binary_to_list(Nonce)),
    case file:make_dir(Root) of
        ok -> ok;
        {error, eexist} -> erlang:error(execution_beam_attempt_conflict);
        {error, _} -> erlang:error(execution_beam_attempt_reservation_failed)
    end,
    _ = execution_beam_directory_info(Root),
    Owner = filename:join(Root, "owner.json"),
    true = execution_beam_owner_receipt_valid(OwnerReceipt, Nonce),
    OwnerBytes = iolist_to_binary([json:encode(OwnerReceipt), $\n]),
    try
        ok = execution_beam_publish_new(
            Owner, OwnerBytes, ?EXECUTION_BEAM_OWNER_MAXIMUM),
        #{root => Root, owner => Owner, owner_bytes => OwnerBytes,
          nonce => Nonce}
    catch
        Class:Reason:Stack ->
            _ = file:del_dir(Root),
            erlang:raise(Class, Reason, Stack)
    end.

execution_beam_release_attempt(Lease) ->
    Root = maps:get(root, Lease),
    Owner = maps:get(owner, Lease),
    ExpectedOwner = maps:get(owner_bytes, Lease),
    ok = execution_beam_equal_or_error(ExpectedOwner,
        execution_beam_read(Owner, ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    execution_beam_terminal_operation(
        Root, Owner, ExpectedOwner, <<"release">>,
        execution_beam_release_hooks(), none).

execution_beam_recover_stale_attempt(Base0, Nonce, SnapshotPath0) ->
    true = execution_beam_digest(Nonce, 32),
    Base = filename:absname(Base0),
    _ = execution_beam_directory_info(Base),
    Root = filename:join(Base, binary_to_list(Nonce)),
    true = filename:dirname(Root) =:= Base,
    _ = execution_beam_directory_info(Root),
    Owner = filename:join(Root, "owner.json"),
    OwnerBytes = execution_beam_read(Owner, ?EXECUTION_BEAM_OWNER_MAXIMUM),
    OwnerReceipt = execution_beam_decode_owner_receipt(OwnerBytes, Nonce),
    SnapshotPath = filename:absname(SnapshotPath0),
    false = execution_beam_path_within(SnapshotPath, Root),
    DeathProof = execution_beam_owner_death_proof(OwnerReceipt),
    Result = execution_beam_terminal_operation(
        Root, Owner, OwnerBytes, <<"stale_recovery">>,
        execution_beam_release_hooks(),
        #{snapshot_path => SnapshotPath, death_proof => DeathProof,
          owner_receipt => OwnerReceipt, nonce => Nonce}),
    #{status => recovered,
      attempt_sha256 => execution_beam_sha256(Nonce),
      snapshot_sha256 => maps:get(snapshot_sha256, Result),
      death_proof => maps:get(kind, DeathProof)}.

execution_beam_terminal_operation(Root0, Owner0, ExpectedOwner, Operation,
                                  Hooks, Recovery) ->
    Root = filename:absname(Root0),
    Owner = filename:absname(Owner0),
    true = filename:dirname(Owner) =:= Root,
    ok = execution_beam_equal_or_error(ExpectedOwner,
        execution_beam_read(Owner, ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    Lock = execution_beam_acquire_operation(
        Root, Owner, ExpectedOwner, Operation),
    try
        execution_beam_release_locked(
            Root, Owner, ExpectedOwner, Lock, Hooks, Recovery)
    catch
        Class:Reason:Stack ->
            ok = execution_beam_release_operation_if_owned(Lock),
            erlang:raise(Class, Reason, Stack)
    end.

execution_beam_acquire_operation(Root, Owner, ExpectedOwner, Operation) ->
    true = Operation =:= <<"release">> orelse
           Operation =:= <<"stale_recovery">>,
    RootIdentity = execution_beam_directory_identity(
        execution_beam_directory_info(Root)),
    ok = execution_beam_equal_or_error(ExpectedOwner,
        execution_beam_read(Owner, ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    LockDirectory = execution_beam_operation_directory(Root),
    LockPath = execution_beam_operation_owner_path(LockDirectory),
    true = execution_beam_no_operation_claim(Root),
    case file:make_dir(LockDirectory) of
        ok -> ok;
        {error, eexist} -> erlang:error(execution_beam_attempt_busy);
        {error, _} -> erlang:error(execution_beam_operation_lock_create_failed)
    end,
    LockDirectoryIdentity = execution_beam_directory_identity(
        execution_beam_directory_info(LockDirectory)),
    case file:list_dir(LockDirectory) of
        {ok, []} -> ok;
        {ok, _} -> erlang:error(execution_beam_operation_lock_changed);
        {error, _} ->
            erlang:error(execution_beam_operation_lock_inspection_failed)
    end,
    LockReceipt = #{schema => 1,
        kind => <<"execution_beam_terminal_operation">>,
        operation => Operation,
        token => binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
        owner => execution_beam_process_owner_identity(),
        created_at_unix_ms => execution_beam_finite_system_time()},
    LockBytes = iolist_to_binary([json:encode(LockReceipt), $\n]),
    try execution_beam_publish_new(
            LockPath, LockBytes, ?EXECUTION_BEAM_OWNER_MAXIMUM) of
        ok -> ok
    catch
        error:evidence_publication_conflict ->
            erlang:error(execution_beam_attempt_busy)
    end,
    %% The fixed directory is the atomic exclusion primitive. The receipt
    %% inside it is opened before trusting any subsequent pathname read. If
    %% the receipt cannot be attested, preserve the directory and fail closed;
    %% deleting by pathname without a retained identity could remove a
    %% replacement.
    Guard = execution_beam_open_operation_guard(LockPath, LockBytes),
    Lock = #{path => LockPath, bytes => LockBytes, root => Root,
             root_identity => RootIdentity, directory => LockDirectory,
             directory_identity => LockDirectoryIdentity, guard => Guard},
    try
        ok = execution_beam_equal_or_error(RootIdentity,
            execution_beam_directory_identity(
                execution_beam_directory_info(Root)),
            execution_beam_attempt_root_changed),
        ok = execution_beam_equal_or_error(ExpectedOwner,
            execution_beam_read(Owner, ?EXECUTION_BEAM_OWNER_MAXIMUM),
            execution_beam_owner_changed),
        true = execution_beam_operation_claim_exact(Root, LockDirectory),
        ok = execution_beam_verify_operation_guard(Lock),
        Lock
    catch
        Class:Reason:Stack ->
            _ = try execution_beam_release_operation_if_owned(Lock)
                catch _:_ -> ok end,
            erlang:raise(Class, Reason, Stack)
    end.

execution_beam_operation_directory(Root) ->
    filename:join(Root, ".terminal-operation").

execution_beam_operation_owner_path(Directory) ->
    filename:join(Directory, "owner.json").

execution_beam_open_operation_guard(Path, Bytes) ->
    {ok, Handle} = file:open(Path, [read, binary, raw]),
    try
        {ok, Info} = file:read_file_info(Handle),
        case element(3, Info) =:= regular andalso element(9, Info) =:= 1 of
            true -> ok;
            false -> erlang:error(execution_beam_operation_guard_changed)
        end,
        {ok, Captured} = file:read(Handle, byte_size(Bytes) + 1),
        Bytes = Captured,
        eof = file:read(Handle, 1),
        Identity = execution_beam_file_identity(Info),
        ok = execution_beam_equal_or_error(Identity,
            execution_beam_file_identity(execution_beam_regular_info(Path)),
            execution_beam_operation_guard_changed),
        #{handle => Handle, identity => Identity}
    catch
        Class:Reason:Stack ->
            _ = file:close(Handle),
            erlang:raise(Class, Reason, Stack)
    end.

execution_beam_verify_operation_guard(Lock) ->
    Root = maps:get(root, Lock),
    Directory = maps:get(directory, Lock),
    Path = maps:get(path, Lock),
    Bytes = maps:get(bytes, Lock),
    ok = execution_beam_equal_or_error(maps:get(root_identity, Lock),
        execution_beam_directory_identity(execution_beam_directory_info(Root)),
        execution_beam_attempt_root_changed),
    true = execution_beam_operation_claim_exact(Root, Directory),
    ok = execution_beam_equal_or_error(maps:get(directory_identity, Lock),
        execution_beam_directory_identity(
            execution_beam_directory_info(Directory)),
        execution_beam_operation_lock_changed),
    true = execution_beam_operation_directory_exact(Lock),
    Guard = maps:get(guard, Lock),
    Handle = maps:get(handle, Guard),
    case file:read_file_info(Handle) of
        {ok, Info} when element(3, Info) =:= regular,
                        element(9, Info) =:= 1 ->
            ok = execution_beam_equal_or_error(maps:get(identity, Guard),
                execution_beam_file_identity(Info),
                execution_beam_operation_guard_changed),
            ok = execution_beam_equal_or_error(maps:get(identity, Guard),
                execution_beam_file_identity(execution_beam_regular_info(
                    Path)),
                execution_beam_operation_guard_changed),
            ok = execution_beam_equal_or_error(Bytes,
                execution_beam_read(Path, ?EXECUTION_BEAM_OWNER_MAXIMUM),
                execution_beam_operation_lock_changed),
            ok = execution_beam_equal_or_error(maps:get(directory_identity, Lock),
                execution_beam_directory_identity(
                    execution_beam_directory_info(Directory)),
                execution_beam_operation_lock_changed),
            true = execution_beam_operation_directory_exact(Lock),
            ok;
        _ -> erlang:error(execution_beam_operation_guard_changed)
    end.

execution_beam_close_operation_guard(Lock) ->
    Handle = maps:get(handle, maps:get(guard, Lock)),
    case file:close(Handle) of
        ok -> ok;
        {error, einval} -> ok;
        {error, _} -> erlang:error(execution_beam_operation_guard_close_failed)
    end.

execution_beam_no_operation_claim(Root) ->
    case file:list_dir(Root) of
        {ok, Names} ->
            Forbidden = [Name || Name <- Names,
                begin
                    Folded = string:casefold(Name),
                    Folded =:= ".terminal-operation" orelse
                    lists:prefix(".terminal-operation.claim-", Folded)
                end],
            case Forbidden of
                [] -> true;
                _ -> erlang:error(execution_beam_attempt_busy)
            end;
        {error, _} ->
            erlang:error(execution_beam_operation_lock_inspection_failed)
    end.

execution_beam_operation_claim_exact(Root, Directory) ->
    Expected = filename:basename(Directory),
    FoldedExpected = string:casefold(Expected),
    case file:list_dir(Root) of
        {ok, Names} ->
            case execution_beam_names_unique(Names) of
                true -> ok;
                false -> erlang:error(execution_beam_operation_lock_changed)
            end,
            Matches = [Name || Name <- Names,
                string:casefold(Name) =:= FoldedExpected],
            Legacy = [Name || Name <- Names,
                lists:prefix(".terminal-operation.claim-",
                             string:casefold(Name))],
            case {Matches, Legacy} of
                {[Expected], []} -> true;
                _ -> erlang:error(execution_beam_operation_lock_changed)
            end;
        {error, _} ->
            erlang:error(execution_beam_operation_lock_inspection_failed)
    end.

execution_beam_operation_directory_exact(Lock) ->
    Directory = maps:get(directory, Lock),
    Expected = filename:basename(maps:get(path, Lock)),
    case file:list_dir(Directory) of
        {ok, Names} ->
            case execution_beam_names_unique(Names) of
                true -> ok;
                false -> erlang:error(execution_beam_operation_lock_changed)
            end,
            case lists:sort(Names) of
                [Expected] -> true;
                _ -> erlang:error(execution_beam_operation_lock_changed)
            end;
        {error, _} ->
            erlang:error(execution_beam_operation_lock_inspection_failed)
    end.

execution_beam_release_operation_if_owned(Lock) ->
    Guard = maps:get(guard, Lock),
    Handle = maps:get(handle, Guard),
    case file:read_file_info(Handle) of
        {ok, _} ->
            try execution_beam_verify_operation_guard(Lock)
            after ok = execution_beam_close_operation_guard(Lock)
            end,
            execution_beam_release_operation_directory(Lock);
        {error, einval} ->
            case file:read_link_info(maps:get(directory, Lock)) of
                {error, enoent} -> ok;
                _ -> erlang:error(execution_beam_operation_guard_changed)
            end;
        _ -> erlang:error(execution_beam_operation_guard_changed)
    end.

execution_beam_release_operation_required(Lock) ->
    ok = execution_beam_verify_operation_guard(Lock),
    ok = execution_beam_close_operation_guard(Lock),
    execution_beam_release_operation_directory(Lock).

execution_beam_release_operation_directory(Lock) ->
    Root = maps:get(root, Lock),
    Directory = maps:get(directory, Lock),
    Path = maps:get(path, Lock),
    Bytes = maps:get(bytes, Lock),
    GuardIdentity = maps:get(identity, maps:get(guard, Lock)),
    try
        ok = execution_beam_equal_or_error(maps:get(root_identity, Lock),
            execution_beam_directory_identity(
                execution_beam_directory_info(Root)),
            execution_beam_attempt_root_changed),
        true = execution_beam_operation_claim_exact(Root, Directory),
        ok = execution_beam_equal_or_error(maps:get(directory_identity, Lock),
            execution_beam_directory_identity(
                execution_beam_directory_info(Directory)),
            execution_beam_operation_lock_changed),
        true = execution_beam_operation_directory_exact(Lock),
        Info = execution_beam_regular_info(Path),
        case element(9, Info) =:= 1 of
            true -> ok;
            false -> erlang:error(execution_beam_operation_lock_changed)
        end,
        ok = execution_beam_equal_or_error(GuardIdentity,
            execution_beam_file_identity(Info),
            execution_beam_operation_lock_changed),
        ok = execution_beam_equal_or_error(Bytes,
            execution_beam_read(Path, ?EXECUTION_BEAM_OWNER_MAXIMUM),
            execution_beam_operation_lock_changed),
        ok = execution_beam_equal_or_error(maps:get(directory_identity, Lock),
            execution_beam_directory_identity(
                execution_beam_directory_info(Directory)),
            execution_beam_operation_lock_changed),
        ok = execution_beam_delete_result(file:delete(Path)),
        true = execution_beam_path_absent(Path),
        ok = execution_beam_equal_or_error(maps:get(root_identity, Lock),
            execution_beam_directory_identity(
                execution_beam_directory_info(Root)),
            execution_beam_attempt_root_changed),
        true = execution_beam_operation_claim_exact(Root, Directory),
        ok = execution_beam_equal_or_error(maps:get(directory_identity, Lock),
            execution_beam_directory_identity(
                execution_beam_directory_info(Directory)),
            execution_beam_operation_lock_changed),
        case file:list_dir(Directory) of
            {ok, []} -> ok;
            {ok, _} -> erlang:error(execution_beam_operation_lock_changed);
            {error, _} ->
                erlang:error(execution_beam_operation_lock_inspection_failed)
        end,
        ok = execution_beam_delete_result(file:del_dir(Directory)),
        true = execution_beam_path_absent(Directory),
        ok
    catch
        Class:Reason:Stack ->
            ok = execution_beam_restore_operation_receipt(Lock),
            erlang:raise(Class, Reason, Stack)
    end.

execution_beam_restore_operation_receipt(Lock) ->
    Root = maps:get(root, Lock),
    Directory = maps:get(directory, Lock),
    Path = maps:get(path, Lock),
    Bytes = maps:get(bytes, Lock),
    case file:read_link_info(Directory) of
        {error, enoent} -> ok;
        {ok, Info} when element(3, Info) =:= directory ->
            ok = execution_beam_equal_or_error(maps:get(root_identity, Lock),
                execution_beam_directory_identity(
                    execution_beam_directory_info(Root)),
                execution_beam_attempt_root_changed),
            ok = execution_beam_equal_or_error(maps:get(directory_identity, Lock),
                execution_beam_directory_identity(Info),
                execution_beam_operation_lock_changed),
            case file:read_link_info(Path) of
                {error, enoent} ->
                    execution_beam_publish_new(
                        Path, Bytes, ?EXECUTION_BEAM_OWNER_MAXIMUM);
                {ok, PathInfo} when element(3, PathInfo) =:= regular,
                                         element(9, PathInfo) =:= 1 ->
                    ok = execution_beam_equal_or_error(Bytes,
                        execution_beam_read(
                            Path, ?EXECUTION_BEAM_OWNER_MAXIMUM),
                        execution_beam_operation_lock_changed),
                    ok;
                _ -> erlang:error(execution_beam_operation_lock_restore_failed)
            end;
        _ -> erlang:error(execution_beam_operation_lock_restore_failed)
    end.

execution_beam_release_locked(Root, Owner, ExpectedOwner, Lock, Hooks,
                              Recovery) ->
    ok = execution_beam_hook(Hooks, before_preflight,
                             #{root => Root, owner => Owner}),
    Entries = execution_beam_preflight_tree(
        Root, Owner, ExpectedOwner, Lock),
    ok = execution_beam_hook(Hooks, after_preflight,
                             #{root => Root, owner => Owner,
                               entries => Entries}),
    execution_beam_verify_terminal_owners(Root, Owner, ExpectedOwner, Lock),
    RecoveryResult = execution_beam_capture_recovery(
        Recovery, Root, Owner, ExpectedOwner, Lock, Entries),
    {Files, Directories} = execution_beam_removal_entries(Entries),
    lists:foreach(fun(Entry) ->
        execution_beam_remove_entry(
            Entry, Owner, ExpectedOwner, Lock, Hooks, file)
    end, Files),
    lists:foreach(fun(Entry) ->
        execution_beam_remove_entry(
            Entry, Owner, ExpectedOwner, Lock, Hooks, directory)
    end, Directories),
    execution_beam_verify_terminal_owners(Root, Owner, ExpectedOwner, Lock),
    execution_beam_only_terminal_entries(Root, Owner, Lock),
    ok = execution_beam_hook(Hooks, before_owner_delete,
                             #{root => Root, owner => Owner}),
    execution_beam_verify_terminal_owners(Root, Owner, ExpectedOwner, Lock),
    try
        ok = file:delete(Owner),
        true = execution_beam_path_absent(Owner),
        ok = execution_beam_release_operation_required(Lock),
        DeleteRoot = maps:get(delete_root, Hooks),
        case DeleteRoot(Root) of
            ok -> ok;
            {error, enoent} -> erlang:error(execution_beam_attempt_root_changed);
            {error, _} -> erlang:error(execution_beam_attempt_root_delete_failed)
        end,
        true = execution_beam_path_absent(Root),
        case RecoveryResult of none -> ok; Result -> Result end
    catch
        Class:Reason:Stack ->
            ok = execution_beam_restore_owner(
                Root, Owner, ExpectedOwner, maps:get(root_identity, Lock)),
            erlang:raise(Class, Reason, Stack)
    end.

execution_beam_restore_owner(Root, Owner, ExpectedOwner, RootIdentity) ->
    case file:read_link_info(Root) of
        {error, enoent} -> ok;
        {ok, Info} when element(3, Info) =:= directory ->
            ok = execution_beam_equal_or_error(RootIdentity,
                execution_beam_directory_identity(
                    execution_beam_directory_info(Root)),
                execution_beam_attempt_root_changed),
            case file:read_link_info(Owner) of
                {error, enoent} -> execution_beam_publish_new(
                    Owner, ExpectedOwner, ?EXECUTION_BEAM_OWNER_MAXIMUM);
                {ok, OwnerInfo} when element(3, OwnerInfo) =:= regular,
                                     element(9, OwnerInfo) =:= 1 ->
                    ok = execution_beam_equal_or_error(ExpectedOwner,
                        execution_beam_read(
                            Owner, ?EXECUTION_BEAM_OWNER_MAXIMUM),
                        execution_beam_owner_changed),
                    ok;
                _ -> erlang:error(execution_beam_owner_restore_failed)
            end;
        _ -> erlang:error(execution_beam_owner_restore_failed)
    end.

execution_beam_release_hooks() ->
    #{before_preflight => fun(_) -> ok end,
      after_preflight => fun(_) -> ok end,
      before_delete => fun(_) -> ok end,
      delete_file => fun file:delete/1,
      delete_directory => fun file:del_dir/1,
      delete_root => fun file:del_dir/1,
      before_owner_delete => fun(_) -> ok end,
      snapshot_captured => fun(_) -> ok end}.

execution_beam_hook(Hooks, Name, Argument) ->
    Function = maps:get(Name, Hooks),
    ok = Function(Argument).

execution_beam_preflight_tree(Root, Owner, ExpectedOwner, Lock) ->
    _ = execution_beam_directory_info(Root),
    execution_beam_verify_terminal_owners(Root, Owner, ExpectedOwner, Lock),
    {Entries, Count, Bytes} = execution_beam_preflight_directory(
        Root, Root, Owner, ExpectedOwner, Lock, [], 0, 0),
    true = Count =< ?EXECUTION_BEAM_ENTRY_COUNT_MAXIMUM,
    true = Bytes =< ?EXECUTION_BEAM_TREE_MAXIMUM,
    execution_beam_verify_terminal_owners(Root, Owner, ExpectedOwner, Lock),
    Entries.

execution_beam_preflight_directory(Path, Root, Owner, ExpectedOwner, Lock,
                                   Entries0, Count0, Bytes0) ->
    true = Count0 =< ?EXECUTION_BEAM_ENTRY_COUNT_MAXIMUM,
    true = Bytes0 =< ?EXECUTION_BEAM_TREE_MAXIMUM,
    Initial = execution_beam_directory_info(Path),
    {ok, Names0} = file:list_dir(Path),
    Names = lists:sort(Names0),
    true = Count0 + length(Names) =< ?EXECUTION_BEAM_ENTRY_COUNT_MAXIMUM,
    true = execution_beam_names_unique(Names),
    {Entries1, Count1, Bytes1} = lists:foldl(fun(Name, Acc) ->
        execution_beam_preflight_entry(filename:join(Path, Name), Root,
            Owner, ExpectedOwner, Lock, Acc)
    end, {Entries0, Count0, Bytes0}, Names),
    Final = execution_beam_directory_info(Path),
    true = execution_beam_directory_identity(Initial) =:=
           execution_beam_directory_identity(Final),
    case Path =:= Root of
        true -> {Entries1, Count1, Bytes1};
        false ->
            Entry = #{type => directory, path => Path,
                path_sha256 => execution_beam_relative_path_sha256(Path, Root),
                identity => execution_beam_directory_identity(Final),
                depth => execution_beam_relative_depth(Path, Root), size => 0},
            {[Entry | Entries1], Count1 + 1, Bytes1}
    end.

execution_beam_preflight_entry(Path, Root, Owner, ExpectedOwner, Lock,
                               {Entries, Count, Bytes}) ->
    LockDirectory = maps:get(directory, Lock),
    case Path of
        Owner ->
            ok = execution_beam_equal_or_error(ExpectedOwner,
                execution_beam_read(Owner, ?EXECUTION_BEAM_OWNER_MAXIMUM),
                execution_beam_owner_changed),
            {Entries, Count + 1, Bytes + byte_size(ExpectedOwner)};
        LockDirectory ->
            LockBytes = maps:get(bytes, Lock),
            ok = execution_beam_verify_operation_guard(Lock),
            {Entries, Count + 2, Bytes + byte_size(LockBytes)};
        _ ->
            case {execution_beam_terminal_alias(Path, Owner),
                  execution_beam_terminal_alias(Path, LockDirectory)} of
                {true, _} -> erlang:error(execution_beam_owner_changed);
                {_, true} ->
                    erlang:error(execution_beam_operation_lock_changed);
                _ -> execution_beam_preflight_nonterminal(
                    Path, Root, Owner, ExpectedOwner, Lock,
                    Entries, Count, Bytes)
            end
    end.

execution_beam_preflight_nonterminal(Path, Root, Owner, ExpectedOwner, Lock,
                                     Entries, Count, Bytes) ->
    case file:read_link_info(Path) of
        {ok, Info} ->
            case execution_beam_entry_kind(Info) of
                directory -> execution_beam_preflight_directory(
                    Path, Root, Owner, ExpectedOwner, Lock,
                    Entries, Count, Bytes);
                regular ->
                    Captured = execution_beam_read(
                        Path, ?EXECUTION_BEAM_ENTRY_MAXIMUM),
                    true = Bytes + byte_size(Captured) =<
                           ?EXECUTION_BEAM_TREE_MAXIMUM,
                    Current = execution_beam_regular_info(Path),
                    Entry = #{type => file, path => Path,
                        path_sha256 => execution_beam_relative_path_sha256(
                            Path, Root),
                        identity => execution_beam_file_identity(Current),
                        sha256 => execution_beam_sha256(Captured),
                        depth => execution_beam_relative_depth(Path, Root),
                        size => byte_size(Captured)},
                    {[Entry | Entries], Count + 1,
                     Bytes + byte_size(Captured)}
            end;
        {error, enoent} -> erlang:error(execution_beam_attempt_changed);
        {error, _} -> erlang:error(execution_beam_attempt_inspection_failed)
    end.

execution_beam_entry_kind(Info) when element(1, Info) =:= file_info,
                                      element(3, Info) =:= directory ->
    directory;
execution_beam_entry_kind(Info) when element(1, Info) =:= file_info,
                                      element(3, Info) =:= regular,
                                      element(9, Info) =:= 1,
                                      element(2, Info) >= 0,
                                      element(2, Info) =<
                                          ?EXECUTION_BEAM_ENTRY_MAXIMUM ->
    regular;
execution_beam_entry_kind(Info) when element(1, Info) =:= file_info,
                                      element(3, Info) =:= symlink ->
    erlang:error(execution_beam_attempt_link_rejected);
execution_beam_entry_kind(_) ->
    erlang:error(execution_beam_attempt_special_file_rejected).

execution_beam_names_unique(Names) ->
    Folded = [string:casefold(Name) || Name <- Names],
    length(Folded) =:= length(lists:usort(Folded)).

execution_beam_terminal_alias(Path, Terminal) ->
    filename:dirname(Path) =:= filename:dirname(Terminal) andalso
    string:casefold(filename:basename(Path)) =:=
        string:casefold(filename:basename(Terminal)).

execution_beam_directory_identity(Info) ->
    Stable = {element(3, Info), element(4, Info), element(8, Info),
              element(10, Info), element(11, Info), element(12, Info),
              element(13, Info), element(14, Info)},
    case os:type() of
        %% OTP exposes no useful inode/device identity for an NTFS directory.
        %% Its ctime is the creation time and, unlike mtime,
        %% remains stable while this transaction creates and removes children.
        {win32, _} -> {Stable, element(7, Info)};
        _ -> Stable
    end.

execution_beam_relative_path_sha256(Path, Root) ->
    RootParts = filename:split(filename:absname(Root)),
    PathParts = filename:split(filename:absname(Path)),
    true = lists:prefix(RootParts, PathParts),
    Relative = filename:join(lists:nthtail(length(RootParts), PathParts)),
    execution_beam_sha256(unicode:characters_to_binary(Relative)).

execution_beam_relative_depth(Path, Root) ->
    RootParts = filename:split(filename:absname(Root)),
    PathParts = filename:split(filename:absname(Path)),
    true = lists:prefix(RootParts, PathParts),
    length(PathParts) - length(RootParts).

execution_beam_removal_entries(Entries) ->
    Files = lists:sort(fun(A, B) ->
        maps:get(path_sha256, A) =< maps:get(path_sha256, B)
    end, [Entry || Entry <- Entries, maps:get(type, Entry) =:= file]),
    Directories = lists:sort(fun(A, B) ->
        case maps:get(depth, A) =:= maps:get(depth, B) of
            true -> maps:get(path_sha256, A) =< maps:get(path_sha256, B);
            false -> maps:get(depth, A) > maps:get(depth, B)
        end
    end, [Entry || Entry <- Entries,
                    maps:get(type, Entry) =:= directory]),
    {Files, Directories}.

execution_beam_remove_entry(Entry, Owner, ExpectedOwner, Lock, Hooks, Type) ->
    Type = maps:get(type, Entry),
    Root = maps:get(root, Lock),
    execution_beam_verify_terminal_owners(Root, Owner, ExpectedOwner, Lock),
    ok = execution_beam_hook(Hooks, before_delete,
        maps:with([type, path_sha256, depth, size], Entry)),
    case Type of
        file ->
            Path = maps:get(path, Entry),
            Info = execution_beam_regular_info(Path),
            true = maps:get(identity, Entry) =:=
                   execution_beam_file_identity(Info),
            Captured = execution_beam_read(
                Path, ?EXECUTION_BEAM_ENTRY_MAXIMUM),
            true = maps:get(sha256, Entry) =:= execution_beam_sha256(Captured),
            Delete = maps:get(delete_file, Hooks),
            ok = execution_beam_delete_result(Delete(Path));
        directory ->
            Path = maps:get(path, Entry),
            Info = execution_beam_directory_info(Path),
            true = maps:get(identity, Entry) =:=
                   execution_beam_directory_identity(Info),
            {ok, []} = file:list_dir(Path),
            Delete = maps:get(delete_directory, Hooks),
            ok = execution_beam_delete_result(Delete(Path))
    end,
    true = execution_beam_path_absent(maps:get(path, Entry)),
    execution_beam_verify_terminal_owners(Root, Owner, ExpectedOwner, Lock),
    ok.

execution_beam_delete_result(ok) -> ok;
execution_beam_delete_result({error, _}) ->
    erlang:error(execution_beam_attempt_cleanup_failed);
execution_beam_delete_result(_) ->
    erlang:error(execution_beam_attempt_cleanup_failed).

execution_beam_verify_terminal_owners(Root, Owner, ExpectedOwner, Lock) ->
    ok = execution_beam_equal_or_error(maps:get(root_identity, Lock),
        execution_beam_directory_identity(execution_beam_directory_info(Root)),
        execution_beam_attempt_root_changed),
    ok = execution_beam_verify_operation_guard(Lock),
    ok = execution_beam_equal_or_error(ExpectedOwner,
        execution_beam_read(Owner, ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_owner_changed),
    LockBytes = maps:get(bytes, Lock),
    ok = execution_beam_equal_or_error(LockBytes,
        execution_beam_read(
            maps:get(path, Lock), ?EXECUTION_BEAM_OWNER_MAXIMUM),
        execution_beam_operation_lock_changed),
    ok.

execution_beam_only_terminal_entries(Root, Owner, Lock) ->
    {ok, Names} = file:list_dir(Root),
    Expected = lists:sort([filename:basename(Owner),
                           filename:basename(maps:get(directory, Lock))]),
    Expected = lists:sort(Names),
    ok.

execution_beam_capture_recovery(none, _, _, _, _, _) -> none;
execution_beam_capture_recovery(Recovery, Root, _Owner, ExpectedOwner, _Lock,
                                Entries) when is_map(Recovery) ->
    SnapshotPath = maps:get(snapshot_path, Recovery),
    Nonce = maps:get(nonce, Recovery),
    DeathProof = maps:get(death_proof, Recovery),
    Summary = execution_beam_tree_summary(Entries),
    Snapshot = #{schema => 1,
        report_kind => <<"stale_execution_beam_attempt">>,
        status => <<"Captured">>, shareable => true,
        attempt_sha256 => execution_beam_sha256(Nonce),
        owner_sha256 => execution_beam_sha256(ExpectedOwner),
        owner_liveness => <<"dead">>,
        death_proof => atom_to_binary(maps:get(kind, DeathProof), utf8),
        tree => Summary,
        captured_at_unix_ms => execution_beam_finite_system_time(),
        runtime_identity => execution_beam_runtime_identity(),
        source_identity => execution_beam_source_identity(),
        recovery_nonce => binary:encode_hex(
            crypto:strong_rand_bytes(16), lowercase)},
    SnapshotBytes = iolist_to_binary([json:encode(Snapshot), $\n]),
    case file:read_link_info(SnapshotPath) of
        {error, enoent} -> ok;
        {ok, _} -> erlang:error(execution_beam_recovery_snapshot_exists);
        {error, _} -> erlang:error(execution_beam_recovery_snapshot_rejected)
    end,
    ok = execution_beam_publish_new(SnapshotPath, SnapshotBytes, 65536),
    Stored = execution_beam_read(SnapshotPath, 65536),
    true = execution_beam_recovery_snapshot_valid(
        json:decode(Stored), Nonce, ExpectedOwner),
    ok = execution_beam_hook(maps:get(hooks, Recovery,
        execution_beam_release_hooks()), snapshot_captured,
        #{snapshot_sha256 => execution_beam_sha256(Stored)}),
    #{snapshot_sha256 => execution_beam_sha256(Stored), root => Root}.

execution_beam_tree_summary(Entries) ->
    SafeRows = lists:sort([case maps:get(type, Entry) of
        file -> {file, maps:get(path_sha256, Entry), maps:get(sha256, Entry),
                 maps:get(size, Entry), maps:get(depth, Entry)};
        directory -> {directory, maps:get(path_sha256, Entry),
                      maps:get(depth, Entry)}
    end || Entry <- Entries]),
    FileCount = length([ok || Entry <- Entries,
                             maps:get(type, Entry) =:= file]),
    DirectoryCount = length(Entries) - FileCount,
    Bytes = lists:sum([maps:get(size, Entry) || Entry <- Entries,
                                                   maps:get(type, Entry) =:= file]),
    Depths = [maps:get(depth, Entry) || Entry <- Entries],
    #{schema => 1, files => FileCount, directories => DirectoryCount,
      bytes => Bytes,
      max_depth => case Depths of [] -> 0; _ -> lists:max(Depths) end,
      digest => execution_beam_sha256(
          term_to_binary(SafeRows, [{minor_version, 2}]))}.

execution_beam_recovery_snapshot_valid(Snapshot, Nonce, OwnerBytes) ->
    is_map(Snapshot) andalso maps:size(Snapshot) =:= 13 andalso
    maps:get(<<"schema">>, Snapshot, invalid) =:= 1 andalso
    maps:get(<<"report_kind">>, Snapshot, invalid) =:=
        <<"stale_execution_beam_attempt">> andalso
    maps:get(<<"status">>, Snapshot, invalid) =:= <<"Captured">> andalso
    maps:get(<<"shareable">>, Snapshot, invalid) =:= true andalso
    maps:get(<<"attempt_sha256">>, Snapshot, invalid) =:=
        execution_beam_sha256(Nonce) andalso
    maps:get(<<"owner_sha256">>, Snapshot, invalid) =:=
        execution_beam_sha256(OwnerBytes) andalso
    maps:get(<<"owner_liveness">>, Snapshot, invalid) =:= <<"dead">> andalso
    execution_beam_digest(maps:get(<<"recovery_nonce">>, Snapshot, <<>>), 32)
    andalso lists:member(maps:get(<<"death_proof">>, Snapshot, <<>>),
        [<<"pid_absent">>, <<"pid_reused">>, <<"host_rebooted">>]) andalso
    execution_beam_tree_summary_valid(
        maps:get(<<"tree">>, Snapshot, invalid)) andalso
    execution_beam_timestamp(
        maps:get(<<"captured_at_unix_ms">>, Snapshot, invalid)) andalso
    execution_beam_runtime_identity_valid(
        maps:get(<<"runtime_identity">>, Snapshot, invalid), binary_keys)
    andalso execution_beam_source_identity_valid(
        maps:get(<<"source_identity">>, Snapshot, invalid), binary_keys).

execution_beam_tree_summary_valid(Tree) when is_map(Tree),
                                                map_size(Tree) =:= 6 ->
    Files = maps:get(<<"files">>, Tree, invalid),
    Directories = maps:get(<<"directories">>, Tree, invalid),
    Bytes = maps:get(<<"bytes">>, Tree, invalid),
    Depth = maps:get(<<"max_depth">>, Tree, invalid),
    maps:get(<<"schema">>, Tree, invalid) =:= 1 andalso
    is_integer(Files) andalso Files >= 0 andalso
    is_integer(Directories) andalso Directories >= 0 andalso
    Files + Directories =< ?EXECUTION_BEAM_ENTRY_COUNT_MAXIMUM andalso
    is_integer(Bytes) andalso Bytes >= 0 andalso
    Bytes =< ?EXECUTION_BEAM_TREE_MAXIMUM andalso
    is_integer(Depth) andalso Depth >= 0 andalso
    Depth =< ?EXECUTION_BEAM_ENTRY_COUNT_MAXIMUM andalso
    execution_beam_digest(maps:get(<<"digest">>, Tree, <<>>), 64);
execution_beam_tree_summary_valid(_) -> false.

execution_beam_path_within(Path0, Root0) ->
    Path = [string:casefold(Part) || Part <-
        filename:split(filename:absname(Path0))],
    Root = [string:casefold(Part) || Part <-
        filename:split(filename:absname(Root0))],
    lists:prefix(Root, Path).

execution_beam_owner_receipt(Nonce) ->
    #{schema => 2, kind => <<"execution_beam_attempt">>, nonce => Nonce,
      status => <<"Running">>,
      created_at_unix_ms => execution_beam_finite_system_time(),
      owner => execution_beam_process_owner_identity(),
      runtime_identity => execution_beam_runtime_identity(),
      source_identity => execution_beam_source_identity()}.

execution_beam_process_owner_identity() ->
    Pid = unicode:characters_to_binary(os:getpid()),
    true = execution_beam_decimal(Pid),
    case execution_beam_platform_observation(Pid) of
        {ok, Host, {live, Start}} ->
            #{os_pid => Pid, proof_status => <<"Available">>,
              host_identity => Host, process_start_identity => Start,
              failure_code => null};
        {ok, _, dead} -> erlang:error(execution_beam_owner_identity_failed);
        {error, Reason} ->
            #{os_pid => Pid, proof_status => <<"Unavailable">>,
              host_identity => execution_beam_weak_host_identity(),
              process_start_identity => execution_beam_weak_start_identity(),
              failure_code => atom_to_binary(Reason, utf8)}
    end.

execution_beam_owner_receipt_valid(Receipt, Nonce) ->
    case Receipt of
        #{schema := 2, kind := <<"execution_beam_attempt">>,
          nonce := Nonce, status := <<"Running">>,
          created_at_unix_ms := Created, owner := Owner,
          runtime_identity := Runtime, source_identity := Source}
          when map_size(Receipt) =:= 8 ->
            execution_beam_timestamp(Created) andalso
            execution_beam_process_owner_valid(Owner, atom_keys) andalso
            execution_beam_runtime_identity_valid(Runtime, atom_keys) andalso
            execution_beam_source_identity_valid(Source, atom_keys);
        #{<<"schema">> := 2,
          <<"kind">> := <<"execution_beam_attempt">>,
          <<"nonce">> := Nonce, <<"status">> := <<"Running">>,
          <<"created_at_unix_ms">> := Created, <<"owner">> := Owner,
          <<"runtime_identity">> := Runtime,
          <<"source_identity">> := Source}
          when map_size(Receipt) =:= 8 ->
            execution_beam_timestamp(Created) andalso
            execution_beam_process_owner_valid(Owner, binary_keys) andalso
            execution_beam_runtime_identity_valid(Runtime, binary_keys) andalso
            execution_beam_source_identity_valid(Source, binary_keys);
        _ -> false
    end.

execution_beam_process_owner_valid(Owner, atom_keys) ->
    case Owner of
        #{os_pid := Pid, proof_status := Status,
          host_identity := Host, process_start_identity := Start,
          failure_code := Failure} when map_size(Owner) =:= 5 ->
            execution_beam_process_owner_fields(Pid, Status, Host, Start, Failure,
                                                atom_keys);
        _ -> false
    end;
execution_beam_process_owner_valid(Owner, binary_keys) ->
    case Owner of
        #{<<"os_pid">> := Pid, <<"proof_status">> := Status,
          <<"host_identity">> := Host,
          <<"process_start_identity">> := Start,
          <<"failure_code">> := Failure} when map_size(Owner) =:= 5 ->
            execution_beam_process_owner_fields(Pid, Status, Host, Start, Failure,
                                                binary_keys);
        _ -> false
    end.

execution_beam_process_owner_fields(Pid, <<"Available">>, Host, Start, null,
                                    Keys) ->
    execution_beam_decimal(Pid) andalso
    execution_beam_host_identity_valid(Host, Keys) andalso
    execution_beam_start_identity_valid(Start, Keys);
execution_beam_process_owner_fields(Pid, <<"Unavailable">>, Host, Start,
                                    Failure, Keys) ->
    execution_beam_decimal(Pid) andalso execution_beam_safe_code(Failure)
    andalso execution_beam_host_identity_valid(Host, Keys)
    andalso execution_beam_start_identity_valid(Start, Keys);
execution_beam_process_owner_fields(_, _, _, _, _, _) -> false.

execution_beam_host_identity_valid(Host, atom_keys) ->
    case Host of
        #{kind := Kind, machine_sha256 := Machine,
          boot_sha256 := Boot} when map_size(Host) =:= 3 ->
            execution_beam_safe_code(Kind) andalso
            execution_beam_digest(Machine, 64) andalso
            execution_beam_digest(Boot, 64);
        _ -> false
    end;
execution_beam_host_identity_valid(Host, binary_keys) ->
    case Host of
        #{<<"kind">> := Kind, <<"machine_sha256">> := Machine,
          <<"boot_sha256">> := Boot} when map_size(Host) =:= 3 ->
            execution_beam_safe_code(Kind) andalso
            execution_beam_digest(Machine, 64) andalso
            execution_beam_digest(Boot, 64);
        _ -> false
    end.

execution_beam_start_identity_valid(Start, atom_keys) ->
    case Start of
        #{kind := Kind, sha256 := Digest} when map_size(Start) =:= 2 ->
            execution_beam_safe_code(Kind) andalso
            execution_beam_digest(Digest, 64);
        _ -> false
    end;
execution_beam_start_identity_valid(Start, binary_keys) ->
    case Start of
        #{<<"kind">> := Kind, <<"sha256">> := Digest}
          when map_size(Start) =:= 2 ->
            execution_beam_safe_code(Kind) andalso
            execution_beam_digest(Digest, 64);
        _ -> false
    end.

execution_beam_runtime_identity() ->
    {OsFamily, OsName} = os:type(),
    #{schema => 1, kind => <<"erlang_runtime">>,
      otp_release => unicode:characters_to_binary(
          erlang:system_info(otp_release)),
      erts_version => unicode:characters_to_binary(
          erlang:system_info(version)),
      os => unicode:characters_to_binary(
          atom_to_list(OsFamily) ++ "/" ++ atom_to_list(OsName)),
      architecture => unicode:characters_to_binary(
          erlang:system_info(system_architecture))}.

execution_beam_runtime_identity_valid(Runtime, atom_keys) ->
    case Runtime of
        #{schema := 1, kind := <<"erlang_runtime">>, otp_release := Otp,
          erts_version := Erts, os := Os, architecture := Architecture}
          when map_size(Runtime) =:= 6 ->
            lists:all(fun execution_beam_safe_text/1,
                      [Otp, Erts, Os, Architecture]);
        _ -> false
    end;
execution_beam_runtime_identity_valid(Runtime, binary_keys) ->
    case Runtime of
        #{<<"schema">> := 1, <<"kind">> := <<"erlang_runtime">>,
          <<"otp_release">> := Otp, <<"erts_version">> := Erts,
          <<"os">> := Os, <<"architecture">> := Architecture}
          when map_size(Runtime) =:= 6 ->
            lists:all(fun execution_beam_safe_text/1,
                      [Otp, Erts, Os, Architecture]);
        _ -> false
    end.

execution_beam_source_identity() ->
    ScriptDirectory = filename:dirname(filename:absname(escript:script_name())),
    Directories = lists:usort([ScriptDirectory, filename:absname("scripts")]),
    Files = ["evidence_publication.hrl", "execution_beam_identity.hrl"],
    Rows = [execution_beam_source_file_identity(Name, Directories)
            || Name <- Files],
    #{schema => 1, kind => <<"execution_beam_source">>, files => length(Rows),
      sha256 => execution_beam_sha256(
          term_to_binary(Rows, [{minor_version, 2}]))}.

execution_beam_source_file_identity(Name, Directories) ->
    Existing = [Path || Directory <- Directories,
        Path <- [filename:join(Directory, Name)],
        case file:read_link_info(Path) of
            {ok, Info} when element(3, Info) =:= regular,
                            element(9, Info) =:= 1 -> true;
            {error, enoent} -> false;
            _ -> erlang:error(execution_beam_source_identity_rejected)
        end],
    true = Existing =/= [],
    Digests = lists:usort([execution_beam_sha256(
        execution_beam_read(Path, 1048576)) || Path <- Existing]),
    [Digest] = Digests,
    {unicode:characters_to_binary(Name), Digest}.

execution_beam_source_identity_valid(Source, atom_keys) ->
    case Source of
        #{schema := 1, kind := <<"execution_beam_source">>, files := 2,
          sha256 := Digest} when map_size(Source) =:= 4 ->
            execution_beam_digest(Digest, 64);
        _ -> false
    end;
execution_beam_source_identity_valid(Source, binary_keys) ->
    case Source of
        #{<<"schema">> := 1,
          <<"kind">> := <<"execution_beam_source">>, <<"files">> := 2,
          <<"sha256">> := Digest} when map_size(Source) =:= 4 ->
            execution_beam_digest(Digest, 64);
        _ -> false
    end.

execution_beam_decode_owner_receipt(Bytes, Nonce) ->
    try json:decode(Bytes) of
        Receipt ->
            case execution_beam_owner_receipt_valid(Receipt, Nonce) of
                true -> Receipt;
                false -> erlang:error(execution_beam_owner_unverifiable)
            end
    catch
        error:execution_beam_owner_unverifiable ->
            erlang:error(execution_beam_owner_unverifiable);
        _:_ -> erlang:error(execution_beam_owner_unverifiable)
    end.

execution_beam_owner_death_proof(Receipt) ->
    Owner = maps:get(<<"owner">>, Receipt),
    case maps:get(<<"proof_status">>, Owner) of
        <<"Available">> -> ok;
        _ -> erlang:error(execution_beam_owner_unverifiable)
    end,
    Pid = maps:get(<<"os_pid">>, Owner),
    ExpectedHost = execution_beam_normalize_host(
        maps:get(<<"host_identity">>, Owner)),
    ExpectedStart = execution_beam_normalize_start(
        maps:get(<<"process_start_identity">>, Owner)),
    case execution_beam_platform_observation(Pid) of
        {ok, CurrentHost, ProcessState} ->
            case maps:get(kind, CurrentHost) =:= maps:get(kind, ExpectedHost)
                 andalso maps:get(machine_sha256, CurrentHost) =:=
                         maps:get(machine_sha256, ExpectedHost) of
                false -> erlang:error(execution_beam_owner_host_unverifiable);
                true ->
                    case maps:get(boot_sha256, CurrentHost) =:=
                         maps:get(boot_sha256, ExpectedHost) of
                        false -> #{kind => host_rebooted};
                        true -> execution_beam_process_death_proof(
                            ProcessState, ExpectedStart)
                    end
            end;
        {error, _} -> erlang:error(execution_beam_owner_unverifiable)
    end.

execution_beam_process_death_proof(dead, _) -> #{kind => pid_absent};
execution_beam_process_death_proof({live, Current}, Expected) ->
    case Current =:= Expected of
        true -> erlang:error(execution_beam_owner_active);
        false -> #{kind => pid_reused}
    end.

execution_beam_normalize_host(Host) ->
    #{kind => maps:get(<<"kind">>, Host),
      machine_sha256 => maps:get(<<"machine_sha256">>, Host),
      boot_sha256 => maps:get(<<"boot_sha256">>, Host)}.

execution_beam_normalize_start(Start) ->
    #{kind => maps:get(<<"kind">>, Start),
      sha256 => maps:get(<<"sha256">>, Start)}.

%% Windows has no stable process-start or boot identity in the Erlang runtime
%% API.  Callers that already own the native process tree can inject one
%% bounded capture operation.  The self observation is cached only for this
%% still-running BEAM process; arbitrary PIDs are always queried afresh so a
%% stale-recovery decision cannot reuse an old absence result.
execution_beam_with_owned_platform_observer(Capture, Operation)
  when is_function(Capture, 4), is_function(Operation, 0) ->
    Previous = get(execution_beam_owner_observation_provider),
    case os:type() of
        {win32, nt} ->
            SelfPid = unicode:characters_to_binary(os:getpid()),
            SelfObservation = execution_beam_windows_owned_observation(
                SelfPid, Capture),
            Provider = fun(Pid) ->
                case Pid =:= SelfPid of
                    true -> SelfObservation;
                    false -> execution_beam_windows_owned_observation(
                        Pid, Capture)
                end
            end,
            put(execution_beam_owner_observation_provider, Provider);
        _ -> ok
    end,
    try Operation()
    after execution_beam_restore_observation_provider(Previous)
    end.

execution_beam_restore_observation_provider(undefined) ->
    erase(execution_beam_owner_observation_provider), ok;
execution_beam_restore_observation_provider(Previous) ->
    put(execution_beam_owner_observation_provider, Previous), ok.

execution_beam_platform_observation(Pid) ->
    case get(execution_beam_owner_observation_provider) of
        Provider when is_function(Provider, 1) ->
            execution_beam_provider_observation(Provider(Pid));
        undefined -> execution_beam_builtin_platform_observation(Pid);
        _ -> {error, owner_identity_provider_invalid}
    end.

execution_beam_provider_observation({ok, Host, dead}) ->
    case execution_beam_host_identity_valid(Host, atom_keys) of
        true -> {ok, Host, dead};
        false -> {error, owner_identity_provider_invalid}
    end;
execution_beam_provider_observation({ok, Host, {live, Start}}) ->
    case execution_beam_host_identity_valid(Host, atom_keys) andalso
         execution_beam_start_identity_valid(Start, atom_keys) of
        true -> {ok, Host, {live, Start}};
        false -> {error, owner_identity_provider_invalid}
    end;
execution_beam_provider_observation({error, Reason}) when is_atom(Reason) ->
    {error, Reason};
execution_beam_provider_observation(_) ->
    {error, owner_identity_provider_invalid}.

execution_beam_builtin_platform_observation(Pid) ->
    case os:type() of
        {unix, linux} -> execution_beam_linux_observation(Pid);
        {unix, darwin} -> execution_beam_macos_observation(Pid);
        {win32, nt} -> execution_beam_windows_observation(Pid);
        _ -> {error, owner_identity_platform_unsupported}
    end.

execution_beam_linux_observation(Pid) ->
    case {execution_beam_system_file(["/etc/machine-id",
                                      "/var/lib/dbus/machine-id"], 4096),
          execution_beam_system_file(["/proc/sys/kernel/random/boot_id"],
                                     4096)} of
        {{ok, Machine}, {ok, Boot}} ->
            Host = execution_beam_host_identity(
                <<"linux_proc">>, Machine, Boot),
            ProcPath = filename:join(["/proc", binary_to_list(Pid), "stat"]),
            case execution_beam_system_file([ProcPath], 4096) of
                {ok, Stat} ->
                    case execution_beam_linux_start(Stat) of
                        {ok, Start} -> {ok, Host,
                            {live, execution_beam_start_identity(
                                <<"linux_proc_start_ticks">>, Start)}};
                        error -> {error, owner_identity_process_parse_failed}
                    end;
                missing -> {ok, Host, dead};
                {error, _} -> {error, owner_identity_process_query_failed}
            end;
        _ -> {error, owner_identity_host_query_failed}
    end.

execution_beam_linux_start(Stat) ->
    Matches = binary:matches(Stat, <<") ">>),
    case Matches of
        [] -> error;
        _ ->
            {Position, _} = lists:last(Matches),
            TailStart = Position + 2,
            Tail = binary:part(Stat, TailStart, byte_size(Stat) - TailStart),
            Fields = binary:split(Tail, <<" ">>, [global, trim_all]),
            case length(Fields) >= 20 of
                true ->
                    Start = lists:nth(20, Fields),
                    case execution_beam_decimal(Start) of
                        true -> {ok, Start};
                        false -> error
                    end;
                false -> error
            end
    end.

execution_beam_windows_observation(_) ->
    {error, owner_identity_supervised_provider_required}.

execution_beam_windows_owned_observation(Pid, Capture)
  when is_function(Capture, 4) ->
    case execution_beam_decimal(Pid) of
        true -> execution_beam_windows_capture(Pid, Capture);
        false -> {error, owner_identity_pid_invalid}
    end;
execution_beam_windows_owned_observation(_, _) ->
    {error, owner_identity_provider_invalid}.

execution_beam_windows_capture(Pid, Capture) ->
    try
        Executable = execution_beam_windows_powershell(),
        Guard = execution_beam_open_system_executable_guard(Executable),
        try
            Captured = try Capture(
                Executable, execution_beam_windows_capture_arguments(Pid),
                15000, ?EXECUTION_BEAM_OBSERVER_OUTPUT_MAXIMUM)
            catch _:_ -> {error, owner_identity_capture_failed}
            end,
            ok = execution_beam_verify_system_executable_guard(Guard),
            execution_beam_windows_capture_result(Captured)
        after
            ok = execution_beam_close_system_executable_guard(Guard)
        end
    catch _:_ -> {error, owner_identity_process_query_failed}
    end.

execution_beam_windows_capture_arguments(Pid) ->
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
     "Bypass", "-Command", execution_beam_windows_capture_script(Pid)].

execution_beam_windows_capture_script(Pid) ->
    true = execution_beam_decimal(Pid),
    lists:flatten([
        "$ErrorActionPreference='Stop';",
        "function Get-PrivateSha256([string]$v){",
        "$s=[Security.Cryptography.SHA256]::Create();",
        "try{$b=[Text.Encoding]::UTF8.GetBytes($v);$h=$s.ComputeHash($b);",
        "return (($h|ForEach-Object{$_.ToString('x2')}) -join '')}",
        "finally{$s.Dispose()}};",
        "$targetPid=", binary_to_list(Pid), ";try{",
        "$machine=(Get-ItemPropertyValue -LiteralPath ",
        "'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography' ",
        "-Name 'MachineGuid').ToString().Trim().ToLowerInvariant();",
        "$os=Get-CimInstance -ClassName Win32_OperatingSystem ",
        "-Property LastBootUpTime;",
        "$boot=$os.LastBootUpTime.ToUniversalTime().Ticks.ToString(",
        "[Globalization.CultureInfo]::InvariantCulture);",
        "$r=[ordered]@{schema=1;kind='windows_process_observation';",
        "status='dead';machine_sha256=(Get-PrivateSha256 ",
        "('machine-guid-v1:'+$machine));",
        "boot_sha256=(Get-PrivateSha256 ('windows-boot-ticks-v1:'+$boot))};",
        "try{$p=[Diagnostics.Process]::GetProcessById($targetPid)}",
        "catch [ArgumentException]{$p=$null};",
        "if($null -ne $p){try{",
        "$start=$p.StartTime.ToUniversalTime().Ticks.ToString(",
        "[Globalization.CultureInfo]::InvariantCulture);",
        "$r['status']='live';",
        "$r['start_sha256']=(Get-PrivateSha256 ",
        "('windows-process-start-ticks-v1:'+$start))",
        "}finally{$p.Dispose()}};",
        "$j=$r|ConvertTo-Json -Compress;",
        "if($j.Length -gt 1024){exit 74};[Console]::Out.Write($j);exit 0",
        "}catch{exit 73}"
    ]).

execution_beam_windows_capture_result({ok, Bytes})
  when is_binary(Bytes), byte_size(Bytes) > 0,
       byte_size(Bytes) =< ?EXECUTION_BEAM_OBSERVER_OUTPUT_MAXIMUM ->
    execution_beam_windows_observation_decode(Bytes);
execution_beam_windows_capture_result(_) ->
    {error, owner_identity_capture_failed}.

execution_beam_windows_observation_decode(Bytes) ->
    try json:decode(Bytes) of
        #{<<"schema">> := 1,
          <<"kind">> := <<"windows_process_observation">>,
          <<"status">> := <<"dead">>,
          <<"machine_sha256">> := Machine,
          <<"boot_sha256">> := Boot} = Observation
          when map_size(Observation) =:= 5 ->
            true = execution_beam_digest(Machine, 64),
            true = execution_beam_digest(Boot, 64),
            {ok, #{kind => <<"windows_machineguid_boot_time">>,
                   machine_sha256 => Machine, boot_sha256 => Boot}, dead};
        #{<<"schema">> := 1,
          <<"kind">> := <<"windows_process_observation">>,
          <<"status">> := <<"live">>,
          <<"machine_sha256">> := Machine,
          <<"boot_sha256">> := Boot,
          <<"start_sha256">> := Start} = Observation
          when map_size(Observation) =:= 6 ->
            true = execution_beam_digest(Machine, 64),
            true = execution_beam_digest(Boot, 64),
            true = execution_beam_digest(Start, 64),
            {ok, #{kind => <<"windows_machineguid_boot_time">>,
                   machine_sha256 => Machine, boot_sha256 => Boot},
                 {live, #{kind => <<"windows_process_start_ticks">>,
                          sha256 => Start}}};
        _ -> {error, owner_identity_observation_invalid}
    catch _:_ -> {error, owner_identity_observation_invalid}
    end.

execution_beam_windows_powershell() ->
    Root = case os:getenv("SystemRoot") of
        Value when is_list(Value), length(Value) > 0,
                   length(Value) =< 4096 -> Value;
        _ -> erlang:error(owner_identity_runtime_missing)
    end,
    true = filename:pathtype(Root) =:= absolute,
    false = lists:member(0, Root),
    Path = filename:join(
        [Root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"]),
    _ = execution_beam_regular_info(Path),
    filename:absname(Path).

%% Keep the exact system executable open across the owned capture.  NTFS
%% system binaries are legitimately hard-linked, so this guard deliberately
%% permits a stable positive link count while still rejecting linked parent
%% components and re-hashing the open handle after execution.
execution_beam_open_system_executable_guard(Path0) ->
    Path = filename:absname(Path0),
    Initial = execution_beam_regular_info(Path),
    Size = element(2, Initial),
    true = is_integer(Size) andalso Size > 0 andalso
           Size =< ?EXECUTION_BEAM_SYSTEM_EXECUTABLE_MAXIMUM,
    true = is_integer(element(9, Initial)) andalso element(9, Initial) > 0,
    {ok, Handle} = file:open(Path, [read, binary, raw]),
    try
        {ok, Opened} = file:read_file_info(Handle),
        true = element(3, Opened) =:= regular andalso
               element(9, Opened) > 0 andalso
               execution_beam_file_identity(Initial) =:=
                   execution_beam_file_identity(Opened),
        Captured = execution_beam_read_chunks(Handle, Size, []),
        {ok, Finished} = file:read_file_info(Handle),
        true = execution_beam_file_identity(Opened) =:=
               execution_beam_file_identity(Finished),
        true = byte_size(Captured) =:= Size,
        FinalPath = execution_beam_regular_info(Path),
        true = execution_beam_file_identity(Finished) =:=
               execution_beam_file_identity(FinalPath),
        #{path => Path, handle => Handle, size => Size,
          identity => execution_beam_file_identity(Finished),
          sha256 => execution_beam_sha256(Captured)}
    catch
        Class:Reason:Stack ->
            _ = file:close(Handle),
            erlang:raise(Class, Reason, Stack)
    end.

execution_beam_verify_system_executable_guard(Guard) ->
    Path = maps:get(path, Guard),
    Handle = maps:get(handle, Guard),
    Identity = maps:get(identity, Guard),
    Size = maps:get(size, Guard),
    {ok, Before} = file:read_file_info(Handle),
    true = execution_beam_file_identity(Before) =:= Identity,
    {ok, 0} = file:position(Handle, bof),
    Captured = execution_beam_read_chunks(Handle, Size, []),
    true = execution_beam_sha256(Captured) =:= maps:get(sha256, Guard),
    {ok, After} = file:read_file_info(Handle),
    true = execution_beam_file_identity(After) =:= Identity,
    Current = execution_beam_regular_info(Path),
    true = execution_beam_file_identity(Current) =:= Identity,
    ok.

execution_beam_close_system_executable_guard(Guard) ->
    case file:close(maps:get(handle, Guard)) of
        ok -> ok;
        {error, _} -> erlang:error(owner_identity_executable_close_failed)
    end.

execution_beam_macos_observation(_) ->
    {error, owner_identity_supervised_provider_required}.

execution_beam_host_identity(Kind, Machine, Boot) ->
    #{kind => Kind, machine_sha256 => execution_beam_sha256(Machine),
      boot_sha256 => execution_beam_sha256(Boot)}.

execution_beam_start_identity(Kind, Start) ->
    #{kind => Kind, sha256 => execution_beam_sha256(Start)}.

execution_beam_weak_host_identity() ->
    {ok, Hostname} = inet:gethostname(),
    Runtime = execution_beam_runtime_identity(),
    Machine = term_to_binary({Hostname, maps:get(os, Runtime),
                              maps:get(architecture, Runtime)},
                             [{minor_version, 2}]),
    execution_beam_host_identity(
        <<"unverified_runtime_host">>, Machine, <<"unavailable">>).

execution_beam_weak_start_identity() ->
    execution_beam_start_identity(<<"erlang_vm_start_time">>,
        integer_to_binary(erlang:system_info(start_time))).

execution_beam_system_file([], _) -> missing;
execution_beam_system_file([Path | Rest], Maximum) ->
    case file:read_file_info(Path) of
        {ok, Info} when element(3, Info) =:= regular,
                        element(2, Info) > 0,
                        element(2, Info) =< Maximum ->
            case file:read_file(Path) of
                {ok, Bytes} when byte_size(Bytes) =:= element(2, Info) ->
                    Trimmed = execution_beam_trim(Bytes),
                    case byte_size(Trimmed) > 0 of
                        true -> {ok, Trimmed};
                        false -> {error, empty}
                    end;
                _ -> {error, read_failed}
            end;
        {error, enoent} -> execution_beam_system_file(Rest, Maximum);
        _ -> {error, inspection_failed}
    end.

execution_beam_trim(Bytes) ->
    unicode:characters_to_binary(
        string:trim(unicode:characters_to_list(Bytes))).

execution_beam_decimal(Value) when is_binary(Value), byte_size(Value) > 0,
                                          byte_size(Value) =< 20 ->
    re:run(Value, <<"^[0-9]+$">>, [{capture, none}]) =:= match andalso
    binary_to_integer(Value) > 0;
execution_beam_decimal(_) -> false.

execution_beam_timestamp(Value) ->
    is_integer(Value) andalso Value >= 0 andalso Value =< 9999999999999.

execution_beam_finite_system_time() ->
    Value = erlang:system_time(millisecond),
    true = execution_beam_timestamp(Value),
    Value.

execution_beam_safe_code(Value) when is_binary(Value), byte_size(Value) > 0,
                                          byte_size(Value) =< 96 ->
    re:run(Value, <<"^[a-z0-9_/-]+$">>, [{capture, none}]) =:= match;
execution_beam_safe_code(_) -> false.

execution_beam_safe_text(Value) when is_binary(Value), byte_size(Value) > 0,
                                          byte_size(Value) =< 256 ->
    re:run(Value, <<"^[A-Za-z0-9_.+:/ -]+$">>, [{capture, none}]) =:= match;
execution_beam_safe_text(_) -> false.

execution_beam_sha256(Bytes) when is_binary(Bytes) ->
    binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).

execution_beam_equal_or_error(Expected, Actual, Error) ->
    case Expected =:= Actual of
        true -> ok;
        false -> erlang:error(Error)
    end.

execution_beam_read(Path, Maximum) ->
    evidence_publication_read(Path, Maximum).

execution_beam_read_chunks(Handle, Remaining, Acc) ->
    Request = erlang:min(Remaining + 1, 65536),
    case file:read(Handle, Request) of
        eof -> iolist_to_binary(lists:reverse(Acc));
        {ok, Chunk} when byte_size(Chunk) > 0,
                         byte_size(Chunk) =< Remaining ->
            execution_beam_read_chunks(Handle, Remaining - byte_size(Chunk),
                                       [Chunk | Acc]);
        _ -> erlang:error(execution_beam_file_changed)
    end.

execution_beam_regular_info(Path) ->
    execution_beam_components(filename:split(filename:absname(Path)), "", regular).

execution_beam_directory_info(Path) ->
    execution_beam_components(filename:split(filename:absname(Path)), "", directory).

execution_beam_components([], _, _) -> erlang:error(execution_beam_unsafe_path);
execution_beam_components([Name | Rest], Parent, FinalType) ->
    Current = case Parent of "" -> Name; _ -> filename:join(Parent, Name) end,
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            case Rest of
                [] when FinalType =:= directory -> Info;
                [] -> erlang:error(execution_beam_special_file_rejected);
                _ -> execution_beam_components(Rest, Current, FinalType)
            end;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= regular,
                        Rest =:= [], FinalType =:= regular -> Info;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            erlang:error(execution_beam_link_rejected);
        {ok, _} -> erlang:error(execution_beam_special_file_rejected);
        {error, enoent} -> erlang:error(execution_beam_missing);
        {error, _} -> erlang:error(execution_beam_inspection_failed)
    end.

execution_beam_file_identity(Info) ->
    {element(2, Info), element(3, Info), element(4, Info), element(6, Info),
     element(7, Info), element(8, Info), element(9, Info), element(10, Info),
     element(11, Info), element(12, Info)}.

execution_beam_relative(Root0, Path0) ->
    Root = filename:split(execution_beam_absolute(Root0)),
    Path = filename:split(execution_beam_absolute(Path0)),
    CompareRoot = [execution_beam_case_component(Part) || Part <- Root],
    ComparePath = [execution_beam_case_component(Part) || Part <- Path],
    true = lists:prefix(CompareRoot, ComparePath),
    Parts = lists:nthtail(length(Root), Path),
    true = Parts =/= [] andalso lists:all(fun(Part) ->
        Part =/= "" andalso Part =/= "." andalso Part =/= ".."
    end, Parts),
    string:join(Parts, "/").

execution_beam_absolute(Path) when is_binary(Path) ->
    filename:absname(unicode:characters_to_list(Path));
execution_beam_absolute(Path) when is_list(Path) -> filename:absname(Path).

execution_beam_case_component(Part) ->
    case os:type() of
        {win32, _} -> string:lowercase(Part);
        _ -> Part
    end.

execution_beam_module(Value) when is_binary(Value), byte_size(Value) > 0,
                                  byte_size(Value) =< 255 ->
    re:run(Value, <<"^[A-Za-z0-9_@]+$">>, [{capture, none}]) =:= match;
execution_beam_module(_) -> false.

execution_beam_relative_path(Value) when is_binary(Value),
                                         byte_size(Value) > 0,
                                         byte_size(Value) =< 4096 ->
    binary:match(Value, <<"\\">>) =:= nomatch andalso
    begin
        Parts = binary:split(Value, <<"/">>, [global]),
        Parts =/= [] andalso lists:all(fun(Part) ->
            Part =/= <<>> andalso Part =/= <<".">> andalso Part =/= <<"..">>
        end, Parts)
    end;
execution_beam_relative_path(_) -> false.

execution_beam_digest(Value, Bytes) when is_binary(Value),
                                         byte_size(Value) =:= Bytes ->
    re:run(Value, <<"^[0-9a-f]+$">>, [{capture, none}]) =:= match;
execution_beam_digest(_, _) -> false.

execution_beam_no_case_collisions(Values) ->
    Folded = [string:lowercase(Value) || Value <- Values],
    length(Folded) =:= length(lists:usort(Folded)).

execution_beam_no_binary_case_collisions(Values) ->
    execution_beam_no_case_collisions([
        unicode:characters_to_list(Value) || Value <- Values]).

execution_beam_path_absent(Path) ->
    case file:read_link_info(Path) of {error, enoent} -> true; _ -> false end.

-endif.
