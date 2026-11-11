#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("fresh_build_identity.hrl").

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "qualification failed: ~p~n", [diagnostic_failure_details(Class, Reason, Stacktrace)]),
            halt(1)
    end.

run(["--self-test"]) -> self_test();
run(["--input-self-test"]) -> fresh_input_boundary_self_test();
run(["reserve", Target]) -> reserve_build(Target);
run(["begin", Target, Token]) -> begin_build(Target, Token);
run(["write", Target, Token]) -> write(Target, Token);
run(["abort", Target, Token]) -> abort_build(Target, Token);
run(["verify", "all"]) -> fresh_verify_many(["core", "http3", "http"]);
run(["verify" | Targets]) when Targets =/= [] -> fresh_verify_many(Targets);
run(_) -> erlang:error({usage,
                        "--self-test | --input-self-test | reserve <target> | "
                        "begin|write|abort <target> <lease> | "
                        "verify <all|targets...>"}).

reserve_build(Target) ->
    _ = fresh_packages(Target),
    Token = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    ok = fresh_acquire_lease(Target, Token),
    io:put_chars([Token, <<"\n">>]).

begin_build(Target, Token0) ->
    Token = fresh_lease_token(Token0),
    ok = fresh_with_lease_operation(Target, Token, fun() ->
        begin_build_locked(Target, Token)
    end),
    io:format("fresh ~s build inputs captured before compilation~n", [Target]).

begin_build_locked(Target, Token) ->
    Packages = fresh_packages(Target),
    Path = fresh_initial_path(Target),
    Profile = filename:join(fresh_target_directory(Target), "build/dev"),
    _ = fresh_remove_tree(Profile, 0),
    invalidate(Path),
    invalidate(fresh_manifest_path(Target)),
    fresh_ensure(not filelib:is_dir(Profile), nonempty_build_profile),
    Sources = fresh_source_paths(Packages),
    fresh_ensure_paths(Sources, missing_source),
    Inputs = fresh_initial_inputs(fresh_inputs(Target, Sources), Token),
    fresh_ensure(Sources =:= fresh_source_paths(Packages),
                 source_set_changed_before_build),
    Bytes = iolist_to_binary([json:encode(Inputs), <<"\n">>]),
    ok = fresh_require_lease(Target, Token),
    ok = fresh_publish_new(Path, Bytes),
    ok = fresh_require_lease(Target, Token),
    ok.

invalidate(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_invalidate_prior_build)
    end.

fresh_initial_path(Target) ->
    filename:join(fresh_target_directory(Target), "build/fresh-build-inputs.json").

fresh_read_initial(Target) ->
    Path = fresh_initial_path(Target),
    case file:read_link_info(Path) of
        {ok, _} -> evidence_json_decode(fresh_read(Path));
        {error, enoent} -> none;
        {error, _} -> erlang:error(cannot_read_build_inputs)
    end.

write(Target, Token0) ->
    Token = fresh_lease_token(Token0),
    {SourceCount, ArtifactCount} = fresh_with_terminal_lease_operation(
        Target, Token, fun() -> write_locked(Target, Token) end),
    io:format("fresh ~s build: ~B sources -> ~B artifacts~n",
              [Target, SourceCount, ArtifactCount]),
    ok.

write_locked(Target, Token) ->
    Packages = fresh_packages(Target),
    Sources = fresh_source_paths(Packages),
    Artifacts = fresh_artifact_paths(Target, Packages),
    fresh_ensure_paths(Sources, missing_source),
    fresh_ensure_paths(Artifacts, missing_artifact),
    Current = fresh_inputs(Target, Sources),
    Initial = fresh_read_initial(Target),
    fresh_validate_initial(Initial, Current),
    fresh_ensure(maps:get(<<"build_nonce">>, Initial) =:= Token,
                 build_lease_nonce_mismatch),
    Report = Current#{<<"artifact_sha256">> => fresh_digest(Artifacts),
                      <<"artifact_files">> => length(Artifacts),
                      <<"build_nonce">> => maps:get(<<"build_nonce">>, Initial),
                      <<"prebuild_profile_state">> =>
                          maps:get(<<"prebuild_profile_state">>, Initial)},
    fresh_ensure(Current =:= fresh_inputs(
        Target, fresh_source_paths(Packages)), source_changed_during_build),
    fresh_ensure(Sources =:= fresh_source_paths(Packages),
                 source_set_changed_during_build),
    fresh_ensure(Artifacts =:= fresh_artifact_paths(Target, Packages),
                 artifact_set_changed_during_build),
    fresh_ensure(maps:get(<<"artifact_sha256">>, Report) =:=
                 fresh_digest(Artifacts), artifact_changed_during_build),
    ok = fresh_require_lease(Target, Token),
    Path = fresh_manifest_path(Target),
    Bytes = iolist_to_binary([json:encode(Report), <<"\n">>]),
    ok = fresh_publish_new(Path, Bytes),
    ok = file:delete(fresh_initial_path(Target)),
    {length(Sources), length(Artifacts)}.

abort_build(Target, Token0) ->
    Token = fresh_lease_token(Token0),
    fresh_with_terminal_lease_operation(Target, Token, fun() ->
        invalidate(fresh_initial_path(Target)),
        invalidate(fresh_manifest_path(Target)),
        ok
    end).

self_test() ->
    initial_inputs_self_test(),
    initial_json_self_test(),
    fresh_input_boundary_self_test(),
    Paths = fresh_source_paths(fresh_packages("http")),
    Test = filename:join([".", "test", "diagnostics_test.gleam"]),
    fresh_ensure(lists:member(Test, Paths), test_source_not_bound_to_build),
    Artifacts = fresh_artifact_paths("http", fresh_packages("http")),
    Beam = filename:join([".", "build", "dev", "erlang", "http", "ebin",
                           "diagnostics_test.beam"]),
    fresh_ensure(lists:member(Beam, Artifacts), test_artifact_not_bound_to_build),
    io:put_chars("fresh build source and test artifact identity tests passed\n").

fresh_input_boundary_self_test() ->
    Nonce = binary_to_list(binary:encode_hex(
        crypto:strong_rand_bytes(8), lowercase)),
    Directory = filename:absname(filename:join(
        "build", "fresh-input-controls-" ++ Nonce)),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    try
        Original = filename:join(Directory, "original.txt"),
        Alias = filename:join(Directory, "alias.txt"),
        ok = file:write_file(Original, <<"current input">>, [exclusive]),
        <<"current input">> = fresh_read(Original),
        {ok, IdentityInfo} = file:read_link_info(Original),
        Identity = fresh_file_identity(IdentityInfo),
        Identity = fresh_file_identity(
            setelement(5, IdentityInfo, changed_atime)),
        false = Identity =:= fresh_file_identity(
            setelement(6, IdentityInfo, changed_mtime)),
        fresh_publication_self_test(Directory),
        fresh_lease_self_test(Directory),
        fresh_verification_lease_self_test(Directory),
        HardlinkState = case file:make_link(Original, Alias) of
            ok ->
                true = fresh_input_rejected(fun() -> fresh_read(Original) end,
                                            file_hardlink_rejected),
                <<"verified">>;
            {error, _} -> <<"unavailable">>
        end,
        Source = filename:join(Directory, "source"),
        Target = filename:join(Directory, "target"),
        ok = filelib:ensure_dir(filename:join(Source, "placeholder")),
        ok = filelib:ensure_dir(filename:join(Target, "placeholder")),
        Stable = filename:join(Source, "stable.gleam"),
        ok = file:write_file(Stable, <<"pub fn stable() { Nil }\n">>,
                             [exclusive]),
        [Stable] = fresh_tree_files(Source, [".gleam"]),
        ok = file:write_file(filename:join(Target, "linked.gleam"),
                             <<"pub fn linked() { Nil }\n">>, [exclusive]),
        Link = filename:join(Source, "linked"),
        SymlinkState = case file:make_symlink(Target, Link) of
            ok ->
                true = fresh_input_rejected(fun() ->
                    fresh_tree_files(Source, [".gleam"])
                end, tree_link_rejected),
                <<"verified">>;
            {error, _} -> <<"unavailable">>
        end,
        true = fresh_portable_path_key("archive/" ++ [16#00E9]) =:=
            fresh_portable_path_key("archive/e" ++ [16#0301]),
        true = fresh_portable_path_key("archive/" ++ [16#00DF]) =:=
            fresh_portable_path_key("ARCHIVE/SS"),
        io:format("fresh_input hardlink=~s symlink=~s "
                  "identity_before_after=verified atime_stable=verified "
                  "publication=verified build_lease=verified "
                  "verification_lease=verified terminal_race=verified "
                  "unicode_collision=verified~n",
                  [HardlinkState, SymlinkState])
    after
        _ = fresh_remove_tree(Directory, 0)
    end.

fresh_input_rejected(Function, Expected) ->
    try Function(), false
    catch error:{fresh_input_rejected, Expected} -> true end.

fresh_publication_self_test(Directory) ->
    Path = filename:join(Directory, "atomic.json"),
    First = <<"{\"status\":\"first\"}\n">>,
    Second = <<"{\"status\":\"second\"}\n">>,
    ok = fresh_publish_new(Path, First),
    First = fresh_read(Path),
    true = try fresh_publish_new(Path, Second), false
           catch error:fresh_publication_conflict -> true end,
    First = fresh_read(Path),
    [] = filelib:wildcard(Path ++ ".pending-*"),
    ok.

fresh_lease_self_test(Directory) ->
    Path = filename:join(Directory, "lease.json"),
    First = binary:copy(<<"1">>, 32),
    Second = binary:copy(<<"2">>, 32),
    ok = fresh_acquire_lease_at(Path, "http", First),
    ok = fresh_require_lease_at(Path, "http", First),
    true = try fresh_acquire_lease_at(Path, "http", Second), false
           catch error:fresh_lease_conflict -> true end,
    true = try fresh_require_lease_at(Path, "http", Second), false
           catch error:invalid_build_lease -> true end,
    Operation = fresh_acquire_lease_operation_at(Path, "http", First),
    true = try fresh_acquire_lease_operation_at(Path, "http", First), false
           catch error:fresh_lease_operation_busy -> true end,
    ok = fresh_release_lease_operation(Operation),
    ok = fresh_release_lease_at(Path, "http", First),
    true = fresh_path_absent(Path),
    ok = fresh_acquire_lease_at(Path, "http", Second),
    true = try fresh_release_lease_at(Path, "http", First), false
           catch error:invalid_build_lease -> true end,
    ok = fresh_require_lease_at(Path, "http", Second),
    ok = fresh_release_lease_at(Path, "http", Second),
    true = fresh_path_absent(Path),
    fresh_lease_concurrency_self_test(Directory),
    fresh_lease_failed_commit_self_test(Directory),
    ok.

fresh_lease_concurrency_self_test(Directory) ->
    Path = filename:join(Directory, "concurrent-lease"),
    Marker = filename:join(Directory, "concurrent-commit.json"),
    Token = binary:copy(<<"3">>, 32),
    ok = fresh_acquire_lease_at(Path, "http", Token),
    Parent = self(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Result = try fresh_with_terminal_lease_operation_at(
            Path, "http", Token, fun() ->
                ok = fresh_publish_new(Marker, <<"committed\n">>),
                Parent ! {fresh_lease_operation_held, self()},
                receive
                    {fresh_lease_continue, Parent} -> ok
                after 5000 -> erlang:error(concurrency_sync_timeout)
                end
            end) of
            ok -> ok
        catch _:_ -> failed
        end,
        Parent ! {fresh_lease_worker_done, self(), Result}
    end),
    receive
        {fresh_lease_operation_held, Worker} -> ok;
        {'DOWN', Monitor, process, Worker, _} ->
            erlang:error(concurrency_worker_failed)
    after 5000 -> erlang:error(concurrency_sync_timeout)
    end,
    LoserRejected = try fresh_with_terminal_lease_operation_at(
        Path, "http", Token, fun() ->
            Parent ! fresh_lease_loser_ran,
            ok
        end), false
    catch error:fresh_lease_operation_busy -> true end,
    fresh_ensure(LoserRejected, concurrent_terminal_operation_accepted),
    fresh_ensure(receive fresh_lease_loser_ran -> false after 0 -> true end,
                 concurrent_loser_executed),
    Worker ! {fresh_lease_continue, Parent},
    receive
        {fresh_lease_worker_done, Worker, ok} -> ok;
        {fresh_lease_worker_done, Worker, failed} ->
            erlang:error(concurrency_worker_failed)
    after 5000 -> erlang:error(concurrency_sync_timeout)
    end,
    receive
        {'DOWN', Monitor, process, Worker, normal} -> ok;
        {'DOWN', Monitor, process, Worker, _} ->
            erlang:error(concurrency_worker_failed)
    after 5000 -> erlang:error(concurrency_sync_timeout)
    end,
    <<"committed\n">> = fresh_read(Marker),
    true = fresh_path_absent(Path),
    ok = file:delete(Marker),
    ok.

fresh_lease_failed_commit_self_test(Directory) ->
    Path = filename:join(Directory, "failed-commit-lease"),
    Marker = filename:join(Directory, "failed-commit.json"),
    Token = binary:copy(<<"4">>, 32),
    ok = fresh_acquire_lease_at(Path, "http", Token),
    Rejected = try fresh_with_terminal_lease_operation_at(
        Path, "http", Token, fun() ->
            ok = fresh_publish_new(Marker, <<"uncommitted\n">>),
            erlang:error(intentional_commit_failure)
        end), false
    catch error:intentional_commit_failure -> true end,
    fresh_ensure(Rejected, failed_commit_accepted),
    false = fresh_path_absent(Path),
    ok = fresh_require_lease_at(Path, "http", Token),
    <<"uncommitted\n">> = fresh_read(Marker),
    ok = fresh_release_lease_at(Path, "http", Token),
    true = fresh_path_absent(Path),
    ok = file:delete(Marker),
    ok.

fresh_verification_lease_self_test(Directory) ->
    Path = filename:join(Directory, "verification-lease"),
    BuildToken = binary:copy(<<"5">>, 32),
    Verification = fresh_acquire_verification_lease_at(Path, "http"),
    true = try fresh_acquire_lease_at(Path, "http", BuildToken), false
           catch error:fresh_lease_conflict -> true end,
    Extra = filename:join(Path, "unexpected"),
    ok = file:write_file(Extra, <<"contaminated">>, [exclusive]),
    true = try fresh_release_verification_lease(Verification), false
           catch error:fresh_verification_lease_contaminated -> true end,
    false = fresh_path_absent(Path),
    ok = file:delete(Extra),
    ok = fresh_release_verification_lease(Verification),
    true = fresh_path_absent(Path),
    ok = fresh_acquire_lease_at(Path, "http", BuildToken),
    true = try fresh_acquire_verification_lease_at(Path, "http"), false
           catch error:{active_build_or_verification_lease, "http"} -> true end,
    ok = fresh_release_lease_at(Path, "http", BuildToken),
    true = fresh_path_absent(Path),
    ok.

fresh_acquire_lease(Target, Token) ->
    fresh_acquire_lease_at(fresh_lease_path(Target), Target, Token).

fresh_acquire_lease_at(Path, Target, Token) ->
    Report = fresh_lease_report(Target, Token),
    Parent = filename:dirname(Path),
    ok = filelib:ensure_dir(filename:join(Parent, "placeholder")),
    _ = fresh_directory_info(Parent),
    case file:make_dir(Path) of
        ok -> ok;
        {error, eexist} -> erlang:error(fresh_lease_conflict);
        {error, _} -> erlang:error(fresh_lease_acquire_failed)
    end,
    _ = fresh_directory_info(Path),
    ok = fresh_publish_new(fresh_lease_owner_path(Path),
        iolist_to_binary([json:encode(Report), <<"\n">>])),
    fresh_require_lease_at(Path, Target, Token).

fresh_require_lease(Target, Token) ->
    fresh_require_lease_at(fresh_lease_path(Target), Target, Token).

fresh_require_lease_at(Path, Target, Token) ->
    Initial = try fresh_directory_info(Path)
              catch _:_ -> erlang:error(invalid_build_lease) end,
    Report = try evidence_json_decode(fresh_read(fresh_lease_owner_path(Path)))
             catch _:_ -> erlang:error(invalid_build_lease) end,
    Expected = fresh_lease_report(Target, Token),
    fresh_ensure(Report =:= Expected, invalid_build_lease),
    Final = try fresh_directory_info(Path)
            catch _:_ -> erlang:error(invalid_build_lease) end,
    fresh_ensure(fresh_file_identity(Initial) =:= fresh_file_identity(Final),
                 invalid_build_lease),
    ok.

fresh_release_lease_at(Path, Target, Token) ->
    fresh_with_terminal_lease_operation_at(Path, Target, Token, fun() -> ok end).

fresh_with_lease_operation(Target, Token, Function) ->
    fresh_with_lease_operation_at(
        fresh_lease_path(Target), Target, Token, Function).

fresh_with_lease_operation_at(Path, Target, Token, Function) ->
    Operation = fresh_acquire_lease_operation_at(Path, Target, Token),
    try
        Result = Function(),
        ok = fresh_require_lease_at(Path, Target, Token),
        Result
    after
        ok = fresh_release_lease_operation_if_present(Operation)
    end.

fresh_with_terminal_lease_operation(Target, Token, Function) ->
    fresh_with_terminal_lease_operation_at(
        fresh_lease_path(Target), Target, Token, Function).

fresh_with_terminal_lease_operation_at(Path, Target, Token, Function) ->
    Operation = fresh_acquire_lease_operation_at(Path, Target, Token),
    try
        Result = Function(),
        ok = fresh_require_lease_at(Path, Target, Token),
        ok = fresh_retire_lease_owner_at(Path, Target, Token),
        ok = fresh_release_lease_operation(Operation),
        ok = fresh_release_lease_root(Path),
        Result
    after
        ok = fresh_release_lease_operation_if_present(Operation)
    end.

fresh_acquire_lease_operation_at(Path, Target, Token) ->
    ok = fresh_require_lease_at(Path, Target, Token),
    Operation = fresh_lease_operation_path(Path, Token),
    case file:make_dir(Operation) of
        ok -> ok;
        {error, eexist} -> erlang:error(fresh_lease_operation_busy);
        {error, _} -> erlang:error(fresh_lease_operation_failed)
    end,
    try
        _ = fresh_directory_info(Operation),
        ok = fresh_require_lease_at(Path, Target, Token),
        Operation
    catch
        Class:Reason:Stacktrace ->
            ok = fresh_release_lease_operation_if_present(Operation),
            erlang:raise(Class, Reason, Stacktrace)
    end.

fresh_retire_lease_owner_at(Path, Target, Token) ->
    ok = fresh_require_lease_at(Path, Target, Token),
    Owner = fresh_lease_owner_path(Path),
    case file:delete(Owner) of
        ok -> ok;
        {error, _} -> erlang:error(cannot_release_build_lease)
    end,
    fresh_ensure(fresh_path_absent(Owner), cannot_release_build_lease),
    ok.

fresh_release_lease_operation(Operation) ->
    case file:read_link_info(Operation) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            case file:del_dir(Operation) of
                ok -> ok;
                {error, _} -> erlang:error(cannot_release_build_operation)
            end;
        {error, enoent} -> erlang:error(missing_build_operation);
        {ok, _} -> erlang:error(invalid_build_operation);
        {error, _} -> erlang:error(cannot_release_build_operation)
    end,
    fresh_ensure(fresh_path_absent(Operation),
                 cannot_release_build_operation),
    ok.

fresh_release_lease_operation_if_present(Operation) ->
    case file:read_link_info(Operation) of
        {error, enoent} -> ok;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            case file:del_dir(Operation) of
                ok -> ok;
                {error, _} -> erlang:error(cannot_release_build_operation)
            end;
        {ok, _} -> erlang:error(invalid_build_operation);
        {error, _} -> erlang:error(cannot_release_build_operation)
    end.

fresh_release_lease_root(Path) ->
    _ = fresh_directory_info(Path),
    case file:list_dir(Path) of
        {ok, []} -> ok;
        {ok, _} -> erlang:error(cannot_release_build_lease);
        {error, _} -> erlang:error(cannot_release_build_lease)
    end,
    case file:del_dir(Path) of
        ok -> ok;
        {error, _} -> erlang:error(cannot_release_build_lease)
    end,
    fresh_ensure(fresh_path_absent(Path), cannot_release_build_lease),
    ok.

fresh_lease_owner_path(Path) -> filename:join(Path, "owner.json").

fresh_lease_operation_path(Path, Token) ->
    fresh_ensure(fresh_build_nonce_valid(Token), invalid_build_lease),
    filename:join(Path, "operation-" ++ binary_to_list(Token)).

fresh_lease_report(Target, Token) ->
    _ = fresh_packages(Target),
    fresh_ensure(fresh_build_nonce_valid(Token), invalid_build_lease),
    #{<<"schema">> => 1, <<"kind">> => <<"fresh_build_lease">>,
      <<"target">> => list_to_binary(Target), <<"token">> => Token,
      <<"status">> => <<"Running">>}.

fresh_lease_token(Token) when is_list(Token) ->
    Binary = unicode:characters_to_binary(Token),
    fresh_ensure(fresh_build_nonce_valid(Binary), invalid_build_lease),
    Binary;
fresh_lease_token(_) -> erlang:error(invalid_build_lease).

fresh_publish_new(Path, Bytes) when is_binary(Bytes) ->
    fresh_ensure(byte_size(Bytes) > 0 andalso byte_size(Bytes) =< 1048576,
                 fresh_publication_size_rejected),
    ok = filelib:ensure_dir(Path),
    fresh_ensure(fresh_path_absent(Path), fresh_publication_conflict),
    Temporary = Path ++ ".pending-" ++ binary_to_list(
        binary:encode_hex(crypto:strong_rand_bytes(16), lowercase)),
    try
        {ok, Handle} = file:open(Temporary, [write, binary, raw, exclusive]),
        try
            ok = file:write(Handle, Bytes),
            ok = file:sync(Handle)
        after
            ok = file:close(Handle)
        end,
        case file:make_link(Temporary, Path) of
            ok -> ok;
            {error, eexist} -> erlang:error(fresh_publication_conflict);
            {error, _} -> erlang:error(fresh_publication_failed)
        end,
        ok = file:delete(Temporary),
        Bytes = fresh_read(Path),
        ok
    after
        case file:delete(Temporary) of
            ok -> ok;
            {error, enoent} -> ok;
            {error, _} -> ok
        end
    end.

fresh_remove_tree(Path, Count) when Count =< 100000 ->
    case file:read_link_info(Path) of
        {error, enoent} -> Count;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            {ok, Names} = file:list_dir(Path),
            Next = lists:foldl(fun(Name, Acc) ->
                fresh_remove_tree(filename:join(Path, Name), Acc)
            end, Count + 1, Names),
            ok = file:del_dir(Path),
            Next;
        {ok, _} ->
            ok = file:delete(Path),
            Count + 1;
        {error, _} -> erlang:error(fresh_input_cleanup_failed)
    end;
fresh_remove_tree(_, _) -> erlang:error(fresh_input_cleanup_limit).

initial_inputs_self_test() ->
    Current = #{<<"schema">> => 3, <<"package">> => <<"http">>,
        <<"source_sha256">> => <<"current">>, <<"source_files">> => 2,
        <<"toolchain">> => #{<<"observed">> => <<"current-tool">>}},
    Initial = fresh_initial_inputs(Current),
    MissingRejected = initial_rejected(none, Current),
    ChangedRejected = initial_rejected(
        Initial#{<<"source_sha256">> => <<"old">>}, Current),
    ToolRejected = initial_rejected(Initial#{<<"toolchain">> => #{}}, Current),
    io:format("build_inputs missing_rejected=~p changed_rejected=~p tool_changed_rejected=~p~n",
              [MissingRejected, ChangedRejected, ToolRejected]),
    fresh_ensure(MissingRejected andalso ChangedRejected andalso ToolRejected,
                 invalid_build_inputs_accepted),
    ok = fresh_validate_initial(Initial, Current),
    fresh_ensure(not initial_rejected(Initial, Current),
                 valid_build_inputs_rejected),
    fresh_ensure(initial_rejected(
        Initial#{<<"prebuild_profile_state">> => <<"present">>}, Current),
        present_prebuild_profile_accepted),
    fresh_ensure(initial_rejected(
        Initial#{<<"build_nonce">> => <<"invalid">>}, Current),
        invalid_build_nonce_accepted).

initial_json_self_test() ->
    Current = #{<<"schema">> => 3, <<"package">> => <<"http">>,
        <<"source_sha256">> => <<"current">>, <<"source_files">> => 2,
        <<"toolchain">> => #{<<"observed">> => <<"current-tool">>}},
    Initial = fresh_initial_inputs(Current),
    Directory = filename:absname("build/fresh-json-controls"),
    Path = filename:join(Directory, "build/fresh-build-inputs.json"),
    ok = filelib:ensure_dir(Path),
    {ok, Previous} = file:get_cwd(),
    try
        ok = file:set_cwd(Directory),
        ok = file:write_file(Path, iolist_to_binary(json:encode(Initial))),
        ok = fresh_validate_initial(fresh_read_initial("http"), Current),
        InitialBytes = iolist_to_binary(json:encode(Initial)),
        InitialSize = byte_size(InitialBytes),
        <<InitialBeforeEnd:(InitialSize-1)/binary, $}>> = InitialBytes,
        Rejected = [begin
            ok = file:write_file(Path, Invalid),
            try fresh_validate_initial(fresh_read_initial("http"), Current), false
            catch error:_ -> true end
        end || Invalid <- [
            <<InitialBeforeEnd/binary, ",\"source_sha256\":\"stale\"}">>,
            <<InitialBeforeEnd/binary, ",\"source_\\u0073ha256\":\"stale\"}">>
        ]],
        All = lists:all(fun(Value) -> Value end, Rejected),
        io:format("build_inputs duplicate_keys_rejected=~p~n", [All]),
        fresh_ensure(All, duplicate_build_inputs_accepted)
    after
        ok = file:set_cwd(Previous),
        ok = file:delete(Path)
    end.

initial_rejected(Initial, Current) ->
    try fresh_validate_initial(Initial, Current), false
    catch error:unverified_build_inputs -> true end.
