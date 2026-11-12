%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_FRESH_BUILD_IDENTITY_HRL).
-define(HTTP_FRESH_BUILD_IDENTITY_HRL, true).
-compile({nowarn_unused_function, [
    {fresh_verify_many, 1},
    {fresh_verify, 1},
    {fresh_verified_report, 1},
    {fresh_verified_snapshot, 1},
    {fresh_with_verified_build, 2},
    {fresh_with_verified_builds, 2},
    {fresh_initial_inputs, 1},
    {fresh_initial_inputs, 2}
]}).

%% Shared verification of source, tests, generated Erlang, and loaded BEAMs.
-include("diagnostic_failure.hrl").
-include("file_identity.hrl").
-include("execution_identity.hrl").
-include("json_evidence.hrl").

fresh_verify_many(Targets) ->
    Snapshots = fresh_with_verified_builds(Targets,
        fun(Verified) -> Verified end),
    lists:foreach(fun(Snapshot) ->
        io:format("fresh-build manifest ~s ok~n",
                  [maps:get(target, Snapshot)])
    end, Snapshots),
    ok.

fresh_verify(Target) ->
    Snapshot = fresh_verified_snapshot(Target),
    io:format("fresh-build manifest ~s ok~n", [maps:get(target, Snapshot)]),
    ok.

fresh_verified_report(Target) ->
    maps:get(report, fresh_verified_snapshot(Target)).

fresh_verified_snapshot(Target) ->
    fresh_with_verified_build(Target, fun(Snapshot) -> Snapshot end).

fresh_with_verified_build(Target, Function) when is_function(Function, 1) ->
    fresh_with_verified_builds([Target], fun([Snapshot]) ->
        Function(Snapshot)
    end).

fresh_with_verified_builds(Targets, Function)
  when is_list(Targets), is_function(Function, 1) ->
    fresh_ensure(Targets =/= [] andalso
                 length(Targets) =:= length(lists:usort(Targets)),
                 invalid_fresh_verification_targets),
    _ = [fresh_packages(Target) || Target <- Targets],
    Ordered = lists:sort(Targets),
    Leases = fresh_acquire_verification_leases(Ordered, []),
    try
        ByTarget = maps:from_list([{Target, fresh_verify_locked(Target)}
                                   || Target <- Ordered]),
        Function([maps:get(Target, ByTarget) || Target <- Targets])
    after
        ok = fresh_release_verification_leases(lists:reverse(Leases))
    end.

fresh_acquire_verification_leases([], Acc) -> lists:reverse(Acc);
fresh_acquire_verification_leases([Target | Rest], Acc) ->
    Lease = try fresh_acquire_verification_lease(Target)
    catch
        Class:Reason:Stacktrace ->
            ok = fresh_release_verification_leases(Acc),
            erlang:raise(Class, Reason, Stacktrace)
    end,
    fresh_acquire_verification_leases(Rest, [Lease | Acc]).

fresh_release_verification_leases([]) -> ok;
fresh_release_verification_leases([Lease | Rest]) ->
    ok = fresh_release_verification_lease(Lease),
    fresh_release_verification_leases(Rest).

fresh_acquire_verification_lease(Target) ->
    fresh_acquire_verification_lease_at(fresh_lease_path(Target), Target).

fresh_acquire_verification_lease_at(Root, Target) ->
    Parent = filename:dirname(Root),
    ok = filelib:ensure_dir(filename:join(Parent, "placeholder")),
    _ = fresh_directory_info(Parent),
    case file:make_dir(Root) of
        ok -> ok;
        {error, eexist} ->
            erlang:error({active_build_or_verification_lease, Target});
        {error, _} -> erlang:error(fresh_verification_lease_failed)
    end,
    Token = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Owner = filename:join(Root, "verification.json"),
    Report = #{<<"schema">> => 1,
               <<"kind">> => <<"fresh_build_verification_lease">>,
               <<"target">> => list_to_binary(Target),
               <<"token">> => Token,
               <<"status">> => <<"Verifying">>},
    Bytes = iolist_to_binary([json:encode(Report), <<"\n">>]),
    {ok, Handle} = case file:open(Owner, [write, binary, raw, exclusive]) of
        {ok, Opened} -> {ok, Opened};
        {error, _} -> erlang:error(fresh_verification_lease_failed)
    end,
    try
        ok = file:write(Handle, Bytes),
        ok = file:sync(Handle)
    after
        ok = file:close(Handle)
    end,
    Bytes = fresh_read(Owner),
    _ = fresh_directory_info(Root),
    #{target => Target, root => Root, owner => Owner,
      token => Token, bytes => Bytes}.

fresh_release_verification_lease(Lease) ->
    Root = maps:get(root, Lease),
    Owner = maps:get(owner, Lease),
    Expected = maps:get(bytes, Lease),
    Expected = fresh_read(Owner),
    case file:list_dir(Root) of
        {ok, ["verification.json"]} -> ok;
        {ok, _} -> erlang:error(fresh_verification_lease_contaminated);
        {error, _} -> erlang:error(fresh_verification_lease_failed)
    end,
    case file:delete(Owner) of
        ok -> ok;
        {error, _} -> erlang:error(fresh_verification_lease_failed)
    end,
    case file:del_dir(Root) of
        ok -> ok;
        {error, _} -> erlang:error(fresh_verification_lease_failed)
    end,
    fresh_ensure(fresh_path_absent(Root),
                 fresh_verification_lease_failed),
    ok.

fresh_verify_locked(Target) ->
    Packages = fresh_packages(Target),
    Sources = fresh_source_paths(Packages),
    Artifacts = fresh_artifact_paths(Target, Packages),
    fresh_ensure_paths(Sources, missing_source),
    fresh_ensure_paths(Artifacts, missing_artifact),
    Path = fresh_manifest_path(Target),
    Bytes = fresh_read(Path),
    Report = evidence_json_decode(Bytes),
    fresh_ensure(lists:sort(maps:keys(Report)) =:= lists:sort([
        <<"schema">>, <<"package">>, <<"source_sha256">>,
        <<"source_files">>, <<"artifact_sha256">>, <<"artifact_files">>,
        <<"toolchain">>, <<"build_nonce">>, <<"prebuild_profile_state">>]),
        {invalid_manifest_fields, Path}),
    ExpectedPackage = unicode:characters_to_binary(Target),
    fresh_ensure(maps:get(<<"schema">>, Report, 0) =:= 3,
           {invalid_manifest_schema, Path}),
    fresh_ensure(maps:get(<<"package">>, Report, <<>>) =:= ExpectedPackage,
           {invalid_manifest_package, Path}),
    fresh_ensure(maps:get(<<"source_sha256">>, Report, <<>>) =:= fresh_digest(Sources),
           {stale_build_sources, Target}),
    fresh_ensure(maps:get(<<"artifact_sha256">>, Report, <<>>) =:=
               fresh_digest(Artifacts),
           {modified_build_artifacts, Target}),
    fresh_ensure(maps:get(<<"source_files">>, Report, -1) =:= length(Sources),
           {source_set_changed, Target}),
    fresh_ensure(maps:get(<<"artifact_files">>, Report, -1) =:= length(Artifacts),
           {artifact_set_changed, Target}),
    fresh_ensure(fresh_build_nonce_valid(maps:get(<<"build_nonce">>, Report, null)),
           {invalid_build_nonce, Target}),
    fresh_ensure(maps:get(<<"prebuild_profile_state">>, Report, null) =:=
               <<"absent">>,
           {unverified_prebuild_profile_state, Target}),
    Current = fresh_inputs(Target, Sources),
    InitialKeys = maps:keys(Current) ++
        [<<"build_nonce">>, <<"prebuild_profile_state">>],
    fresh_validate_initial(maps:with(InitialKeys, Report), Current),
    fresh_ensure(Sources =:= fresh_source_paths(Packages),
                 {source_set_changed, Target}),
    fresh_ensure(Artifacts =:= fresh_artifact_paths(Target, Packages),
                 {artifact_set_changed, Target}),
    #{target => Target, report => Report, bytes => Bytes,
      sha256 => binary:encode_hex(crypto:hash(sha256, Bytes), lowercase)}.

fresh_packages("core") -> [{"quic_core", "packages/quic_core"}];
fresh_packages("http3") -> [{"quic_core", "packages/quic_core"},
                       {"http3", "packages/http3"}];
fresh_packages("http") -> [{"quic_core", "packages/quic_core"},
                      {"http3", "packages/http3"}, {"http", "."}];
fresh_packages(Target) -> erlang:error({unknown_target, Target}).

fresh_source_paths(Packages) ->
    PackagePaths = lists:append([fresh_package_sources(Package) || Package <- Packages]),
    {_Name, TargetDirectory} = lists:last(Packages),
    Tests = fresh_tree_files(filename:join(TargetDirectory, "test"),
                             [".gleam", ".erl", ".hrl"]),
    lists:usort([".mise.toml", "scripts/fresh_build.sh",
                 "scripts/fresh_build_manifest.escript",
                 "scripts/diagnostic_failure.hrl",
                 "scripts/file_identity.hrl",
                 "scripts/execution_identity.hrl",
                 "scripts/json_evidence.hrl",
                 "scripts/fresh_build_identity.hrl" | PackagePaths ++ Tests]).

fresh_package_sources({_Name, Directory}) ->
    Configs = lists:append([fresh_optional_regular(filename:join(Directory, Name))
               || Name <- ["gleam.toml", "manifest.toml", "mix.exs", "mix.lock"]]),
    Sources = fresh_tree_files(filename:join(Directory, "src"),
                               [".gleam", ".erl", ".hrl"]),
    Configs ++ Sources.

fresh_artifact_paths(Target, Packages) ->
    Build = filename:join(fresh_target_directory(Target), "build/dev/erlang"),
    {Name, Directory} = lists:last(Packages),
    Tests = fresh_tree_artifacts(filename:join(Build, Name), filename:join(Directory, "test")),
    %% Bind every runtime dependency too, including unexpected or replaced
    %% BEAMs that could otherwise shadow a verified package on the code path.
    Runtime = fresh_tree_files(Build, [".beam", ".app"]),
    lists:usort(Runtime ++ Tests ++ lists:append([fresh_package_artifacts(Build, Package)
                                      || Package <- Packages])).

fresh_package_artifacts(Build, {Name, Directory}) ->
    SourceRoot = filename:join(Directory, "src"),
    PackageBuild = filename:join(Build, Name),
    [filename:join([PackageBuild, "ebin", Name ++ ".app"])
     | fresh_tree_artifacts(PackageBuild, SourceRoot)].

fresh_tree_artifacts(PackageBuild, SourceRoot) ->
    GleamSources = fresh_tree_files(SourceRoot, [".gleam"]),
    ErlangSources = fresh_tree_files(SourceRoot, [".erl"]),
    Generated = lists:append([fresh_gleam_artifacts(PackageBuild, SourceRoot, Path)
                              || Path <- GleamSources]),
    Native = [filename:join([PackageBuild, "ebin",
                             filename:basename(Path, ".erl") ++ ".beam"])
              || Path <- ErlangSources],
    Generated ++ Native.

fresh_optional_regular(Path) ->
    case file:read_link_info(Path) of
        {error, enoent} -> [];
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= regular ->
            _ = fresh_regular_info(Path),
            [Path];
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            fresh_input_error(file_link_rejected);
        {ok, _} -> fresh_input_error(file_special_file_rejected);
        {error, _} -> fresh_input_error(file_inspection_failed)
    end.

fresh_tree_files(Root0, Extensions) ->
    %% Preserve repository-relative names in the manifest while component
    %% validation below resolves each access to an absolute path.
    Root = Root0,
    {_Remaining, Files} = fresh_walk_tree(Root, Extensions, 0, 100000, []),
    lists:sort(Files).

fresh_walk_tree(Path, Extensions, Depth, Remaining, Acc) ->
    fresh_ensure(Depth =< 64, {fresh_input_rejected, tree_depth_limit}),
    Before = fresh_directory_info(Path),
    Names = case file:list_dir(Path) of
        {ok, Entries} -> lists:sort(Entries);
        {error, _} -> fresh_input_error(tree_read_failed)
    end,
    fresh_ensure(length(Names) =< Remaining,
                 {fresh_input_rejected, tree_entry_limit}),
    Result = lists:foldl(fun(Name, {Left, Paths}) ->
        fresh_ensure(Left > 0, {fresh_input_rejected, tree_entry_limit}),
        fresh_ensure(Name =/= "" andalso Name =/= "." andalso Name =/= "..",
                     {fresh_input_rejected, unsafe_path}),
        Member = filename:join(Path, Name),
        case file:read_link_info(Member) of
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= directory ->
                fresh_walk_tree(Member, Extensions, Depth + 1,
                                Left - 1, Paths);
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= regular ->
                case lists:member(filename:extension(Name), Extensions) of
                    true -> {Left - 1, [Member | Paths]};
                    false -> {Left - 1, Paths}
                end;
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= symlink ->
                fresh_input_error(tree_link_rejected);
            {ok, _} -> fresh_input_error(tree_special_file_rejected);
            {error, enoent} -> fresh_input_error(tree_changed_while_reading);
            {error, _} -> fresh_input_error(tree_inspection_failed)
        end
    end, {Remaining, Acc}, Names),
    After = fresh_directory_info(Path),
    fresh_ensure(fresh_file_identity(Before) =:= fresh_file_identity(After),
                 {fresh_input_rejected, tree_changed_while_reading}),
    Result.

fresh_gleam_artifacts(PackageBuild, SourceRoot, Path) ->
    Relative0 = fresh_relative_path(SourceRoot, Path),
    Relative = filename:rootname(Relative0, ".gleam"),
    Module = string:replace(Relative, "/", "@", all),
    [filename:join([PackageBuild, "_gleam_artefacts", Module ++ ".erl"]),
     filename:join([PackageBuild, "ebin", Module ++ ".beam"])].

fresh_relative_path(Root0, Path0) ->
    Root = filename:split(filename:absname(Root0)),
    Path = filename:split(filename:absname(Path0)),
    fresh_ensure(lists:prefix(Root, Path), path_outside_source_root),
    Parts = lists:nthtail(length(Root), Path),
    fresh_ensure(Parts =/= [] andalso
        lists:all(fun(Part) -> Part =/= "" andalso Part =/= "."
                                   andalso Part =/= ".." end, Parts),
        unsafe_relative_source_path),
    string:join(Parts, "/").

fresh_target_directory("core") -> "packages/quic_core";
fresh_target_directory("http3") -> "packages/http3";
fresh_target_directory("http") -> ".";
fresh_target_directory(Target) -> erlang:error({unknown_target, Target}).

fresh_manifest_path(Target) ->
    filename:join(fresh_target_directory(Target), "build/dev/fresh-build.json").

fresh_lease_path(Target) ->
    filename:join(fresh_target_directory(Target),
                  "build/fresh-build-lease").

fresh_path_absent(Path) ->
    case file:read_link_info(Path) of
        {error, enoent} -> true;
        _ -> false
    end.

fresh_ensure_paths(Paths, Kind) ->
    Missing = [Path || Path <- Paths,
        try _ = fresh_regular_info(Path), false
        catch error:{fresh_input_rejected, file_missing} -> true end],
    fresh_ensure(Missing =:= [], {Kind, Missing}).

fresh_digest(Paths) ->
    fresh_ensure(Paths =:= lists:usort(Paths),
                 {fresh_input_rejected, duplicate_path}),
    Folded = [fresh_portable_path_key(Path) || Path <- Paths],
    fresh_ensure(length(Folded) =:= length(lists:usort(Folded)),
                 {fresh_input_rejected, case_colliding_path}),
    file_identity_digest(Paths, fun fresh_read/1, lowercase).

fresh_read(Path) ->
    Initial = fresh_regular_info(Path),
    Size = element(2, Initial),
    fresh_ensure(is_integer(Size) andalso Size >= 0 andalso Size =< 134217728,
                 {fresh_input_rejected, file_size_rejected}),
    fresh_ensure(element(9, Initial) =:= 1,
                 {fresh_input_rejected, file_hardlink_rejected}),
    File = case file:open(Path, [read, binary, raw]) of
        {ok, Handle} -> Handle;
        {error, _} -> fresh_input_error(file_read_failed)
    end,
    {Bytes, Finished} = try
        Opened = case file:read_file_info(File) of
            {ok, Info} -> Info;
            {error, _} -> fresh_input_error(file_inspection_failed)
        end,
        fresh_ensure(element(3, Opened) =:= regular andalso
                     element(9, Opened) =:= 1 andalso
                     fresh_file_identity(Initial) =:= fresh_file_identity(Opened),
                     {fresh_input_rejected, file_changed_while_reading}),
        Captured = fresh_read_bounded(File, Size, []),
        FinalHandle = case file:read_file_info(File) of
            {ok, Info2} -> Info2;
            {error, _} -> fresh_input_error(file_inspection_failed)
        end,
        fresh_ensure(fresh_file_identity(Opened) =:=
                         fresh_file_identity(FinalHandle) andalso
                     byte_size(Captured) =:= Size,
                     {fresh_input_rejected, file_changed_while_reading}),
        {Captured, FinalHandle}
    after
        ok = file:close(File)
    end,
    FinalPath = fresh_regular_info(Path),
    fresh_ensure(fresh_file_identity(Finished) =:=
                     fresh_file_identity(FinalPath),
                 {fresh_input_rejected, file_changed_while_reading}),
    Bytes.

fresh_read_bounded(File, Remaining, Acc) when Remaining >= 0 ->
    Request = erlang:min(Remaining + 1, 65536),
    case file:read(File, Request) of
        eof -> iolist_to_binary(lists:reverse(Acc));
        {ok, Chunk} when byte_size(Chunk) > 0,
                         byte_size(Chunk) =< Remaining ->
            fresh_read_bounded(File, Remaining - byte_size(Chunk),
                               [Chunk | Acc]);
        {ok, _} -> fresh_input_error(file_changed_while_reading);
        {error, _} -> fresh_input_error(file_read_failed)
    end.

fresh_regular_info(Path) ->
    fresh_regular_components(filename:split(filename:absname(Path)), "").

fresh_regular_components([Name], Parent) ->
    Current = fresh_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= regular -> Info;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            fresh_input_error(file_link_rejected);
        {ok, _} -> fresh_input_error(file_special_file_rejected);
        {error, enoent} -> fresh_input_error(file_missing);
        {error, _} -> fresh_input_error(file_inspection_failed)
    end;
fresh_regular_components([Name | Rest], Parent) ->
    Current = fresh_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            fresh_regular_components(Rest, Current);
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            fresh_input_error(file_link_rejected);
        {ok, _} -> fresh_input_error(file_parent_rejected);
        {error, enoent} -> fresh_input_error(file_missing);
        {error, _} -> fresh_input_error(file_inspection_failed)
    end;
fresh_regular_components([], _) -> fresh_input_error(unsafe_path).

fresh_directory_info(Path) ->
    fresh_directory_components(filename:split(filename:absname(Path)), "").

fresh_directory_components([], _) -> fresh_input_error(unsafe_path);
fresh_directory_components([Name | Rest], Parent) ->
    Current = fresh_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            case Rest of
                [] -> Info;
                _ -> fresh_directory_components(Rest, Current)
            end;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            fresh_input_error(tree_link_rejected);
        {ok, _} -> fresh_input_error(tree_special_file_rejected);
        {error, enoent} -> fresh_input_error(tree_missing);
        {error, _} -> fresh_input_error(tree_inspection_failed)
    end.

fresh_join_component("", Name) -> Name;
fresh_join_component(Parent, Name) -> filename:join(Parent, Name).

fresh_file_identity(Info) ->
    %% Do not bind atime (element 5): verification itself can update it on
    %% Unix.  Keep the metadata which identifies replacement or mutation.
    {element(2, Info), element(3, Info), element(4, Info), element(6, Info),
     element(7, Info), element(8, Info), element(9, Info), element(10, Info),
     element(11, Info), element(12, Info)}.

fresh_normalized_path(Path) ->
    [case Character of $\\ -> $/; _ -> Character end || Character <- Path].

fresh_portable_path_key(Path) ->
    Normalized = unicode:characters_to_nfc_binary(fresh_normalized_path(Path)),
    unicode:characters_to_nfc_binary(string:casefold(Normalized)).

fresh_input_error(Reason) ->
    erlang:error({fresh_input_rejected, Reason}).

fresh_validate_initial(Initial, Current)
  when is_map(Initial), is_map(Current) ->
    ExpectedKeys = lists:sort(maps:keys(Current) ++
        [<<"build_nonce">>, <<"prebuild_profile_state">>]),
    fresh_ensure(lists:sort(maps:keys(Initial)) =:= ExpectedKeys,
                 unverified_build_inputs),
    fresh_ensure(maps:with(maps:keys(Current), Initial) =:= Current,
                 unverified_build_inputs),
    fresh_ensure(fresh_build_nonce_valid(
        maps:get(<<"build_nonce">>, Initial, null)), unverified_build_inputs),
    fresh_ensure(maps:get(<<"prebuild_profile_state">>, Initial, null) =:=
                 <<"absent">>, unverified_build_inputs),
    ok;
fresh_validate_initial(_, _) -> erlang:error(unverified_build_inputs).

fresh_inputs(Target, Sources) ->
    #{<<"schema">> => 3,
      <<"package">> => unicode:characters_to_binary(Target),
      <<"source_sha256">> => fresh_digest(Sources),
      <<"source_files">> => length(Sources),
      <<"toolchain">> => execution_build_tools()}.

fresh_initial_inputs(Current) ->
    fresh_initial_inputs(Current,
        binary:encode_hex(crypto:strong_rand_bytes(16), lowercase)).

fresh_initial_inputs(Current, Nonce) ->
    fresh_ensure(fresh_build_nonce_valid(Nonce), invalid_build_nonce),
    Current#{<<"build_nonce">> => Nonce,
        <<"prebuild_profile_state">> => <<"absent">>}.

fresh_build_nonce_valid(Value) ->
    is_binary(Value) andalso byte_size(Value) =:= 32 andalso
        re:run(Value, <<"^[0-9a-f]{32}$">>, [{capture, none}]) =:= match.

fresh_ensure(true, _) -> ok;
fresh_ensure(false, Error) -> erlang:error(Error).
-endif.
