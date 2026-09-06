#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error,
                      "fresh-build manifest failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run(["write", Target]) -> write(Target);
run(["verify", "all"]) -> verify_many(["core", "http3", "http"]);
run(["verify" | Targets]) when Targets =/= [] -> verify_many(Targets);
run(_) -> erlang:error({usage,
                        "write <http|http3|core> | verify <all|targets...>"}).

write(Target) ->
    Packages = packages(Target),
    Sources = source_paths(Packages),
    Artifacts = artifact_paths(Target, Packages),
    ensure_paths(Sources, missing_source),
    ensure_paths(Artifacts, missing_artifact),
    Report = #{schema => 1,
               package => unicode:characters_to_binary(Target),
               source_sha256 => digest(Sources),
               artifact_sha256 => digest(Artifacts),
               source_files => length(Sources),
               artifact_files => length(Artifacts)},
    Path = manifest_path(Target),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Report), <<"\n">>]),
    io:format("fresh ~s build: ~B sources -> ~B artifacts~n",
              [Target, length(Sources), length(Artifacts)]),
    ok.

verify_many(Targets) ->
    lists:foreach(fun verify/1, Targets),
    ok.

verify(Target) ->
    Packages = packages(Target),
    Sources = source_paths(Packages),
    Artifacts = artifact_paths(Target, Packages),
    ensure_paths(Sources, missing_source),
    ensure_paths(Artifacts, missing_artifact),
    Path = manifest_path(Target),
    Report = json:decode(read(Path)),
    ExpectedPackage = unicode:characters_to_binary(Target),
    ensure(maps:get(<<"schema">>, Report, 0) =:= 1,
           {invalid_manifest_schema, Path}),
    ensure(maps:get(<<"package">>, Report, <<>>) =:= ExpectedPackage,
           {invalid_manifest_package, Path}),
    ensure(maps:get(<<"source_sha256">>, Report, <<>>) =:= digest(Sources),
           {stale_build_sources, Target}),
    ensure(maps:get(<<"artifact_sha256">>, Report, <<>>) =:=
               digest(Artifacts),
           {modified_build_artifacts, Target}),
    ensure(maps:get(<<"source_files">>, Report, -1) =:= length(Sources),
           {source_set_changed, Target}),
    ensure(maps:get(<<"artifact_files">>, Report, -1) =:= length(Artifacts),
           {artifact_set_changed, Target}),
    io:format("fresh-build manifest ~s ok~n", [Target]),
    ok.

packages("core") -> [{"quic_core", "packages/quic_core"}];
packages("http3") -> [{"quic_core", "packages/quic_core"},
                       {"http3", "packages/http3"}];
packages("http") -> [{"quic_core", "packages/quic_core"},
                      {"http3", "packages/http3"}, {"http", "."}];
packages(Target) -> erlang:error({unknown_target, Target}).

source_paths(Packages) ->
    PackagePaths = lists:append([package_sources(Package) || Package <- Packages]),
    lists:usort([".mise.toml", "scripts/fresh_build.sh",
                 "scripts/fresh_build_manifest.escript" | PackagePaths]).

package_sources({_Name, Directory}) ->
    Configs = [filename:join(Directory, Name)
               || Name <- ["gleam.toml", "manifest.toml", "mix.exs", "mix.lock"],
                  filelib:is_regular(filename:join(Directory, Name))],
    Sources = filelib:fold_files(filename:join(Directory, "src"),
                                 ".*\\.(gleam|erl|hrl)$", true,
                                 fun(Path, Acc) -> [Path | Acc] end, []),
    Configs ++ Sources.

artifact_paths(Target, Packages) ->
    Build = filename:join(target_directory(Target), "build/dev/erlang"),
    lists:usort(lists:append([package_artifacts(Build, Package)
                             || Package <- Packages])).

package_artifacts(Build, {Name, Directory}) ->
    SourceRoot = filename:join(Directory, "src"),
    GleamSources = filelib:fold_files(SourceRoot, ".*\\.gleam$", true,
                                      fun(Path, Acc) -> [Path | Acc] end, []),
    ErlangSources = filelib:fold_files(SourceRoot, ".*\\.erl$", true,
                                       fun(Path, Acc) -> [Path | Acc] end, []),
    PackageBuild = filename:join(Build, Name),
    Generated = lists:append([gleam_artifacts(PackageBuild, SourceRoot, Path)
                              || Path <- GleamSources]),
    Native = [filename:join([PackageBuild, "ebin",
                             filename:basename(Path, ".erl") ++ ".beam"])
              || Path <- ErlangSources],
    [filename:join([PackageBuild, "ebin", Name ++ ".app"])
     | Generated ++ Native].

gleam_artifacts(PackageBuild, SourceRoot, Path) ->
    Relative0 = relative_path(SourceRoot, Path),
    Relative = filename:rootname(Relative0, ".gleam"),
    Module = string:replace(Relative, "/", "@", all),
    [filename:join([PackageBuild, "_gleam_artefacts", Module ++ ".erl"]),
     filename:join([PackageBuild, "ebin", Module ++ ".beam"])].

relative_path(Root0, Path0) ->
    Root = filename:absname(Root0),
    Path = filename:absname(Path0),
    Prefix = Root ++ "/",
    ensure(lists:prefix(Prefix, Path), {path_outside_source_root, Path}),
    lists:nthtail(length(Prefix), Path).

target_directory("core") -> "packages/quic_core";
target_directory("http3") -> "packages/http3";
target_directory("http") -> ".";
target_directory(Target) -> erlang:error({unknown_target, Target}).

manifest_path(Target) ->
    filename:join(target_directory(Target), "build/dev/fresh-build.json").

ensure_paths(Paths, Kind) ->
    Missing = [Path || Path <- Paths, not filelib:is_regular(Path)],
    ensure(Missing =:= [], {Kind, Missing}).

digest(Paths) ->
    Bytes = [[unicode:characters_to_binary(Path), 0, read(Path), 0]
             || Path <- lists:sort(Paths)],
    binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({read_failed, Path, Reason})
    end.

ensure(true, _) -> ok;
ensure(false, Error) -> erlang:error(Error).
