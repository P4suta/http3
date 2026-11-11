#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-compile(nowarn_unused_function).

main(Arguments) ->
    try run(Arguments)
    catch Class:Reason:Stack ->
        io:format(standard_error, "evidence identity failed: ~p~n",
                  [diagnostic_failure_details(Class, Reason, Stack)]),
        halt(1)
    end.

run(["--self-test"]) -> self_test();
run(["--toolchain"]) ->
    io:put_chars([json:encode(execution_build_tools()), <<"\n">>]);
run(_) -> halt(1).

self_test() ->
    Paths = evidence_source_paths(),
    Required = [".semgrep.yml", ".osv-scanner.toml", ".gitleaksignore", ".markdownlint-cli2.yaml",
        "packages/http3/mix.exs", "packages/http3/mix.lock", "packages/quic_core/mix.exs",
        "packages/http3/benchmarks/README.md", "SUPPORT.md"],
    Missing = length([P || P <- Required, not lists:member(P, Paths)]),
    io:format("source_catalog missing_verification_inputs=~B~n", [Missing]),
    fresh_ensure(Missing =:= 0, unbound_verification_configuration),
    Identity = evidence_identity(),
    Identity = evidence_identity(),
    2 = maps:get(<<"schema">>, Identity),
    PathCount = length(Paths),
    PathCount = maps:get(<<"files">>, Identity),
    64 = byte_size(maps:get(<<"source_sha256">>, Identity)),
    true = evidence_portable_path_key("archive/" ++ [16#00E9]) =:=
        evidence_portable_path_key("archive/e" ++ [16#0301]),
    true = evidence_portable_path_key("archive/" ++ [16#00DF]) =:=
        evidence_portable_path_key("ARCHIVE/SS"),
    io:format("source_identity files=~B repeatable=true~n", [PathCount]),
    Directory = filename:join("build/evidence-identity-self-test",
        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(12)))),
    Left = filename:join(Directory, "left"),
    Right = filename:join(Directory, "right"),
    ok = filelib:ensure_dir(Left),
    try
        SourceBoundary = <<(unicode:characters_to_binary(Right))/binary, 0>>,
        SourceDifferent = separate_contents(fun evidence_digest_files/1, Left, Right,
                                            SourceBoundary),
        BuildBoundary = <<0, SourceBoundary/binary>>,
        BuildDifferent = separate_contents(fun fresh_digest/1, Left, Right,
                                           BuildBoundary),
        {HardlinkState, SymlinkState} = identity_boundary_self_test(
            Directory, Left),
        io:format("redistributed_content source_distinct=~p build_distinct=~p~n",
                  [SourceDifferent, BuildDifferent]),
        fresh_ensure(SourceDifferent andalso BuildDifferent, ambiguous_content_boundary),
        io:format("source identity hardlink=~s symlink=~s "
                  "atime_stable=verified bounded_read=verified~n",
                  [HardlinkState, SymlinkState]),
        io:put_chars("source and build boundaries reject content redistribution\n")
    after
        _ = identity_remove_tree(Directory, 0)
    end.

identity_boundary_self_test(Directory, Left) ->
    {ok, Info} = file:read_link_info(Left),
    Identity = evidence_file_identity(Info),
    Identity = evidence_file_identity(setelement(5, Info, changed_atime)),
    false = Identity =:= evidence_file_identity(
        setelement(6, Info, changed_mtime)),
    LeftContents = evidence_read_source(Left),
    LeftContents = evidence_read_source(Left),
    Alias = filename:join(Directory, "hardlink-alias"),
    HardlinkState = case file:make_link(Left, Alias) of
        ok ->
            true = try evidence_read_source(Left), false
                   catch error:source_hardlink_rejected -> true end,
            ok = file:delete(Alias),
            <<"verified">>;
        {error, _} -> <<"unavailable">>
    end,
    Target = filename:join(Directory, "symlink-target"),
    Link = filename:join(Directory, "symlink-alias"),
    ok = file:write_file(Target, <<"target">>, [exclusive]),
    SymlinkState = case file:make_symlink(Target, Link) of
        ok ->
            true = try evidence_tree_files(Directory), false
                   catch error:source_tree_link_rejected -> true end,
            ok = file:delete(Link),
            <<"verified">>;
        {error, _} -> <<"unavailable">>
    end,
    _ = evidence_tree_files(Directory),
    {HardlinkState, SymlinkState}.

identity_remove_tree(Path, Count) when Count =< 1000 ->
    case file:read_link_info(Path) of
        {error, enoent} -> Count;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            {ok, Names} = file:list_dir(Path),
            Next = lists:foldl(fun(Name, Acc) ->
                identity_remove_tree(filename:join(Path, Name), Acc)
            end, Count + 1, Names),
            ok = file:del_dir(Path),
            Next;
        {ok, _} ->
            ok = file:delete(Path),
            Count + 1;
        {error, _} -> erlang:error(source_identity_cleanup_failed)
    end;
identity_remove_tree(_, _) -> erlang:error(source_identity_cleanup_limit).

separate_contents(Digest, Left, Right, Boundary) ->
    ok = file:write_file(Left, Boundary),
    ok = file:write_file(Right, <<>>),
    First = Digest([Left, Right]),
    ok = file:write_file(Left, <<>>),
    ok = file:write_file(Right, Boundary),
    Second = Digest([Left, Right]),
    First =/= Second.
