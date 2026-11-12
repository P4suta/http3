#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("diagnostic_failure.hrl").
-include("suite_evidence.hrl").
-include("suite_discovery.hrl").
-include("reader_boundary_fixture.hrl").

main([]) ->
    try self_test() of
        ok -> ok
    catch Class:Reason:Stack ->
        io:format(standard_error, "suite discovery self-test failed: ~p~n",
                  [diagnostic_failure_details(Class, Reason, Stack)]),
        halt(1)
    end;
main(_) ->
    halt(2).

self_test() ->
    Nonce = binary_to_list(binary:encode_hex(
        crypto:strong_rand_bytes(8), lowercase)),
    Root = filename:absname(filename:join(
        "build", "suite-discovery-self-test-" ++ Nonce)),
    ok = filelib:ensure_dir(filename:join(Root, "placeholder")),
    try
        namespaced_and_standalone_control(Root),
        duplicate_module_control(Root),
        unsafe_module_control(Root),
        declared_module_control(Root),
        missing_beam_control(Root),
        malformed_beam_control(Root),
        mismatched_beam_control(Root),
        stale_beam_control(Root),
        HardlinkState = hardlink_control(Root),
        SymlinkState = symlink_control(Root),
        {ParentKind, ParentState} = parent_component_link_control(Root),
        access_time_control(Root),
        unavailable_counts_control(),
        Rejected = 7 + length([verified || State <-
            [HardlinkState, SymlinkState, ParentState],
            State =:= <<"verified">>]),
        io:format("suite discovery controls=13 rejected_mutants=~B "
                  "hardlink=~s symlink=~s parent_component_kind=~s "
                  "parent_component_link=~s passed=true~n",
                  [Rejected, HardlinkState, SymlinkState,
                   ParentKind, ParentState])
    after
        remove_tree(Root, 0)
    end.

namespaced_and_standalone_control(Root) ->
    {Source, Ebin} = fixture(Root, "complete"),
    write(filename:join(Source, "nested/alpha_test.gleam"),
          <<"pub fn smoke_test() { Nil }\n">>),
    write(filename:join(Source, "standalone_tests.erl"),
          <<"-module(standalone_tests).\n"
            "-export([works_test/0]).\nworks_test() -> ok.\n">>),
    write_beam(Ebin, 'nested@alpha_test', [smoke_test]),
    write_beam(Ebin, standalone_tests, [works_test]),
    Inventory = suite_inventory(Source, Ebin),
    2 = maps:get(source_files, Inventory),
    2 = maps:get(modules, Inventory),
    2 = maps:get(beam_files, Inventory),
    2 = maps:get(configured_units, Inventory),
    true = suite_inventory_schema_valid(Inventory),
    [<<"nested@alpha_test">>, <<"standalone_tests">>] =
        lists:sort(suite_inventory_modules(Inventory)),
    true = suite_inventory_unchanged(Inventory, Source, Ebin),
    ok.

duplicate_module_control(Root) ->
    {Source, _Ebin} = fixture(Root, "duplicate"),
    write(filename:join(Source, "same.gleam"), <<"pub fn value() { Nil }\n">>),
    write(filename:join(Source, "same.erl"),
          <<"-module(same).\n-export([value/0]).\nvalue() -> ok.\n">>),
    expect_inventory_error(fun() -> suite_source_inventory(Source) end,
                           duplicate_source_module).

unsafe_module_control(Root) ->
    {Source, _Ebin} = fixture(Root, "unsafe"),
    write(filename:join(Source, "Bad.gleam"), <<"pub fn value() { Nil }\n">>),
    expect_inventory_error(fun() -> suite_source_inventory(Source) end,
                           unsafe_module_name).

declared_module_control(Root) ->
    {Source, _Ebin} = fixture(Root, "declared"),
    write(filename:join(Source, "expected.erl"),
          <<"-module(actual).\n-export([value/0]).\nvalue() -> ok.\n">>),
    expect_inventory_error(fun() -> suite_source_inventory(Source) end,
                           erlang_declared_module_mismatch).

missing_beam_control(Root) ->
    {Source, Ebin} = fixture(Root, "missing"),
    write(filename:join(Source, "missing_test.gleam"),
          <<"pub fn missing_test() { Nil }\n">>),
    expect_inventory_error(fun() -> suite_inventory(Source, Ebin) end,
                           beam_missing).

malformed_beam_control(Root) ->
    {Source, Ebin} = fixture(Root, "malformed"),
    write(filename:join(Source, "broken_test.gleam"),
          <<"pub fn broken_test() { Nil }\n">>),
    write(filename:join(Ebin, "broken_test.beam"), <<"not-a-beam">>),
    expect_inventory_error(fun() -> suite_inventory(Source, Ebin) end,
                           malformed_beam).

mismatched_beam_control(Root) ->
    {Source, Ebin} = fixture(Root, "mismatch"),
    write(filename:join(Source, "expected_test.gleam"),
          <<"pub fn expected_test() { Nil }\n">>),
    write_beam_as(Ebin, "expected_test.beam", actual_test, [actual_test]),
    expect_inventory_error(fun() -> suite_inventory(Source, Ebin) end,
                           beam_module_mismatch).

stale_beam_control(Root) ->
    {Source, Ebin} = fixture(Root, "stale"),
    write(filename:join(Source, "stable_test.gleam"),
          <<"pub fn stable_test() { Nil }\n">>),
    write_beam(Ebin, stable_test, [stable_test]),
    Before = suite_inventory(Source, Ebin),
    write_beam(Ebin, stable_test, [changed_test]),
    false = suite_inventory_unchanged(Before, Source, Ebin),
    expect_inventory_error(fun() ->
        suite_require_inventory_unchanged(Before, Source, Ebin)
    end, stale_suite_inventory).

hardlink_control(Root) ->
    {Source, _Ebin} = fixture(Root, "hardlink"),
    Original = filename:join(Source, "hardlink_test.gleam"),
    Alias = filename:join(Source, "hardlink-alias.data"),
    write(Original, <<"pub fn hardlink_test() { Nil }\n">>),
    case file:make_link(Original, Alias) of
        ok ->
            expect_inventory_error(fun() ->
                suite_read_regular(Original, source)
            end, source_hardlink_rejected),
            <<"verified">>;
        {error, _} ->
            %% Unsupported filesystems are represented as unavailable. They
            %% are never reported as a verified hardlink rejection.
            <<"unavailable">>
    end.

symlink_control(Root) ->
    {Source, _Ebin} = fixture(Root, "symlink"),
    Target = filename:join(Root, "symlink-target"),
    ok = filelib:ensure_dir(filename:join(Target, "placeholder")),
    write(filename:join(Target, "linked_test.gleam"),
          <<"pub fn linked_test() { Nil }\n">>),
    Link = filename:join(Source, "linked"),
    case file:make_symlink(filename:absname(Target), Link) of
        ok ->
            expect_inventory_error(fun() ->
                suite_source_inventory(Source)
            end, source_tree_link_rejected),
            <<"verified">>;
        {error, _} ->
            <<"unavailable">>
    end.

parent_component_link_control(Root) ->
    case reader_boundary_supplied_parent_path() of
        {ok, Supplied} ->
            expect_inventory_error(fun() ->
                suite_read_regular(Supplied, source)
            end, source_parent_link_rejected),
            {<<"junction">>, <<"verified">>};
        none ->
            Container = filename:join(Root, "parent-component"),
            Target = filename:join(Root, "parent-component-target"),
            Link = filename:join(Container, "linked-parent"),
            ok = filelib:ensure_dir(filename:join(Container, "placeholder")),
            ok = filelib:ensure_dir(filename:join(Target, "placeholder")),
            write(filename:join(Target, "linked_test.gleam"),
                  <<"pub fn linked_test() { Nil }\n">>),
            {Kind, State} = reader_boundary_make_parent_link(Target, Link),
            case State of
                <<"verified">> ->
                    try
                        expect_inventory_error(fun() ->
                            suite_read_regular(filename:join(
                                Link, "linked_test.gleam"), source)
                        end, source_parent_link_rejected)
                    after
                        ok = reader_boundary_remove_parent_link(Link)
                    end;
                <<"unavailable">> -> ok
            end,
            {Kind, State}
    end.

access_time_control(Root) ->
    {Source, _Ebin} = fixture(Root, "access-time"),
    Path = filename:join(Source, "identity_test.gleam"),
    write(Path, <<"pub fn identity_test() { Nil }\n">>),
    {ok, Info} = file:read_link_info(Path),
    %% A verifier must not invalidate its own input merely by reading it.
    Identity = suite_file_identity(Info),
    Identity = suite_file_identity(setelement(5, Info, changed_atime)),
    false = Identity =:= suite_file_identity(
        setelement(6, Info, changed_mtime)),
    ok.

unavailable_counts_control() ->
    Counts = suite_test_counts(#{invalid => true}, [], <<"nonce">>),
    #{state := <<"unavailable">>, completed := null, skipped := null} = Counts,
    true = suite_test_counts_valid(Counts),
    false = suite_test_counts_valid(
        Counts#{completed => 0, skipped => 0}),
    ok.

fixture(Root, Name) ->
    Directory = filename:join(Root, Name),
    Source = filename:join(Directory, "test"),
    Ebin = filename:join(Directory, "ebin"),
    ok = filelib:ensure_dir(filename:join(Source, "placeholder")),
    ok = filelib:ensure_dir(filename:join(Ebin, "placeholder")),
    {Source, Ebin}.

write(Path, Bytes) ->
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, Bytes).

write_beam(Ebin, Module, Functions) ->
    write_beam_as(Ebin, atom_to_list(Module) ++ ".beam", Module, Functions).

write_beam_as(Ebin, Name, Module, Functions) ->
    Exports = [{Function, 0} || Function <- Functions],
    Forms = [{attribute, 1, module, Module},
             {attribute, 2, export, Exports}] ++
        [{function, 3, Function, 0,
          [{clause, 3, [], [], [{atom, 3, ok}]}]}
         || Function <- Functions],
    {ok, Module, Beam, []} = compile:forms(
        Forms, [binary, return_errors, return_warnings]),
    write(filename:join(Ebin, Name), Beam).

expect_inventory_error(Fun, Expected) ->
    case try Fun(), accepted
         catch error:{suite_inventory_rejected, Reason} -> {rejected, Reason}
         end of
        {rejected, Expected} -> ok;
        _ -> erlang:error({inventory_control_failed, Expected})
    end.

remove_tree(Path, Count) when Count =< 1000 ->
    case file:read_link_info(Path) of
        {error, enoent} -> ok;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            {ok, Names} = file:list_dir(Path),
            Next = lists:foldl(fun(Name, Acc) ->
                remove_tree(filename:join(Path, Name), Acc)
            end, Count + 1, Names),
            ok = file:del_dir(Path),
            Next;
        {ok, _} ->
            ok = file:delete(Path),
            Count + 1;
        {error, _} ->
            erlang:error(self_test_cleanup_failed)
    end;
remove_tree(_, _) ->
    erlang:error(self_test_cleanup_limit).
