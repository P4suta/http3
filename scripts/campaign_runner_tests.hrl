%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("json_reader_tests.hrl").
generated_self_test() ->
    json_reader_duplicate_controls("campaign-build", [fresh_manifest_path("http")],
        fun() -> is_map(generated_builds(["http"])) end),
    Compiled = generated_compile_runner(),
    [{campaign_child, ChildBytes} | _] = Compiled,
    {module, campaign_child} = code:load_binary(campaign_child, "campaign_child.beam", ChildBytes),
    Failure = #{exception_class => <<"error">>, classification => <<"validation_failed">>},
    Run = fun(N) when N >= 7 -> {error, Failure}; (N) -> {ok, N} end,
    #{scope := <<"generated">>, minimal_generated_prefix := 7,
      deterministic_replay := true} = campaign_child:localize(Run, 100, {error, Failure}),
    #{scope := <<"retained_or_setup">>} = campaign_child:localize(fun(_) -> {error, Failure} end, 100, {error, Failure}),
    #{scope := <<"non_reproducible">>} = campaign_child:localize(fun(N) -> {ok, N} end, 100, {error, Failure}),
    Runtime = execution_runtime(),
    generated_package_closure_controls(Compiled, Runtime),
    Request = #{mode => <<"property">>, family => <<"quic-core-wire">>, seed => 7,
                requested_cases => 100, retained_seeds => 0},
    Good = generated_fixture_execution(Compiled, Request, Runtime, "N", 10000),
    true = maps:get(exit_status, Good) =:= 0,
    true = generated_child_valid(maps:get(child, Good), generated_json(Request), maps:get(nonce, Good), Runtime),
    Digest = maps:get(runner_sha256, Good),
    Qualified = generated_json(Good#{deadline_ms := 600000}),
    true = generated_execution_valid(Qualified, generated_json(Request), Runtime, Digest),
    lists:foreach(fun(Bad) -> false = generated_execution_valid(Bad, generated_json(Request), Runtime, Digest) end,
        [Qualified#{<<"nonce">> => <<"stale">>}, Qualified#{<<"exit_status">> => 1},
         Qualified#{<<"child_sha256">> => binary:copy(<<"0">>, 64)},
         Qualified#{<<"process">> => (maps:get(<<"process">>, Qualified))#{<<"child_exit_observed">> => false}},
         Qualified#{<<"secret">> => <<"private-marker">>}]),
    Private = generated_fixture_execution(Compiled, Request, Runtime,
        "case N >= 7 of true -> erlang:error({badmatch,<<\"private-marker\">>}); false -> N end", 10000),
    1 = maps:get(exit_status, Private),
    #{<<"failure">> := #{<<"minimal_generated_prefix">> := 7}} = maps:get(child, Private),
    true = binary:match(iolist_to_binary(json:encode(Private)), <<"private-marker">>) =:= nomatch,
    Start = erlang:monotonic_time(millisecond),
    Stalled = generated_fixture_execution(Compiled, Request, Runtime, "receive never -> N end", 5000, 100),
    124 = maps:get(exit_status, Stalled),
    true = process_deadline_verified(124, maps:get(process, Stalled)),
    true = erlang:monotonic_time(millisecond) - Start < 17000,
    Flood = generated_fixture_execution(Compiled, Request, Runtime,
        "lists:foreach(fun(_)->io:put_chars(standard_error,binary:copy(<<\"private-marker\">>,65536)) end,lists:seq(1,64)),N", 10000),
    125 = maps:get(exit_status, Flood),
    true = process_output_limit_verified(125, maps:get(process, Flood)),
    true = maps:get(output_limit_exceeded, maps:get(process, Flood)),
    true = binary:match(iolist_to_binary(json:encode(Flood)), <<"private-marker">>) =:= nomatch,
    %% The first failure remains inspectable if replay itself never returns.
    ReplayBlocked = generated_fixture_execution(Compiled, Request, Runtime,
        "case N of 100 -> erlang:error(badarg); _ -> receive never -> N end end", 5000, 0),
    124 = maps:get(exit_status, ReplayBlocked),
    #{<<"failure">> := #{<<"scope">> := <<"unlocalized">>}} = maps:get(child, ReplayBlocked),
    true = process_deadline_verified(124, maps:get(process, ReplayBlocked)),
    io:put_chars("campaign runner: five owned child VMs joined; exact counts, private failure, deadline, flood, checkpoint and tamper checks passed\n"), ok.

generated_fixture_execution(Compiled, Request, Runtime, Body, Deadline) ->
    generated_fixture_execution(Compiled, Request, Runtime, Body, Deadline, any).

generated_fixture_execution(Compiled, Request, Runtime, Body, Deadline, ExpectedEntry) ->
    Directory = filename:absname(filename:join("build/diagnostics/campaign-bounds",
        "fixture-" ++ binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8))))),
    Source = filename:join(Directory, "property_corpus.erl"),
    Entered = filename:join(Directory, "entered"),
    ok = filelib:ensure_dir(Source),
    try
        ok = file:write_file(Source, ["-module(property_corpus).\n-export([exercise_from/2]).\nexercise_from(_,N)->",
            "ok=file:write_file(", io_lib:format("~0tp", [Entered]), ",integer_to_binary(N)),", Body, ".\n"]),
        {ok, property_corpus, Bytes, []} = compile:file(Source, [binary, return_errors, return_warnings]),
        WithFixture = Compiled ++ [{property_corpus, Bytes}],
        %% This synthetic corpus is self-contained. Loading unrelated project
        %% dependency directories can spend the entire short fault-injection
        %% deadline in VM code-path initialization before the fixture runs.
        Run = generated_run_child(Request, WithFixture, generated_runner_digest(WithFixture), Runtime, Deadline, []),
        %% Distinguish initial execution from replay: the initial failure's
        %% marker cannot prove that the replay's stalled callback ran.
        {ok, Marker} = generated_read_fixture_entry(Entered),
        Entry = binary_to_integer(Marker),
        true = integer_to_binary(Entry) =:= Marker andalso Entry >= 0 andalso Entry =< 100,
        true = ExpectedEntry =:= any orelse Entry =:= ExpectedEntry,
        Run
    after
        _ = file:delete(Entered),
        _ = file:delete(Source),
        _ = file:del_dir(Directory)
    end.

generated_read_fixture_entry(Path) ->
    %% Only the fixed fixture's bounded integer is eligible as an entry marker.
    {ok, File} = file:open(Path, [read, binary, raw]),
    try
        {ok, Bytes} = file:read(File, 4),
        true = byte_size(Bytes) =< 3,
        eof = file:read(File, 1),
        {ok, Bytes}
    after ok = file:close(File) end.

generated_package_closure_controls(Compiled, Runtime) ->
    Directory = filename:absname(filename:join("build/diagnostics/campaign-bounds",
        "closures-" ++ binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8))))),
    {ok, Previous} = file:get_cwd(),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    Families = [{<<"http-masque">>, "build/dev/erlang", http, masque_property_corpus},
        {<<"http3-wire">>, "packages/http3/build/dev/erlang", http3, 'native@property_corpus'},
        {<<"quic-core-wire">>, "packages/quic_core/build/dev/erlang", core, property_corpus}],
    try
        ok = file:set_cwd(Directory),
        %% Every package offers the same dependency module with a different
        %% result. A sibling closure must never shadow the requested package.
        lists:foreach(fun({_, Root, Expected, _}) ->
            Source = filename:join([Root, "fixture", "ebin", "campaign_path_fixture.erl"]),
            ok = filelib:ensure_dir(Source),
            ok = file:write_file(Source, io_lib:format(
                "-module(campaign_path_fixture).~n-export([scope/0]).~nscope()->~p.~n", [Expected])),
            {ok, campaign_path_fixture, Beam, []} = compile:file(Source,
                [binary, return_errors, return_warnings]),
            ok = file:write_file(filename:rootname(Source) ++ ".beam", Beam)
        end, Families),
        lists:foreach(fun({Family, _, Expected, Module}) ->
            Source = atom_to_list(Module) ++ ".erl",
            ok = file:write_file(Source, io_lib:format(
                "-module(~p).~n-export([exercise_from/2]).~n"
                "exercise_from(_,N)->case campaign_path_fixture:scope() of ~p->N;_->0 end.~n",
                [Module, Expected])),
            {ok, Module, Beam, []} = compile:file(Source, [binary, return_errors, return_warnings]),
            WithFixture = Compiled ++ [{Module, Beam}],
            Request = #{mode => <<"property">>, family => Family, seed => 7,
                requested_cases => 100, retained_seeds => 0},
            Run = generated_run_child(Request, WithFixture,
                generated_runner_digest(WithFixture), Runtime, 10000),
            true = process_status_verified(maps:get(exit_status, Run), 0,
                                           maps:get(process, Run)),
            true = generated_child_valid(maps:get(child, Run), generated_json(Request),
                maps:get(nonce, Run), Runtime),
            true = process_completion_verified(maps:get(process, Run))
        end, Families),
        io:put_chars("campaign package closures: three conflicting dependencies remained isolated\n")
    after
        ok = file:set_cwd(Previous),
        ok = file:del_dir_r(Directory)
    end.
