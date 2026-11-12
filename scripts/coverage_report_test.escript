#!/usr/bin/env escript
%%! +S 2:2 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-compile(nowarn_unused_function).
-include("evidence_identity.hrl").
-include("process_runner.hrl").
-include("coverage_report_evidence.hrl").

main(Arguments) ->
    try controls(Arguments)
    catch Class:Reason:Stack ->
        io:format(standard_error, "coverage report control failed: ~s~n",
            [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end.

controls(Arguments) ->
    Root = filename:absname("."),
    Directory = filename:absname("build/coverage-report-tests/" ++ binary_to_list(hex(crypto:strong_rand_bytes(16)))),
    Work = filename:join(Directory, "work"),
    ok = filelib:ensure_dir(filename:join(Work, "placeholder")),
    lists:foreach(fun(SourceRoot) ->
        ok = filelib:ensure_dir(filename:join([Work, SourceRoot, "placeholder"]))
    end, evidence_source_roots()),
    FixturePaths = lists:usort(evidence_static_source_paths() ++
        filelib:wildcard("scripts/*.hrl") ++
        ["scripts/coverage.escript", "scripts/process_supervisor.py"]),
    lists:foreach(fun(Path) ->
        {ok, Bytes} = file:read_file(Path),
        Destination = filename:join(Work, Path),
        ok = filelib:ensure_dir(Destination),
        ok = file:write_file(Destination, Bytes, [exclusive])
    end, FixturePaths),
    {ok, OriginalSource} = file:read_file("scripts/coverage.escript"),
    {Mutation, Source, Selected} = mutation(Arguments, OriginalSource),
    AllCases = [{success, "full"}, {blocked, "changed"}, {stream, "full"},
             {cleanup, "changed"}, {flood, "full"}, {prestart, "changed"},
             {partial, "full"}, {private, "changed"},
             {receipt_nonce, "full"}, {receipt_hash, "changed"},
             {receipt_unknown, "full"}, {unobserved_exit, "changed"}],
    Cases = [C || {Kind, _} = C <- AllCases, Selected =:= all orelse lists:member(Kind, Selected)],
    Rows = [control(Kind, Mode, Directory, Work, Root, Source) || {Kind, Mode} <- Cases],
    Passed = lists:all(fun(Row) -> maps:get(passed, Row) end, Rows),
    ok = file:write_file(filename:join(Directory, "result.json"), json:encode(#{
        schema => 1, scope => <<"Synthetic metric producer; actual coverage report dispatch/VM/publication controls">>,
        source_sha256 => hex(crypto:hash(sha256, OriginalSource)),
        executed_source_sha256 => hex(crypto:hash(sha256, Source)),
        mutation => Mutation, passed => Passed, controls => Rows})),
    io:format("coverage report controls: ~B/~B passed; result ~s~n",
        [length([ok || #{passed := true} <- Rows]), length(Rows), filename:join(Directory, "result.json")]),
    halt(case Passed of true -> 0; false -> 1 end).

control(Kind, Mode, Directory, Work, Root, Original) ->
    Case = filename:join(Directory, atom_to_list(Kind)),
    ok = filelib:ensure_dir(filename:join(Case, "placeholder")),
    Fixture = filename:join(Work, "scripts/coverage_report_fixture.erl"),
    Source = fixture(Original, Fixture, Kind),
    ok = file:write_file(Fixture, Source),
    {ok, Module, Beam, []} = compile:file(Fixture,
        [binary, return_errors, return_warnings, {i, filename:join(Work, "scripts")}]),
    ok = file:write_file(filename:join(Case, atom_to_list(Module) ++ ".beam"), Beam),
    Output = filename:join(Work, "build/coverage"),
    ok = filelib:ensure_dir(filename:join(Output, "placeholder")),
    Report = filename:join(Output, Mode ++ ".json"),
    Evidence = filename:join(Work, "coverage-evidence.json"),
    ProcessPath = filename:join(Output, "report-" ++ Mode ++ ".process.json"),
    lists:foreach(fun(P) -> case file:delete(P) of ok -> ok; {error, enoent} -> ok end end,
                  [Report, Evidence, ProcessPath]),
    %% Simulate an earlier Ready attempt. A worker that exits before entering
    %% report_started must not leave it usable by the current invocation.
    ok = file:write_file(Report, <<"{\"status\":\"Ready\"}">>),
    ok = file:write_file(Evidence, <<"{\"statuses\":{\"full\":\"Ready\",\"changed\":\"Ready\"}}">>),
    Eval = lists:flatten(io_lib:format("~p:main([\"report\",~0tp]),halt(0).", [Module, Mode])),
    Started = erlang:monotonic_time(millisecond),
    {Exit, Raw} = run_child_evaluation(Work, [Case], Eval, 15000),
    Elapsed = erlang:monotonic_time(millisecond) - Started,
    Process = read_json(ProcessPath),
    Generated = read_json(Report),
    Receipt = read_json(Evidence),
    Joined = maps:get(child_exit_observed, Raw),
    ProcessJoined = maps:get(<<"child_exit_observed">>, maps:get(<<"process">>, Process, #{}), false),
    Status = maps:get(<<"status">>, Generated, missing),
    Accepted = case Kind of
        success -> Exit =:= 0 andalso Status =:= <<"Ready">> andalso maps:is_key(<<"statuses">>, Receipt);
        blocked -> Exit =:= 1 andalso Status =:= <<"Blocked">> andalso maps:is_key(<<"statuses">>, Receipt);
        _ -> Exit =:= 1 andalso Generated =:= #{} andalso Receipt =:= #{}
    end,
    ExpectedProcess = case Kind of success -> <<"Ready">>; _ -> <<"Failed">> end,
    Inner = maps:get(<<"process">>, Process, #{}),
    LimitObserved = case Kind of
        stream -> maps:get(<<"timed_out">>, Inner, false) andalso maps:get(<<"output_bytes">>, Inner, 0) > 0;
        cleanup -> maps:get(<<"timed_out">>, Inner, false);
        flood -> maps:get(<<"output_limit_exceeded">>, Inner, false) andalso
            maps:get(<<"output_hashed_bytes">>, Inner, 0) =:= 8388608;
        _ -> true
    end,
    PrivateAbsent = binary:match(iolist_to_binary(json:encode(Process)),
                                 <<"coverage-report-private-control">>) =:= nomatch,
    Audited = case Kind of
        success ->
            {ok, RB} = file:read_file(Report), {ok, EB} = file:read_file(Evidence),
            Attempt = read_json(filename:join(Output, "report-" ++ Mode ++ ".attempt.json")),
            coverage_report_process_contract(list_to_binary(Mode), RB, EB,
                maps:get(<<"evidence_identity">>, Process, #{}), Process, Attempt, Source);
        _ -> true
    end,
    Passed = Accepted andalso Joined andalso ProcessJoined andalso Elapsed < 10000 andalso
        maps:get(<<"status">>, Process, missing) =:= ExpectedProcess andalso
        LimitObserved andalso PrivateAbsent andalso Audited,
    Row = #{kind => Kind, mode => list_to_binary(Mode), passed => Passed,
        child_exit_status => Exit, elapsed_milliseconds => Elapsed,
        outer_process => maps:without([tail, output_sha256], Raw),
        report_process => Process, report_status => Status,
        final_report_present => Generated =/= #{}, final_evidence_present => Receipt =/= #{}},
    ok = file:write_file(filename:join(Case, "result.json"), json:encode(Row)),
    %% Keep each source/BEAM pair so a control can be independently inspected.
    ok = file:write_file(filename:join(Case, "coverage_report_fixture.erl"), Source),
    true = filename:absname(".") =:= Root,
    Row.

fixture(Original, Fixture, Kind) ->
    [_Shebang, Body] = binary:split(Original, <<"\n">>),
    [Before, Remaining] = binary:split(Body, <<"\nreport_started(Mode) ->">>),
    [_Old, After] = binary:split(Remaining, <<"\nstart_quiet_io(">>),
    Paths = case binary:match(Original, <<"\ncoverage_report_path(Mode) ->">>) of
        nomatch -> "{filename:join(\"build/coverage\",Mode++\".json\"),\"coverage-evidence.json\"}";
        _ -> "{coverage_report_path(Mode),coverage_evidence_path()}"
    end,
    Replacement = lists:flatten(io_lib:format(
        "\nreport_started(Mode) ->\n"
        "  put(coverage_fixture_kind,~p),Kind=get(coverage_fixture_kind),\n"
        "  case Kind of prestart -> halt(0); _ -> ok end,\n"
        "  {Report,Evidence}=~s,\n"
        "  Status=case Kind of blocked-> <<\"Blocked\">>; _-> <<\"Ready\">> end,\n"
        "  Identity=evidence_identity(),\n"
        "  R=#{schema=>2,status=>Status,mode=>list_to_binary(Mode),evidence_identity=>Identity,execution_environment=>execution_runtime()},\n"
        "  E=#{schema=>2,statuses=>#{list_to_binary(Mode)=>Status},evidence_identity=>Identity,execution_environment=>execution_runtime()},\n"
        "  ok=file:write_file(Report,json:encode(R)),\n"
        "  case Kind of partial->ok; _->ok=file:write_file(Evidence,json:encode(E)) end,\n"
        "  case Kind of\n"
        "    stream-> F=fun Loop(0)->ok;Loop(N)->io:put_chars(\"x\"),receive after 20->Loop(N-1) end end,F(150);\n"
        "    flood-> F=fun Loop(0)->ok;Loop(N)->io:put_chars(binary:copy(<<120>>,65536)),Loop(N-1) end,F(144);\n"
        "    private->io:put_chars(\"coverage-report-private-control\"),erlang:error({private,<<\"coverage-report-private-control\">>});\n"
        "    _->ok\n"
        "  end,\n"
        "  case Kind of blocked->{blocked,{coverage_threshold_not_met,Mode,0,0}}; _->ok end.\n",
        [Kind, Paths])),
    Full = iolist_to_binary(["-module(coverage_report_fixture).\n-export([main/1]).\n-compile(nowarn_unused_function).\n",
                            Before, Replacement, "\nstart_quiet_io(", After]),
    Patched = binary:replace(Full, <<"escript:script_name()">>,
        iolist_to_binary(io_lib:format("~0tp", [Fixture])), [global]),
    Fast = case Kind of
        success -> Patched;
        blocked -> Patched;
        _ -> binary:replace(Patched, <<"coverage_report_deadline() -> 300000.">>,
                                    <<"coverage_report_deadline() -> 1500.">>)
    end,
    case Kind of
        cleanup -> binary:replace(Fast, <<"stop_quiet_io(QuietIo) ->">>,
            <<"stop_quiet_io(QuietIo) -> receive after 3000 -> ok end,">>);
        receipt_nonce -> corrupt_receipt(Fast, <<"Record#{nonce => <<0:256>>}">>);
        receipt_hash -> corrupt_receipt(Fast, <<"Record#{report_sha256 => <<0:512>>}">>);
        receipt_unknown -> corrupt_receipt(Fast, <<"Record#{unknown => true}">>);
        unobserved_exit -> binary:replace(Fast,
            <<"Documents = coverage_completed_report(Staging, Identity, Status, Output)">>,
            <<"Documents = coverage_completed_report(Staging, Identity, Status, Output#{child_exit_observed => false})">>);
        _ -> Fast
    end.

corrupt_receipt(Source, Record) ->
    binary:replace(Source, <<"json:encode(Record), [exclusive]">>,
        <<"json:encode(", Record/binary, "), [exclusive]">>).

mutation([], Source) -> {none, Source, all};
mutation(["--mutant", "direct"], Source) ->
    {direct, replace_one(Source,
        <<"_ -> run_bounded_report(Mode, Arguments)">>, <<"_ -> run(Arguments)">>), [stream, prestart]};
mutation(["--mutant", "early-publication"], Source) ->
    {early_publication, replace_one(Source,
        <<"#{report := Path} -> Path;">>,
        <<"#{report := _Path} -> filename:join(?OUTPUT, Mode ++ \".json\");">>), [cleanup, flood]};
mutation(["--mutant", "unobserved-exit"], Source) ->
    {unobserved_exit, replace_one(Source,
        <<"        true = maps:get(child_exit_observed, Output),">>,
        <<"        _ = maps:get(child_exit_observed, Output),">>), [unobserved_exit]}.

replace_one(Source, Old, New) ->
    [_] = binary:matches(Source, Old), binary:replace(Source, Old, New).

read_json(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> try json:decode(Bytes) catch _:_ -> #{} end;
        _ -> #{}
    end.
hex(Bytes) -> binary:encode_hex(Bytes).
