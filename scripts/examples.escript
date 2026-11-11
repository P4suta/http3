#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-include("process_runner.hrl").
-include("examples_evidence.hrl").

-define(REPORT, "build/examples/report.json").
-define(EXAMPLE_TIMEOUT, 30000).
-define(COMPILER_TIMEOUT, 120000).

main(Arguments) ->
    ok = file:set_cwd(filename:dirname(filename:dirname(filename:absname(escript:script_name())))),
    try run(Arguments)
    catch Class:Reason:Stack ->
        io:format(standard_error, "documentation examples failed: ~s~n",
                  [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end.

run([]) ->
    Identity = evidence_begin(?REPORT),
    ok = filelib:ensure_dir(?REPORT),
    try run_examples(Identity)
    catch Class:Reason:Stack ->
        case filelib:is_regular(?REPORT) of
            true ->
                Retained = read_json(?REPORT),
                case maps:is_key(<<"failure">>, Retained) of
                    true -> ok;
                    false -> write_json(?REPORT, Retained#{<<"status">> => <<"Failed">>,
                        <<"failure">> => json_map(diagnostic_failure_details(Class, Reason, Stack))})
                end;
            false -> write_json(?REPORT, #{schema => 2, status => <<"Failed">>,
                shareable => true, completed_tests => 0, evidence_identity => Identity,
                execution_environment => execution_runtime(),
                failure => diagnostic_failure_details(Class, Reason, Stack)})
        end,
        erlang:raise(Class, Reason, Stack)
    end;
run(["--self-test"]) -> self_test();
run(["--verify"]) ->
    Build = fresh_verified_report("http"),
    {_, Examples} = examples_sources(),
    ok = examples_validate_report(read_json(?REPORT), evidence_identity(),
        Build, Examples),
    io:format("documentation example evidence verified~n");
run(_) -> erlang:error(invalid_example_arguments).

run_examples(Identity) ->
    fresh_with_verified_build("http", fun(Snapshot) ->
        run_examples_verified(Identity, Snapshot)
    end).

run_examples_verified(Identity, Snapshot) ->
    Build = maps:get(report, Snapshot),
    {Markdown, Examples} = examples_sources(),
    Nonce = nonce(),
    Directory = examples_run_directory(Nonce),
    make_run_directory(Directory),
    Runner = compile_runner(Directory),
    RunnerHashes = runner_hashes(Runner),
    write_project(Directory, Examples),
    Compiler = compile_gleam(Directory, ?COMPILER_TIMEOUT),
    Base = #{schema => 2, status => <<"Failed">>, shareable => true,
        count => length(Examples), markdown_files_scanned => length(Markdown),
        run_nonce => Nonce, build_identity => Build, runner_sha256 => RunnerHashes,
        compiler => Compiler, examples => [], completed_tests => 0},
    %% Persist each completed stage before another child starts. A later setup
    %% or freshness failure must not erase actual execution evidence.
    checkpoint(Base, Identity),
    ensure(proof_passed(Compiler, compiler), example_gleam_compilation_failed),
    BeamCompiler = compile_beams(Directory, Runner, Examples, Nonce),
    CompiledBase = Base#{beam_compiler => BeamCompiler},
    checkpoint(CompiledBase, Identity),
    ensure(proof_passed(BeamCompiler, beam) andalso
        examples_compile_child_valid(maps:get(child, BeamCompiler), Nonce, Examples),
        example_beam_compilation_failed),
    Rows = run_all(Examples, Directory, Runner, CompiledBase, Identity, []),
    Finished = CompiledBase#{examples => Rows,
        completed_tests => lists:sum([maps:get(completed_tests, R) || R <- Rows])},
    Complete = lists:all(fun(R) -> maps:get(status, R) =:= <<"Passed">> end, Rows),
    Report = try
        FinalSnapshot = fresh_verify_locked("http"),
        Build = maps:get(report, FinalSnapshot),
        true = maps:get(sha256, Snapshot) =:= maps:get(sha256, FinalSnapshot),
        Bound = evidence_complete(Finished#{status => case Complete of
            true -> <<"Ready">>; false -> <<"Failed">> end}, Identity),
        case Complete of
            true -> ok = examples_validate_report(json_map(Bound), Identity, Build, Examples);
            false -> ok
        end,
        Bound
    catch Class:Reason:Stack ->
        Finished#{status => <<"Failed">>, evidence_identity => Identity,
            execution_environment => execution_runtime(),
            failure => diagnostic_failure_details(Class, Reason, Stack)}
    end,
    write_json(?REPORT, Report),
    io:format("documentation examples: ~s, ~B completed mains in ~B modules~n",
        [maps:get(status, Report), maps:get(completed_tests, Report), length(Examples)]),
    ensure(maps:get(status, Report) =:= <<"Ready">>, example_execution_incomplete).

checkpoint(Report, Identity) ->
    write_json(?REPORT, Report#{evidence_identity => Identity,
                               execution_environment => execution_runtime()}).

run_all([], _, _, _, _, Reversed) -> lists:reverse(Reversed);
run_all([Example | Rest], Directory, Runner, Base, Identity, Reversed) ->
    {Row, _Output} = execute_example(Example, Directory, Runner, ?EXAMPLE_TIMEOUT),
    New = [Row | Reversed],
    checkpoint(Base#{examples => lists:reverse(New), completed_tests =>
        lists:sum([maps:get(completed_tests, R) || R <- New])}, Identity),
    run_all(Rest, Directory, Runner, Base, Identity, New).

compile_runner(Directory) ->
    Runner = filename:absname(filename:join(Directory, "runner")),
    ok = filelib:ensure_dir(filename:join(Runner, "placeholder")),
    lists:foreach(fun(Name) ->
        {ok, Module, Beam, []} = compile:file("scripts/" ++ Name ++ ".erl",
            [binary, return_errors, return_warnings, {i, "scripts"}]),
        ok = file:write_file(filename:join(Runner, atom_to_list(Module) ++ ".beam"), Beam, [exclusive])
    end, ["qualification_eunit_listener", "examples_child"]),
    Runner.

runner_hashes(Runner) -> maps:from_list([{list_to_binary(Name),
    examples_file_hash(filename:join(Runner, Name ++ ".beam"), 4194304)} ||
        Name <- ["qualification_eunit_listener", "examples_child"]]).

write_project(Directory, Examples) ->
    Manifest = <<"name = \"documentation_examples\"\nversion = \"0.0.0\"\n"
        "target = \"erlang\"\ngleam = \">= 1.18.1\"\n\n[dependencies]\n"
        "http = \">= 0.1.0\"\nhttp3 = \">= 0.1.0\"\nquic_core = \">= 0.1.0\"\n"
        "gleam_http = \">= 4.3.0 and < 5.0.0\"\n"
        "gleam_stdlib = \">= 1.0.0 and < 2.0.0\"\n">>,
    ok = filelib:ensure_dir(filename:join(Directory, "src/placeholder")),
    ok = file:write_file(filename:join(Directory, "gleam.toml"), Manifest, [exclusive]),
    lists:foreach(fun(E) ->
        Source = filename:join([Directory, "src", binary_to_list(maps:get(module, E)) ++ ".gleam"]),
        ok = file:write_file(Source, [maps:get(source, E), $\n], [exclusive])
    end, Examples).

compile_gleam(Directory, Timeout) ->
    {Proof, _} = compile_gleam_capture(Directory, Timeout),
    Proof.

compile_gleam_capture(Directory, Timeout) ->
    Executable = os:find_executable("gleam"),
    ensure(is_list(Executable), gleam_not_found),
    Arguments = ["compile-package", "--target", "erlang", "--package", Directory,
        "--out", filename:join(Directory, "out"), "--lib", "build/dev/erlang", "--no-beam"],
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    {Port, Identity} = open_owned_process(Executable, Arguments,
        filename:absname("."), [], Deadline),
    {Status, Output} = collect_eunit(Port, new_output(Identity), Deadline),
    %% compile-package is silent on success. Any warning is therefore rejected
    %% even if it precedes the retained output tail. No output bytes or digest
    %% escape into the shareable result. --no-beam avoids erlc descendants.
    {#{stage => <<"gleam_no_beam">>, child_exit_status => Status, timeout_milliseconds => Timeout,
       process => safe_process(Output, compiler)}, Output}.

compile_beams(Directory, Runner, Examples, Nonce) ->
    Ebin = filename:absname(filename:join(Directory, "out/ebin")),
    ok = filelib:ensure_dir(filename:join(Ebin, "placeholder")),
    Files = [#{module => maps:get(module, E),
        path => filename:absname(examples_generated_path(Directory, maps:get(module, E))),
        sha256 => examples_file_hash(examples_generated_path(Directory, maps:get(module, E)), 4194304)} || E <- Examples],
    Path = filename:absname(filename:join(Directory, "beam-compiler.json")),
    Evaluation = lists:flatten(io_lib:format("examples_child:compile_examples(~0tp,~0tp,~0tp,~0tp).",
        [Files, Ebin, Path, Nonce])),
    {Status, Output} = run_child_evaluation(filename:absname("."), runtime_paths(Runner, Ebin),
        Evaluation, ?COMPILER_TIMEOUT),
    Child = read_json(Path),
    Safe = case examples_compile_child_valid(Child, Nonce, Examples) of
        true -> Child;
        false -> safe_compile_failure(Child, Nonce)
    end,
    #{stage => <<"beam_compile">>, child_exit_status => Status, timeout_milliseconds => ?COMPILER_TIMEOUT,
      process => safe_process(Output, beam), child => Safe}.

safe_compile_failure(Child, Nonce) ->
    try
        true = suite_exact_keys(Child, [schema, nonce, status, modules, classification, exception_class, stack_depth]),
        1 = maps:get(<<"schema">>, Child), Nonce = maps:get(<<"nonce">>, Child),
        <<"Failed">> = maps:get(<<"status">>, Child), [] = maps:get(<<"modules">>, Child),
        true = lists:member(maps:get(<<"classification">>, Child),
            [<<"pattern_mismatch">>, <<"unexpected_variant">>, <<"assertion_failed">>,
             <<"callback_failed">>, <<"invalid_argument">>, <<"resource_limit">>,
             <<"deadline_exceeded">>, <<"validation_failed">>]),
        true = lists:member(maps:get(<<"exception_class">>, Child), [<<"error">>, <<"exit">>, <<"throw">>]),
        Depth = maps:get(<<"stack_depth">>, Child), true = is_integer(Depth) andalso Depth >= 0 andalso Depth =< 16,
        Child
    catch _:_ -> #{invalid => true} end.

execute_example(Example, Directory, Runner, Timeout) ->
    Name = maps:get(module, Example),
    Beam = examples_beam_path(Directory, Name),
    Generated = examples_generated_path(Directory, Name),
    BeamHash = examples_file_hash(Beam, 4194304),
    GeneratedHash = examples_file_hash(Generated, 4194304),
    Nonce = nonce(),
    Path = filename:absname(filename:join(Directory, binary_to_list(Name) ++ "-child.json")),
    Evaluation = lists:flatten(io_lib:format("examples_child:run_example(~0tp,~0tp,~0tp,~B).",
        [Name, Path, Nonce, Timeout])),
    {Status, Output} = run_child_evaluation(filename:absname("."),
        runtime_paths(Runner, filename:absname(filename:dirname(Beam))), Evaluation, Timeout + 5000),
    Child = suite_safe_child(read_json(Path), [examples_unit(Name)], Nonce),
    Process = safe_process(Output, beam),
    Proof = #{child_exit_status => Status, process => Process},
    Passed = proof_passed(Proof, beam) andalso suite_child_valid(Child, [examples_unit(Name)], Nonce)
        andalso BeamHash =:= examples_file_hash(Beam, 4194304)
        andalso GeneratedHash =:= examples_file_hash(Generated, 4194304),
    Row = maps:merge(maps:remove(source, Example), Proof#{child => Child,
        generated_sha256 => GeneratedHash, beam_sha256 => BeamHash, run_nonce => Nonce,
        timeout_milliseconds => Timeout,
        completed_tests => suite_completed_tests(Child),
        status => case Passed of true -> <<"Passed">>; false -> <<"Failed">> end}),
    {Row, Output}.

runtime_paths(Runner, Ebin) -> [Runner, Ebin | [filename:absname(P) ||
    P <- filelib:wildcard("build/dev/erlang/*/ebin")]].

safe_process(Output, _Kind) -> maps:without([tail, output_sha256], Output).

proof_passed(Proof, Kind) ->
    try examples_process_valid(json_map(Proof), Kind) andalso
        (Kind =/= compiler orelse maps:get(output_bytes, maps:get(process, Proof)) =:= 0)
    catch _:_ -> false end.

make_run_directory(Directory) ->
    %% Unique child directories avoid recursive deletion, retain failed runs,
    %% and never follow a preexisting run directory supplied by an artifact.
    examples_real_path("build"),
    case file:make_dir("build/examples") of ok -> ok; {error, eexist} -> ok end,
    examples_real_path("build/examples"),
    ok = file:make_dir(Directory).

read_json(Path) ->
    try json:decode(examples_read(Path, 16777216)) catch _:_ -> #{invalid => true} end.
write_json(Path, Value) -> ok = file:write_file(Path, [json:encode(Value), $\n]).
json_map(Value) -> json:decode(iolist_to_binary(json:encode(Value))).
nonce() -> hex(crypto:strong_rand_bytes(16)).
hex(Binary) -> binary:encode_hex(Binary).
ensure(true, _) -> ok;
ensure(false, Reason) -> erlang:error(Reason).

self_test() ->
    Directory = examples_run_directory(nonce()),
    make_run_directory(Directory),
    Runner = compile_runner(Directory),
    Fixtures = [{"pass", "nil"},
        {"stall", "receive never -> nil end"},
        {"private", "Marker = <<\"example-private-marker\">>, io:format(standard_error,\"~s~n\",[Marker]), erlang:error({badmatch,{Marker,self(),make_ref()}})"},
        {"flood", "Block=binary:copy(<<\"example-private-marker\">>,65536), lists:foreach(fun(_)->io:put_chars(standard_error,Block) end,lists:seq(1,16)),nil"},
        {"non_nil", "ok"}],
    Tests = [fixture(Directory, Name, Body) || {Name, Body} <- Fixtures],
    Started = erlang:monotonic_time(millisecond),
    Runs = [execute_example(E, Directory, Runner, case maps:get(module, E) of
        <<"example_fixture_flood">> -> 5000;
        _ -> 200
    end) || E <- Tests],
    Elapsed = erlang:monotonic_time(millisecond) - Started,
    write_json(filename:join(Directory, "self-test.json"), #{schema => 1, status => <<"Running">>,
        elapsed_milliseconds => Elapsed, examples => [R || {R, _} <- Runs]}),
    [{Pass, _}, {Stall, _}, {Private, PrivateOutput}, {Flood, _}, {NonNil, _}] = Runs,
    ensure(maps:get(status, Pass) =:= <<"Passed">> andalso maps:get(completed_tests, Pass) =:= 1, ordinary_main_executed),
    ensure(maps:get(status, Stall) =:= <<"Failed">>, stalled_main_rejected),
    ensure(maps:get(status, Private) =:= <<"Failed">>, private_failure_rejected),
    ensure(maps:get(status, Flood) =:= <<"Failed">>, output_flood_rejected),
    ensure(maps:get(child_exit_status, Flood) =:= 125, output_limit_exit),
    ensure(maps:get(status, NonNil) =:= <<"Failed">>, non_nil_result_rejected),
    ensure(Elapsed < 25000, absolute_main_deadline),
    ensure(lists:all(fun({R, _}) -> maps:get(child_exit_observed, maps:get(process, R)) end, Runs), child_teardown_observed),
    ensure(binary:match(output_tail(PrivateOutput), <<"example-private-marker">>) =/= nomatch, private_output_positive_control),
    Shareable = iolist_to_binary(json:encode([R || {R, _} <- Runs])),
    ensure(binary:match(Shareable, <<"example-private-marker">>) =:= nomatch, private_output_removed),
    ensure(binary:match(Shareable, <<"output_sha256">>) =:= nomatch, private_digest_removed),
    ensure(binary:match(Shareable, <<"tail">>) =:= nomatch, private_tail_removed),
    source_self_tests(),
    CompilerProofs = compiler_self_tests(Directory, Runner),
    validator_self_tests(Pass, hd(Tests), Directory, Runner),
    write_json(filename:join(Directory, "self-test.json"), #{schema => 1, status => <<"Passed">>,
        elapsed_milliseconds => Elapsed, examples => [R || {R, _} <- Runs],
        compiler_fixtures => CompilerProofs,
        private_output_positive_control => true, child_teardown_observed => true}),
    io:format("examples self-test: executed pass/stall/private/flood/non-Nil, bounded exit and strict evidence verified (~B ms)~n", [Elapsed]).

compiler_self_tests(Directory, Runner) ->
    GoodDirectory = filename:join(Directory, "compiler-pass"),
    Good = #{module => <<"example_compile_pass">>, source => <<"pub fn main() -> Nil { Nil }">>},
    write_project(GoodDirectory, [Good]),
    GoodProof = compile_gleam(GoodDirectory, 10000),
    ensure(proof_passed(GoodProof, compiler), actual_gleam_compilation),
    Nonce = nonce(),
    BeamProof = compile_beams(GoodDirectory, Runner, [Good], Nonce),
    ensure(proof_passed(BeamProof, beam) andalso
        examples_compile_child_valid(maps:get(child, BeamProof), Nonce, [Good]), actual_beam_compilation),
    WarningDirectory = filename:join(Directory, "compiler-warning"),
    Warning = #{module => <<"example_compile_warning">>, source =>
        <<"pub fn main() -> Nil { let private_unused = \"example-private-marker\" Nil }">>},
    write_project(WarningDirectory, [Warning]),
    {WarningProof, WarningOutput} = compile_gleam_capture(WarningDirectory, 10000),
    ensure(maps:get(child_exit_status, WarningProof) =:= 0, warning_is_not_compiler_error),
    ensure(not proof_passed(WarningProof, compiler), compiler_warning_rejected),
    ensure(binary:match(output_tail(WarningOutput), <<"example-private-marker">>) =/= nomatch,
        compiler_private_output_positive_control),
    ensure(binary:match(iolist_to_binary(json:encode(WarningProof)), <<"example-private-marker">>) =:= nomatch,
        compiler_private_output_removed),
    #{pass => GoodProof, beam => BeamProof, warning => WarningProof,
      warning_private_output_positive_control => true}.

fixture(Directory, Suffix, Body) ->
    Name = list_to_binary("example_fixture_" ++ Suffix),
    Path = examples_generated_path(Directory, Name),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, ["-module(", Name, ").\n-export([main/0]).\nmain()->", Body, ".\n"]),
    {ok, _, Beam, []} = compile:file(Path, [binary, return_errors, return_warnings]),
    BeamPath = examples_beam_path(Directory, Name),
    ok = filelib:ensure_dir(BeamPath), ok = file:write_file(BeamPath, Beam),
    FixtureSource = list_to_binary(Body),
    ProjectPath = examples_project_path(Directory, Name),
    ok = filelib:ensure_dir(ProjectPath),
    ok = file:write_file(ProjectPath, <<FixtureSource/binary, $\n>>),
    #{package => <<"http">>, module => Name, document => <<"self_test.md">>, line => 1,
      source => FixtureSource,
      sha256 => hex(crypto:hash(sha256, list_to_binary(Body)))}.

source_self_tests() ->
    ensure(not examples_documented("build/snapshot/docs.md"), generated_tree_pruned),
    ensure(not examples_documented("node_modules/package/docs.md"), dependencies_pruned),
    ensure(examples_documented("docs/MIGRATION.md"), migration_discovered),
    ensure(try examples_parse_lines([], "fixture.md", 2, pending, none, []), false catch _:_ -> true end,
        orphan_annotation_rejected),
    ensure(try examples_parse_lines([<<"```gleam">>], "fixture.md", 1, none, none, []), false catch _:_ -> true end,
        unannotated_example_rejected),
    {_, Examples} = examples_sources(),
    ensure(lists:any(fun(E) -> maps:get(document, E) =:= <<"docs/MIGRATION.md">> end, Examples), actual_migration_extracted).

validator_self_tests(Pass, Example, Directory, Runner) ->
    Row = json_map(Pass),
    ensure(examples_row_valid(Row, Example, Directory), valid_execution_row),
    ensure(reject_row(Row#{<<"payload">> => <<"private">>}, Example, Directory), unknown_row_field_rejected),
    ensure(reject_row(Row#{<<"completed_tests">> => 0}, Example, Directory), unexecuted_example_rejected),
    ensure(reject_row(Row#{<<"run_nonce">> => nonce()}, Example, Directory), stale_child_rejected),
    Proc = maps:get(<<"process">>, Row),
    ensure(reject_row(Row#{<<"process">> => Proc#{<<"output_sha256">> => <<"private">>}}, Example, Directory), output_digest_rejected),
    ensure(reject_row(Row#{<<"process">> => Proc#{<<"child_exit_observed">> => false}}, Example, Directory), unreaped_child_rejected),
    Beam = examples_beam_path(Directory, maps:get(module, Example)),
    Original = examples_read(Beam, 4194304),
    ok = file:write_file(Beam, <<Original/binary, 0>>),
    ensure(reject_row(Row, Example, Directory), changed_beam_rejected),
    ok = file:write_file(Beam, Original),
    Project = examples_project_path(Directory, maps:get(module, Example)),
    Source = examples_read(Project, 524289),
    ok = file:write_file(Project, <<Source/binary, "tampered">>),
    ensure(reject_row(Row, Example, Directory), changed_extracted_source_rejected),
    ok = file:write_file(Project, Source),
    Hashes = runner_hashes(Runner),
    ensure(examples_runner_valid(Hashes, Directory), runner_bytes_bound),
    whole_report_self_tests(Pass, Example, Directory, Hashes).

whole_report_self_tests(Pass, Example, Directory, Hashes) ->
    "run-" ++ RunNonce = filename:basename(Directory),
    Nonce = list_to_binary(RunNonce),
    Runtime = execution_runtime(), Identity = #{<<"fixture">> => true},
    Build = #{<<"toolchain">> => #{<<"runtime">> => Runtime}},
    %% Synthetic schema fixture only. It is never emitted as Ready evidence;
    %% the retained self-test report contains actual execution rows above.
    Row = Pass#{timeout_milliseconds => 30000},
    Process = maps:get(process, Row),
    CompiledRow = maps:with([module, generated_sha256, beam_sha256], Row),
    Report = json_map(#{schema => 2, status => <<"Ready">>, shareable => true,
        count => 1, markdown_files_scanned => length(examples_markdown_files()),
        run_nonce => Nonce, build_identity => Build, runner_sha256 => Hashes,
        compiler => #{stage => <<"gleam_no_beam">>, timeout_milliseconds => 120000,
            child_exit_status => 0, process => Process},
        beam_compiler => #{stage => <<"beam_compile">>, timeout_milliseconds => 120000,
            child_exit_status => 0, process => Process, child => #{schema => 1, nonce => Nonce,
                status => <<"Passed">>, modules => [CompiledRow]}},
        examples => [Row], completed_tests => 1, evidence_identity => Identity,
        execution_environment => Runtime}),
    Valid = fun(R) -> examples_validate_report(R, Identity, Build, [Example]) end,
    ensure(Valid(Report) =:= ok, complete_report_schema),
    Mutations = [Report#{<<"payload">> => <<"private">>},
        Report#{<<"status">> => <<"Failed">>},
        Report#{<<"evidence_identity">> => #{}},
        Report#{<<"build_identity">> => #{}},
        Report#{<<"execution_environment">> => #{}},
        Report#{<<"examples">> => []}, Report#{<<"count">> => 0},
        Report#{<<"completed_tests">> => 0}, Report#{<<"run_nonce">> => nonce()},
        Report#{<<"runner_sha256">> => #{}},
        Report#{<<"compiler">> => maps:put(<<"child_exit_status">>, 1, maps:get(<<"compiler">>, Report))},
        Report#{<<"beam_compiler">> => maps:put(<<"child">>, #{}, maps:get(<<"beam_compiler">>, Report))}],
    ensure(lists:all(fun(R) -> Valid(R) =:= error end, Mutations), forged_report_rejected).

reject_row(Row, Example, Directory) ->
    try not examples_row_valid(Row, Example, Directory) catch _:_ -> true end.
