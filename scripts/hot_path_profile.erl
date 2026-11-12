-module(hot_path_profile).
-export([main/1, measure/1, verify_report/1, bundle_paths/0]).
-compile(nowarn_unused_function).

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-include("process_runner.hrl").
-include("hot_path_evidence.hrl").

-define(PROFILE_PATH, "standards/performance-profile.json").
-define(JSON_REPORT, "build/performance/hot-path-profile.json").
-define(CSV_REPORT, "build/performance/hot-path-profile.csv").
-include("hot_path_tests.hrl").

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            _ = case Arguments of
                [] -> try preserve_execution_failure(Class, Reason, Stacktrace)
                      catch _:_ -> failure_report_unavailable end;
                _ -> ok
            end,
            io:format(standard_error, "hot-path profile failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stacktrace)]),
            halt(1)
    end.

run(["--self-test"]) ->
    self_test();
run(["--invalidate"]) ->
    invalidate_outputs(?JSON_REPORT, ?CSV_REPORT);
run(["--verify"]) -> verify_report(evidence_json_decode(read(?JSON_REPORT)));
run([]) ->
    ok = invalidate_outputs(?JSON_REPORT, ?CSV_REPORT),
    %% Preserve the explicit Failed record while source identity is computed.
    Identity = evidence_identity(),
    write_reports(#{schema => 2, status => <<"Failed">>, shareable => false,
        evidence_identity => Identity, failure => <<"execution_not_completed">>}, []),
    fresh_with_verified_build("http3", fun(Snapshot) ->
        run_profile_locked(Identity, Snapshot)
    end);
run(_) ->
    erlang:error({usage, "[--invalidate|--self-test|--verify]"}).

run_profile_locked(Identity, Snapshot) ->
    Build = maps:get(report, Snapshot),
    ProfileBytes = read(?PROFILE_PATH),
    Profile = evidence_json_decode(ProfileBytes),
    HotPath = maps:get(<<"hot_path_call_profile">>, Profile),
    Signals = maps:get(<<"signals">>, HotPath),
    validate_signals(Signals),
    validate_required_supervised_wait_signals(Signals),
    Workload = maps:get(<<"workload">>, HotPath),
    120000 = maps:get(<<"timeout_milliseconds">>, HotPath),
    Compiled = hpp_compile(), Nonce = hex(crypto:strong_rand_bytes(16)),
    Execution0 = execute_child(HotPath, Compiled, Nonce, 120000),
    Execution = Execution0#{build_identity => Build, runner_sha256 => hpp_digest(Compiled),
        execution_environment => execution_runtime()},
    Child = maps:get(child, Execution),
    Results = [hpp_atom_row(Row) || Row <- maps:get(<<"signals">>, Child, [])],
    Complete = hpp_execution_valid(runtime_matrix_json(Execution), Nonce, Signals, Build,
        hpp_digest(Compiled), execution_runtime()) andalso
        hpp_execution_files_valid(runtime_matrix_json(Execution),Compiled),
    Violations = violations(Results) ++ case Complete of
        true -> []; false -> [#{id => <<"profile-workload">>, reason => <<"owned_execution_incomplete">>}] end,
    Status = case Violations of [] -> <<"Ready">>; _ -> <<"Failed">> end,
    Report0 = #{schema => 2, status => Status, shareable => false,
               baseline_date => maps:get(<<"baseline_date">>, Profile),
               otp_release => list_to_binary(erlang:system_info(otp_release)),
               profile_sha256 => hex(crypto:hash(sha256, ProfileBytes)),
               source_sha256 => source_digest(
                                    maps:get(<<"source_files">>, HotPath)),
               workload => workload_report(Workload),
               workload_failure => maps:get(<<"failure">>, Child, #{classification => <<"invalid_child_schema">>}),
               execution => Execution,
               replay_command => <<"escript scripts/hot_path_profile.escript">>,
               signals => Results, violations => Violations},
    write_reports(Report0#{evidence_identity => Identity}, Results),
    FinalSnapshot = fresh_verify_locked("http3"),
    Build = maps:get(report, FinalSnapshot),
    true = maps:get(sha256, Snapshot) =:= maps:get(sha256, FinalSnapshot),
    Report = evidence_complete(Report0, Identity),
    write_reports(Report, Results),
    case Violations of
        [] ->
            io:format("hot-path call profile: ~B signals within bounds (~B requests)~n",
                      [length(Results),
                       maps:get(total_requests, maps:get(workload, Report))]),
            ok;
        _ ->
            erlang:error({hot_path_call_regression, Violations})
    end.

%% This entry point runs only in the owned VM. tprof records call counts,
%% never call arguments or return values, and the scalar projection discards
%% runtime process identities before returning to the evidence boundary.
measure(HotPath) ->
    Signals = maps:get(<<"signals">>, HotPath),
    validate_signals(Signals), validate_required_supervised_wait_signals(Signals),
    add_code_paths(), Targets = [target(Signal) || Signal <- Signals],
    ensure_modules_loaded(Targets),
    Arguments = workload_arguments(maps:get(<<"workload">>, HotPath)),
    Options = #{type => call_count, pattern => Targets, report => return,
        timeout => maps:get(<<"timeout_milliseconds">>, HotPath)},
    {Result, RawProfile} = profile_workload(Arguments, Options),
    {Result, [signal_result(Signal, RawProfile) || Signal <- Signals]}.

execute_child(HotPath, Compiled, Nonce, Deadline) ->
    Directory = filename:absname("build/performance/hot-path-runner/" ++ binary_to_list(Nonce)),
    ChildPath = filename:join(Directory, "child.json"), ok = filelib:ensure_dir(ChildPath),
    Loads = [begin
        Path = filename:join(Directory, atom_to_list(Module) ++ ".beam"), ok = file:write_file(Path, Bytes, [exclusive]),
        io_lib:format("(fun()->{ok,B}=file:read_file(~0tp),~0tp=crypto:hash(sha256,B),"
            "{module,~p}=code:load_binary(~p,~0tp,B) end)(),",
            [Path, crypto:hash(sha256,Bytes), Module, Module, atom_to_list(Module)++".beam"])
    end || {Module,Bytes} <- Compiled],
    Paths = [Directory | [filename:absname(P)||P<-filelib:wildcard("packages/http3/build/dev/erlang/*/ebin")]],
    Eval = [Loads,io_lib:format("hot_path_child:run(~0tp,~0tp,~0tp).",[HotPath,ChildPath,Nonce])],
    Started = erlang:monotonic_time(millisecond),
    {Exit,Output} = run_child_evaluation(filename:absname("."),Paths,lists:flatten(Eval),Deadline),
    Elapsed = erlang:monotonic_time(millisecond)-Started,
    Child = try evidence_json_decode(runtime_matrix_read(ChildPath,1048576)) catch _:_ -> #{} end,
    Safe = case hpp_child_valid(Child,Nonce,maps:get(<<"signals">>,HotPath)) of
        true -> Child; false -> #{<<"invalid_child_schema">> => true} end,
    ok = file:write_file(ChildPath,[json:encode(Safe),$\n]),
    #{nonce => Nonce, deadline_ms => Deadline, elapsed_ms => Elapsed,
        child => Safe, exit_status => Exit, process => maps:without([tail,output_sha256],Output)}.

verify_report(Report) ->
    ProfileBytes = read(?PROFILE_PATH), Profile = evidence_json_decode(ProfileBytes),
    HotPath = maps:get(<<"hot_path_call_profile">>,Profile), Signals = maps:get(<<"signals">>,HotPath),
    validate_signals(Signals), validate_required_supervised_wait_signals(Signals),
    Build = fresh_verified_report("http3"),
    Compiled = hpp_compile(),
    true = hpp_report_valid(Report, Profile, HotPath, evidence_identity(), Build, hpp_digest(Compiled),
        hex(crypto:hash(sha256,ProfileBytes)), source_digest(maps:get(<<"source_files">>,HotPath))),
    true = hpp_execution_files_valid(maps:get(<<"execution">>,Report),Compiled),
    Rows = [hpp_atom_row(R)||R<-maps:get(<<"signals">>,Report)],
    true = read(?CSV_REPORT) =:= iolist_to_binary([hpp_csv_header(),[csv_row(R)||R<-Rows]]),
    ok.

bundle_paths() ->
    Report = evidence_json_decode(read(?JSON_REPORT)), ok = verify_report(Report),
    Nonce = maps:get(<<"nonce">>,maps:get(<<"execution">>,Report)),
    Directory = "build/performance/hot-path-runner/"++binary_to_list(Nonce),
    [filename:join(Directory,"child.json")|[filename:join(Directory,atom_to_list(M)++".beam")||{M,_}<-hpp_compile()]].

hpp_report_valid(Report, Profile, HotPath, Identity, Build, Digest, ProfileDigest, SourceDigest) ->
    try
        true = suite_exact_keys(Report,[schema,status,shareable,baseline_date,otp_release,profile_sha256,source_sha256,
            workload,workload_failure,execution,replay_command,signals,violations,evidence_identity,execution_environment]),
        2 = maps:get(<<"schema">>,Report), <<"Ready">> = maps:get(<<"status">>,Report),
        false = maps:get(<<"shareable">>,Report), Identity = maps:get(<<"evidence_identity">>,Report),
        Runtime = execution_runtime(), Runtime = maps:get(<<"execution_environment">>,Report),
        true = maps:get(<<"otp_release">>,Report) =:= list_to_binary(erlang:system_info(otp_release)),
        true = maps:get(<<"baseline_date">>,Report) =:= maps:get(<<"baseline_date">>,Profile),
        ProfileDigest = maps:get(<<"profile_sha256">>,Report), SourceDigest = maps:get(<<"source_sha256">>,Report),
        true = maps:get(<<"workload">>,Report) =:= runtime_matrix_json(workload_report(maps:get(<<"workload">>,HotPath))),
        null = maps:get(<<"workload_failure">>,Report), [] = maps:get(<<"violations">>,Report),
        <<"escript scripts/hot_path_profile.escript">> = maps:get(<<"replay_command">>,Report),
        Execution = maps:get(<<"execution">>,Report),
        true = hpp_execution_valid(Execution,maps:get(<<"nonce">>,Execution),maps:get(<<"signals">>,HotPath),Build,Digest,Runtime),
        Rows = maps:get(<<"signals">>,Report), Rows = maps:get(<<"signals">>,maps:get(<<"child">>,Execution)),
        [] = violations([hpp_atom_row(R)||R<-Rows]), true
    catch _:_ -> false end.

hpp_atom_row(Row) -> maps:from_list([{K,maps:get(atom_to_binary(K),Row)}||K<-
    [id,purpose,module,function,arity,minimum_calls,maximum_calls,calls,status]]).

preserve_execution_failure(Class,Reason,Stack) ->
    Previous = evidence_json_decode(read(?JSON_REPORT)),
    ok = file:write_file(?JSON_REPORT,[json:encode(Previous#{<<"status">> => <<"Failed">>,
        <<"runner_failure">> => diagnostic_failure_details(Class,Reason,Stack)}),$\n]).

profile_workload(Arguments, Options) ->
    {ok, RepositoryRoot} = file:get_cwd(),
    PackageRoot = filename:join([RepositoryRoot, "packages", "http3"]),
    ok = file:set_cwd(PackageRoot),
    try
        tprof:profile(http3_benchmark, profile_workload, Arguments, Options)
    after
        ok = file:set_cwd(RepositoryRoot)
    end.

workload_arguments(Workload) ->
    [maps:get(<<"measured_trials">>, Workload),
     maps:get(<<"concurrency">>, Workload),
     maps:get(<<"requests_per_connection">>, Workload),
     maps:get(<<"payload_bytes">>, Workload)].

workload_report(Workload) ->
    Trials = maps:get(<<"measured_trials">>, Workload),
    Concurrency = maps:get(<<"concurrency">>, Workload),
    Requests = maps:get(<<"requests_per_connection">>, Workload),
    Warmups = maps:get(<<"warmup_runs">>, Workload),
    ensure(Warmups =:= 1, {unsupported_profile_warmups, Warmups}),
    #{warmup_runs => Warmups, measured_trials => Trials,
      concurrency => Concurrency, requests_per_connection => Requests,
      payload_bytes => maps:get(<<"payload_bytes">>, Workload),
      total_requests => (Warmups + Trials) * Concurrency * Requests}.

add_code_paths() ->
    Paths = [filename:absname(Path) || Path <-
             filelib:wildcard("packages/http3/build/dev/erlang/*/ebin")],
    ensure(Paths =/= [], missing_http3_build_code_paths),
    lists:foreach(fun(Path) -> true = code:add_patha(Path) end, Paths).

ensure_modules_loaded(Targets) ->
    Modules = lists:usort([Module || {Module, _Function, _Arity} <- Targets]
                          ++ [http3_benchmark]),
    lists:foreach(fun(Module) ->
        case code:ensure_loaded(Module) of
            {module, Module} -> ok;
            Error -> erlang:error({cannot_load_profile_module, Module, Error})
        end
    end, Modules).

validate_signals(Signals) ->
    ensure(is_list(Signals) andalso Signals =/= [] andalso length(Signals) =< 256, empty_hot_path_signals),
    Ids = [maps:get(<<"id">>, Signal) || Signal <- Signals],
    ensure(length(Ids) =:= length(lists:usort(Ids)),
           duplicate_hot_path_signal_id),
    Targets = [target(Signal) || Signal <- Signals],
    ensure(length(Targets) =:= length(lists:usort(Targets)),
           duplicate_hot_path_target),
    lists:foreach(fun(Signal) ->
        Minimum = maps:get(<<"minimum_calls">>, Signal),
        Maximum = maps:get(<<"maximum_calls">>, Signal),
        ensure(is_integer(Minimum) andalso Minimum >= 0,
               {invalid_minimum_calls, maps:get(<<"id">>, Signal), Minimum}),
        ensure(hpp_count(Maximum) andalso Maximum >= Minimum,
               {invalid_maximum_calls, maps:get(<<"id">>, Signal), Maximum})
    end, Signals).

validate_required_supervised_wait_signals(Signals) ->
    lists:foreach(fun({Id, Module, Function, Arity, Minimum, Maximum}) ->
        case [Signal || Signal <- Signals,
                        maps:get(<<"id">>, Signal) =:= Id] of
            [Signal] ->
                Actual = {maps:get(<<"module">>, Signal),
                          maps:get(<<"function">>, Signal),
                          maps:get(<<"arity">>, Signal),
                          maps:get(<<"minimum_calls">>, Signal),
                          maps:get(<<"maximum_calls">>, Signal)},
                Expected = {Module, Function, Arity, Minimum, Maximum},
                ensure(Actual =:= Expected,
                       {supervised_wait_signal_drift, Id,
                        expected, Expected, actual, Actual});
            [] -> erlang:error({missing_supervised_wait_signal, Id});
            _ -> erlang:error({duplicate_supervised_wait_signal, Id})
        end
    end, required_supervised_wait_signal_specs()).

required_supervised_wait_signal_specs() ->
    [{<<"supervised-server-connection-waits">>,
      <<"quic_core@server">>, <<"accept_next">>, 1, 8, 16},
     {<<"retired-finite-server-connection-waits">>,
      <<"quic_core@server">>, <<"accept">>, 1, 0, 0},
     {<<"supervised-client-stream-admission-waits">>,
      <<"quic_core@client">>, <<"accept_stream_next">>, 1, 40, 40},
     {<<"supervised-client-stream-read-waits">>,
      <<"quic_core@client">>, <<"receive_next">>, 2, 40, 900},
     {<<"default-disabled-client-datagram-waits">>,
      <<"quic_core@client">>, <<"receive_datagram_next">>, 1, 0, 0},
     {<<"supervised-client-ticket-waits">>,
      <<"quic_core@client">>, <<"resumption_ticket_next">>, 1, 10, 10},
     {<<"retired-finite-client-stream-admission-waits">>,
      <<"quic_core@client">>, <<"accept_stream">>, 1, 0, 0},
     {<<"retired-finite-client-stream-read-waits">>,
      <<"quic_core@client">>, <<"receive">>, 2, 0, 0},
     {<<"retired-finite-client-datagram-waits">>,
      <<"quic_core@client">>, <<"receive_datagram">>, 1, 0, 0},
     {<<"retired-finite-client-ticket-waits">>,
      <<"quic_core@client">>, <<"resumption_ticket">>, 1, 0, 0},
     {<<"supervised-server-stream-admission-waits">>,
      <<"quic_core@server">>, <<"accept_stream_next">>, 1, 240, 240},
     {<<"supervised-server-stream-read-waits">>,
      <<"quic_core@server">>, <<"receive_next">>, 2, 240, 900},
     {<<"default-disabled-server-datagram-waits">>,
      <<"quic_core@server">>, <<"receive_datagram_next">>, 1, 0, 0},
     {<<"retired-finite-server-stream-admission-waits">>,
      <<"quic_core@server">>, <<"accept_stream">>, 1, 0, 0},
     {<<"retired-finite-server-stream-read-waits">>,
      <<"quic_core@server">>, <<"receive">>, 2, 0, 0},
     {<<"retired-finite-server-datagram-waits">>,
      <<"quic_core@server">>, <<"receive_datagram">>, 1, 0, 0}].

target(Signal) ->
    Module = binary_to_atom(maps:get(<<"module">>, Signal)),
    Function = binary_to_atom(maps:get(<<"function">>, Signal)),
    Arity = maps:get(<<"arity">>, Signal),
    ensure(is_integer(Arity) andalso Arity >= 0,
           {invalid_signal_arity, maps:get(<<"id">>, Signal), Arity}),
    {Module, Function, Arity}.

signal_result(Signal, RawProfile) ->
    {Module, Function, Arity} = target(Signal),
    Calls = raw_count(Module, Function, Arity, RawProfile),
    Minimum = maps:get(<<"minimum_calls">>, Signal),
    Maximum = maps:get(<<"maximum_calls">>, Signal),
    Status = case Calls >= Minimum andalso Calls =< Maximum of
        true -> <<"Ready">>;
        false -> <<"Failed">>
    end,
    #{id => maps:get(<<"id">>, Signal),
      purpose => maps:get(<<"purpose">>, Signal),
      module => maps:get(<<"module">>, Signal),
      function => maps:get(<<"function">>, Signal), arity => Arity,
      minimum_calls => Minimum, maximum_calls => Maximum,
      calls => Calls, status => Status}.

raw_count(Module, Function, Arity, {call_count, Entries}) ->
    ensure(is_list(Entries) andalso length(Entries) =< 256, profile_entry_limit),
    case [Samples || {EntryModule, EntryFunction, EntryArity, Samples} <- Entries,
                   EntryModule =:= Module,
                   EntryFunction =:= Function,
                   EntryArity =:= Arity] of
        [] -> 0;
        [Samples] -> sample_count(Samples);
        _ -> erlang:error(duplicate_profile_entry)
    end;
raw_count(_Module, _Function, _Arity, _Other) ->
    erlang:error(unexpected_tprof_profile).

sample_count(Samples) ->
    ensure(is_list(Samples) andalso length(Samples) =< 16384, profile_counter_limit),
    lists:foldl(fun({_Process, Calls, Measurement}, Total) ->
        ensure(hpp_count(Calls) andalso Calls =:= Measurement,
               invalid_call_count_measurement),
        Next = Total + Measurement, ensure(hpp_count(Next), profile_counter_limit), Next
    end, 0, Samples).

violations(Results) ->
    [#{id => maps:get(id, Result), calls => maps:get(calls, Result),
       minimum_calls => maps:get(minimum_calls, Result),
       maximum_calls => maps:get(maximum_calls, Result)}
     || Result <- Results, maps:get(status, Result) =:= <<"Failed">>].

workload_violations(nil) -> [];
workload_violations(Other) ->
    [#{id => <<"profile-workload">>, reason => diagnostic_failure_category(Other)}].

workload_failure(nil) -> null;
workload_failure(Other) -> diagnostic_failure_details(error, Other, []).

write_reports(Report, Results) ->
    ok = filelib:ensure_dir(?JSON_REPORT),
    ok = file:write_file(?JSON_REPORT,
                         [json:encode(Report), <<"\n">>]),
    Header = hpp_csv_header(),
    Rows = [csv_row(Result) || Result <- Results],
    ok = file:write_file(?CSV_REPORT, [Header, Rows]).

invalidate_outputs(JsonPath, CsvPath) ->
    ok = filelib:ensure_dir(JsonPath),
    Failed = #{schema => 2, status => <<"Failed">>, shareable => false,
        failure => <<"execution_not_completed">>},
    ok = file:write_file(JsonPath, [json:encode(Failed), <<"\n">>]),
    ok = file:write_file(CsvPath, hpp_csv_header()),
    ok.

hpp_csv_header() -> <<"signal,module,function,arity,minimum_calls,maximum_calls,calls,status\n">>.

csv_row(Result) ->
    io_lib:format("~s,~s,~s,~B,~B,~B,~B,~s~n",
                  [maps:get(id, Result), maps:get(module, Result),
                   maps:get(function, Result), maps:get(arity, Result),
                   maps:get(minimum_calls, Result),
                   maps:get(maximum_calls, Result), maps:get(calls, Result),
                   maps:get(status, Result)]).

source_digest(Paths) ->
    Entries = [{Path, read(binary_to_list(Path))} || Path <- Paths],
    hex(crypto:hash(sha256, term_to_binary(Entries))).

self_test() ->
    ok = invalidation_self_test(),
    Secret = <<"private-profile-regression-sentinel">>,
    Failure = #{credential => Secret, body => Secret, process => self()},
    FailureReport = iolist_to_binary(json:encode(#{
        failure => workload_failure(Failure),
        violations => workload_violations(Failure)})),
    PrivatePresent = binary:match(FailureReport, Secret) =/= nomatch,
    io:format("profile_failure private_value_present=~p~n", [PrivatePresent]),
    ensure(not PrivatePresent, private_workload_failure),
    Hit = fixture_signal(<<"hit">>, <<"hit">>, 2, 3),
    Missing = fixture_signal(<<"missing">>, <<"missing">>, 0, 0),
    TooMany = fixture_signal(<<"too-many">>, <<"too_many">>, 0, 2),
    Signals = [Hit, Missing, TooMany],
    validate_signals(Signals),
    Raw = {call_count,
           [{hot_path_fixture, hit, 1, [{all, 3, 3}]},
            {hot_path_fixture, too_many, 1, [{all, 3, 3}]}]},
    Results = [signal_result(Signal, Raw) || Signal <- Signals],
    [HitResult, MissingResult, TooManyResult] = Results,
    ensure(maps:get(calls, HitResult) =:= 3, self_test_hit_count),
    ensure(maps:get(calls, MissingResult) =:= 0, self_test_missing_zero),
    ensure(maps:get(status, HitResult) =:= <<"Ready">>, self_test_hit_status),
    ensure(maps:get(status, MissingResult) =:= <<"Ready">>,
           self_test_missing_status),
    ensure(maps:get(status, TooManyResult) =:= <<"Failed">>,
           self_test_failure_status),
    [Violation] = violations(Results),
    ensure(maps:get(id, Violation) =:= <<"too-many">>,
           self_test_violation_identity),
    [] = workload_violations(nil),
    [WorkloadViolation] = workload_violations({'EXIT', fixture_failure}),
    ensure(maps:get(id, WorkloadViolation) =:= <<"profile-workload">>,
           self_test_workload_violation),
    CounterFailure = try sample_count([{self(), Secret, Secret}]) of
        _ -> false
    catch error:invalid_call_count_measurement -> true end,
    ensure(CounterFailure, self_test_private_counter_rejection),
    Profile = json:decode(read(?PROFILE_PATH)),
    ProfileSignals = maps:get(
        <<"signals">>, maps:get(<<"hot_path_call_profile">>, Profile)
    ),
    validate_required_supervised_wait_signals(ProfileSignals),
    hpp_adversarial_self_test(),
    hpp_owned_self_test(),
    io:put_chars("hot-path profile self-test: count extraction and bounds ok\n"),
    ok.

invalidation_self_test() ->
    Stem = filename:absname("build/diagnostics/hot-path-fixtures/invalidate-" ++
        binary_to_list(hex(crypto:strong_rand_bytes(16)))),
    JsonPath = Stem ++ ".json", CsvPath = Stem ++ ".csv",
    Marker = <<"private-stale-hot-path-marker">>,
    ok = filelib:ensure_dir(JsonPath),
    ok = file:write_file(JsonPath, Marker), ok = file:write_file(CsvPath, Marker),
    ok = invalidate_outputs(JsonPath, CsvPath),
    Failed = evidence_json_decode(read(JsonPath)),
    <<"Failed">> = maps:get(<<"status">>, Failed),
    nomatch = binary:match(iolist_to_binary(json:encode(Failed)), Marker),
    true = read(CsvPath) =:= hpp_csv_header(),
    ok.

fixture_signal(Id, Function, Minimum, Maximum) ->
    #{<<"id">> => Id, <<"purpose">> => <<"self-test">>,
      <<"module">> => <<"hot_path_fixture">>, <<"function">> => Function,
      <<"arity">> => 1, <<"minimum_calls">> => Minimum,
      <<"maximum_calls">> => Maximum}.

read(Path) ->
    runtime_matrix_read(Path,16777216).

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
