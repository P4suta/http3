#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(PROFILE_PATH, "standards/performance-profile.json").
-define(JSON_REPORT, "build/performance/hot-path-profile.json").
-define(CSV_REPORT, "build/performance/hot-path-profile.csv").

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            _ = case preserves_detailed_report(Reason) of
                true -> detailed_report_preserved;
                false -> try write_runner_failure(Class, Reason, Stacktrace) of
                    ok -> ok
                catch
                    _:_ -> failure_report_unavailable
                end
            end,
            io:format(standard_error,
                      "hot-path profile failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run(["--self-test"]) ->
    self_test();
run([]) ->
    ProfileBytes = read(?PROFILE_PATH),
    Profile = json:decode(ProfileBytes),
    HotPath = maps:get(<<"hot_path_call_profile">>, Profile),
    Signals = maps:get(<<"signals">>, HotPath),
    validate_signals(Signals),
    validate_required_supervised_wait_signals(Signals),
    add_code_paths(),
    Targets = [target(Signal) || Signal <- Signals],
    ensure_modules_loaded(Targets),
    Workload = maps:get(<<"workload">>, HotPath),
    Timeout = maps:get(<<"timeout_milliseconds">>, HotPath),
    Arguments = workload_arguments(Workload),
    Options = #{type => call_count, pattern => Targets, report => return,
                timeout => Timeout},
    {WorkloadResult, RawProfile} = profile_workload(Arguments, Options),
    Results = [signal_result(Signal, RawProfile) || Signal <- Signals],
    WorkloadViolations = workload_violations(WorkloadResult),
    Violations = violations(Results) ++ WorkloadViolations,
    Status = case Violations of [] -> <<"Ready">>; _ -> <<"Failed">> end,
    Report = #{schema => 1, status => Status,
               baseline_date => maps:get(<<"baseline_date">>, Profile),
               otp_release => list_to_binary(erlang:system_info(otp_release)),
               profile_sha256 => hex(crypto:hash(sha256, ProfileBytes)),
               source_sha256 => source_digest(
                                    maps:get(<<"source_files">>, HotPath)),
               workload => workload_report(Workload),
               workload_failure => workload_failure(WorkloadResult),
               signals => Results, violations => Violations},
    write_reports(Report, Results),
    case Violations of
        [] ->
            io:format("hot-path call profile: ~B signals within bounds (~B requests)~n",
                      [length(Results),
                       maps:get(total_requests, maps:get(workload, Report))]),
            ok;
        _ ->
            erlang:error({hot_path_call_regression, Violations})
    end;
run(_) ->
    erlang:error({usage, "[--self-test]"}).

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
    ensure(Signals =/= [], empty_hot_path_signals),
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
        ensure(is_integer(Maximum) andalso Maximum >= Minimum,
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
    case [Samples || {EntryModule, EntryFunction, EntryArity, Samples} <- Entries,
                   EntryModule =:= Module,
                   EntryFunction =:= Function,
                   EntryArity =:= Arity] of
        [] -> 0;
        [Samples] -> sample_count(Samples);
        Duplicate ->
            erlang:error({duplicate_profile_entry,
                          {Module, Function, Arity}, Duplicate})
    end;
raw_count(_Module, _Function, _Arity, Other) ->
    erlang:error({unexpected_tprof_profile, Other}).

sample_count(Samples) ->
    lists:foldl(fun({Process, Calls, Measurement}, Total) ->
        ensure(Calls =:= Measurement,
               {invalid_call_count_measurement, Process, Calls, Measurement}),
        Total + Measurement
    end, 0, Samples).

violations(Results) ->
    [#{id => maps:get(id, Result), calls => maps:get(calls, Result),
       minimum_calls => maps:get(minimum_calls, Result),
       maximum_calls => maps:get(maximum_calls, Result)}
     || Result <- Results, maps:get(status, Result) =:= <<"Failed">>].

workload_violations(nil) -> [];
workload_violations(Other) ->
    [#{id => <<"profile-workload">>, reason => bounded_term(Other)}].

workload_failure(nil) -> null;
workload_failure(Other) -> bounded_term(Other).

write_reports(Report, Results) ->
    ok = filelib:ensure_dir(?JSON_REPORT),
    ok = file:write_file(?JSON_REPORT,
                         [json:encode(Report), <<"\n">>]),
    Header =
        <<"signal,module,function,arity,minimum_calls,maximum_calls,calls,status\n">>,
    Rows = [csv_row(Result) || Result <- Results],
    ok = file:write_file(?CSV_REPORT, [Header, Rows]).

write_runner_failure(Class, Reason, Stacktrace) ->
    ok = filelib:ensure_dir(?JSON_REPORT),
    Report = #{schema => 1, status => <<"Failed">>,
               otp_release => list_to_binary(erlang:system_info(otp_release)),
               runner_error => #{class => atom_to_binary(Class),
                                 reason => bounded_term(Reason),
                                 stacktrace => bounded_term(Stacktrace)}},
    ok = file:write_file(?JSON_REPORT, [json:encode(Report), <<"\n">>]),
    ok = file:write_file(
           ?CSV_REPORT,
           <<"signal,module,function,arity,minimum_calls,maximum_calls,calls,status\nrunner-error,,,,,,,Failed\n">>).

%% run/1 writes the complete per-signal JSON and CSV before raising a bounded
%% regression. Replacing those files with a generic stack trace would destroy
%% the evidence needed to tune or diagnose the failing bounds.
preserves_detailed_report({hot_path_call_regression, Violations})
        when is_list(Violations) -> true;
preserves_detailed_report(_Reason) -> false.

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
    ensure(preserves_detailed_report(
             {hot_path_call_regression, [#{id => <<"fixture">>}]}),
           self_test_preserves_regression_report),
    ensure(not preserves_detailed_report(fixture_runner_failure),
           self_test_replaces_runner_failure_report),
    Profile = json:decode(read(?PROFILE_PATH)),
    ProfileSignals = maps:get(
        <<"signals">>, maps:get(<<"hot_path_call_profile">>, Profile)
    ),
    validate_required_supervised_wait_signals(ProfileSignals),
    io:put_chars("hot-path profile self-test: count extraction and bounds ok\n"),
    ok.

fixture_signal(Id, Function, Minimum, Maximum) ->
    #{<<"id">> => Id, <<"purpose">> => <<"self-test">>,
      <<"module">> => <<"hot_path_fixture">>, <<"function">> => Function,
      <<"arity">> => 1, <<"minimum_calls">> => Minimum,
      <<"maximum_calls">> => Maximum}.

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

bounded_term(Term) ->
    Bytes = unicode:characters_to_binary(io_lib:format("~0P", [Term, 20])),
    case byte_size(Bytes) =< 8192 of
        true -> Bytes;
        false -> <<(binary:part(Bytes, 0, 8192))/binary, "...[truncated]">>
    end.

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
