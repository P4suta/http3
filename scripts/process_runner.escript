#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("process_runner.hrl").
-include("diagnostic_failure.hrl").
-include("diagnostic_assertion_tests.hrl").

main(["--runtime-identity-self-test"]) ->
    try runtime_identity_self_test()
    catch Class:Reason:Stack ->
        io:format(standard_error, "runtime identity failed: ~p~n",
            [diagnostic_failure_details(Class, Reason, Stack)]), halt(1)
    end;
main(["--self-test"]) ->
    try self_test() of
        ok -> io:format("process runner self-test ok~n")
    catch Class:Reason:Stack ->
        io:format(standard_error, "process runner failed: ~p~n",
                  [diagnostic_failure_details(Class, Reason, Stack)]),
        halt(1)
    end;
main(["--assertion-self-test"]) ->
    try diagnostic_assertion_self_test()
    catch Class:Reason:Stack ->
        io:format(standard_error, "assertion contract failed: ~p~n",
            [diagnostic_failure_details(Class, Reason, Stack)]), halt(1)
    end;
main(["--console-self-test"]) ->
    try console_boundary_self_test() of
        ok -> io:format("process console boundary self-test ok~n")
    catch Class:Reason:Stack ->
        io:format(standard_error, "process console boundary failed: ~p~n",
            [diagnostic_failure_details(Class, Reason, Stack)]), halt(1)
    end;
main(["--eof-self-test"]) ->
    case supervisor_parent_eof_control() of
        true -> io:format("supervisor parent EOF self-test ok~n");
        false -> halt(1)
    end;
main(["--windows-entry-contract-self-test"]) ->
    try windows_entry_contract_self_test() of
        ok -> io:format("windows headless entry contract self-test ok~n")
    catch Class:Reason:Stack ->
        io:format(standard_error, "windows entry contract failed: ~p~n",
            [diagnostic_failure_details(Class, Reason, Stack)]), halt(1)
    end;
main(["--windows-entry" | Arguments]) ->
    windows_entry_main(Arguments);
main(_) -> halt(2).

%% This is the only public Windows execution surface. Its grammar is closed:
%% callers select a repository operation, never an executable, path, module,
%% argument vector, environment override, deadline, or output limit.
windows_entry_main(Arguments) ->
    ok = file:set_cwd(filename:dirname(filename:dirname(
        filename:absname(escript:script_name())))),
    Request = windows_entry_request(Arguments),
    RuntimeOtp = windows_entry_runtime_otp(),
    Report = case os:type() of
        {win32, _} -> windows_entry_execute(Request, RuntimeOtp);
        _ -> windows_entry_failed_report(
            Request, RuntimeOtp, <<"unsupported_platform">>,
            windows_entry_runtime_identity(Request, RuntimeOtp))
    end,
    io:format("~s~n", [json:encode(Report)]),
    case maps:get(passed, Report) of true -> ok; false -> halt(1) end.

windows_entry_request(["fresh-build", Target])
  when Target =:= "all"; Target =:= "http"; Target =:= "http3";
       Target =:= "core" ->
    #{operation => <<"fresh-build">>, target => list_to_binary(Target),
      platform => <<"windows-2025">>, requested_otp => <<"current">>,
      deadline_milliseconds => 570000,
      steps => [{fresh_build, bash, "scripts/fresh_build.sh", [Target]}]};
windows_entry_request(["package-suite", Target])
  when Target =:= "http"; Target =:= "http3"; Target =:= "core" ->
    #{operation => <<"package-suite">>, target => list_to_binary(Target),
      platform => <<"windows-2025">>, requested_otp => <<"current">>,
      deadline_milliseconds => 1170000,
      steps => [
        {canonical_etf_wire_self_test, escript,
         "scripts/canonical_etf_wire_self_test.escript", []},
        {etf_boundary_audit_self_test, escript,
         "scripts/etf_boundary_audit.escript", ["--self-test"]},
        {etf_boundary_audit, escript,
         "scripts/etf_boundary_audit.escript",
         ["matrix", runtime_package, "windows-2025", runtime_otp]},
        {windows_console_inheritance_audit, powershell,
         "scripts/windows_console_inheritance_audit.ps1",
         ["-OtpMajor", runtime_otp]},
        {package_suite, escript, "scripts/package_suite.escript", [Target]}
      ]};
windows_entry_request(["runtime-stage", Target, "windows-2025", Otp])
  when (Target =:= "http" orelse Target =:= "http3" orelse Target =:= "core")
       andalso (Otp =:= "28" orelse Otp =:= "29") ->
    #{operation => <<"runtime-stage">>, target => list_to_binary(Target),
      platform => <<"windows-2025">>, requested_otp => list_to_binary(Otp),
      deadline_milliseconds => 120000,
      steps => [{runtime_stage, escript, "scripts/runtime_matrix.escript",
                 ["stage", Target, "windows-2025", Otp]}]};
windows_entry_request(["credential-local"]) ->
    %% Keep this sequence here rather than delegating back through mise. That
    %% prevents recursive task expansion and puts all three native trees under
    %% the same finite entry contract.
    #{operation => <<"credential-local">>, target => <<"none">>,
      platform => <<"windows-2025">>, requested_otp => <<"current">>,
      deadline_milliseconds => 3450000,
      steps => [
        {credential_self_test, escript, "scripts/test_matrix.escript",
         ["--self-test"]},
        {credential_fresh_build, bash, "scripts/fresh_build.sh", ["all"]},
        {credential_matrix, escript, "scripts/test_matrix.escript",
         ["credential-local"]}
      ]};
windows_entry_request(_) -> erlang:error(invalid_windows_entry_arguments).

windows_entry_runtime_otp() ->
    Otp = unicode:characters_to_binary(erlang:system_info(otp_release)),
    case Otp of
        <<"28">> -> Otp;
        <<"29">> -> Otp;
        _ -> <<"unsupported">>
    end.

windows_entry_configured_otp() ->
    windows_entry_configured_otp(os:getenv("MISE_ERLANG_VERSION")).

windows_entry_configured_otp(false) -> current;
windows_entry_configured_otp(Value) when is_list(Value) ->
    case re:run(Value, "^(28|29)(?:\\.[0-9]+){0,3}$",
                [{capture, [1], list}]) of
        {match, [Major]} -> list_to_binary(Major);
        nomatch -> unsupported
    end.

windows_entry_execute(Request, RuntimeOtp) ->
    RequestedOtp = maps:get(requested_otp, Request),
    ConfiguredOtp = windows_entry_configured_otp(),
    Identity = windows_entry_runtime_identity(Request, RuntimeOtp),
    EnvironmentPlatform = case os:getenv("QUALIFICATION_PLATFORM") of
        false -> <<"windows-2025">>;
        Value -> unicode:characters_to_binary(Value)
    end,
    EnvironmentValid = EnvironmentPlatform =:= <<"windows-2025">>,
    OtpValid = RuntimeOtp =/= <<"unsupported">> andalso
        (RequestedOtp =:= <<"current">> orelse RequestedOtp =:= RuntimeOtp)
        andalso ConfiguredOtp =:= RuntimeOtp,
    IdentityValid = maps:get(verified, Identity),
    case EnvironmentValid andalso OtpValid andalso IdentityValid of
        false -> windows_entry_failed_report(
            Request, RuntimeOtp, <<"runtime_identity_mismatch">>, Identity);
        true ->
            Deadline = erlang:monotonic_time(millisecond) +
                maps:get(deadline_milliseconds, Request),
            {Results, Failure} = windows_entry_run_steps(
                windows_entry_bind_steps(
                    maps:get(steps, Request), Request, RuntimeOtp),
                Deadline, [], none),
            windows_entry_report(
                Request, RuntimeOtp, Failure, Results, Identity)
    end.

windows_entry_bind_steps(Steps, Request, RuntimeOtp) ->
    [{Name, Kind, Script,
      [windows_entry_bind_argument(Argument, Request, RuntimeOtp) ||
          Argument <- Arguments]}
     || {Name, Kind, Script, Arguments} <- Steps].

windows_entry_bind_argument(runtime_otp, _Request, RuntimeOtp) ->
    binary_to_list(RuntimeOtp);
windows_entry_bind_argument(runtime_package, Request, _RuntimeOtp) ->
    case maps:get(target, Request) of
        <<"core">> -> "quic_core";
        Target -> binary_to_list(Target)
    end;
windows_entry_bind_argument(Argument, _Request, _RuntimeOtp) -> Argument.

%% Every independent step is attempted while the shared absolute deadline has
%% budget. A failed audit therefore cannot hide a later package or credential
%% result. Once the deadline is exhausted, every remaining step is represented
%% by an explicit typed, non-passing result.
windows_entry_run_steps([], _Deadline, Acc, Failure) ->
    {lists:reverse(Acc), Failure};
windows_entry_run_steps([Step | Rest], Deadline, Acc, PriorFailure) ->
    Result = windows_entry_run_step(Step, Deadline),
    Failure = case {PriorFailure, maps:get(passed, Result)} of
        {none, false} -> maps:get(failure_code, Result);
        _ -> PriorFailure
    end,
    windows_entry_run_steps(Rest, Deadline, [Result | Acc], Failure).

windows_entry_run_step({Name, Kind, RelativeScript, Arguments}, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true -> windows_entry_unstarted_step(Name, <<"deadline_exceeded">>);
        false ->
            try run_process_runner_worker(fun() ->
                windows_entry_run_step_owned(
                    Name, Kind, RelativeScript, Arguments, Deadline)
            end, Remaining) of
                Result -> Result
            catch _Class:Reason:_Stack ->
                windows_entry_unstarted_step(
                    Name, windows_entry_exception_code(Reason))
            end
    end.

windows_entry_run_step_owned(Name, Kind, RelativeScript, Arguments,
                             Deadline) ->
    Script = filename:absname(RelativeScript),
    Snapshot = process_file_snapshot(Script, 2097152),
    Executable = windows_entry_executable(Kind),
    ChildArguments = windows_entry_child_arguments(Kind, Script, Arguments),
    Environment = [{"ERL_AFLAGS", false}, {"ERL_FLAGS", false},
                   {"ERL_ZFLAGS", false},
                   {"ERL_CRASH_DUMP_BYTES", "0"},
                   {"ERL_CRASH_DUMP_SECONDS", "0"} |
                   windows_entry_identity_environment()],
    {Port, Identity} = open_owned_process(
        Executable, ChildArguments, filename:absname("."), Environment,
        Deadline),
    put(windows_entry_owned_port, {Port, Identity}),
    try
        {Status, Output} = collect_eunit(Port, new_output(Identity), Deadline),
        ok = unregister_owned_tree(Port),
        erase(windows_entry_owned_port),
        ok = process_verify_snapshot(Snapshot, 2097152),
        windows_entry_step_report(Name, Status, Output)
    after
        windows_entry_cleanup_owned_port()
    end.

windows_entry_identity_environment() ->
    Names = ["HTTP_WINDOWS_EXPECTED_OTP", "HTTP_WINDOWS_ESCRIPT_SHA256",
             "HTTP_WINDOWS_ESCRIPT_PATH_ID", "HTTP_WINDOWS_RUNNER_SHA256",
             "HTTP_WINDOWS_CONFIGURATION_SHA256", "MISE_ERLANG_VERSION",
             "QUALIFICATION_PLATFORM"],
    [{Name, os:getenv(Name)} || Name <- Names, os:getenv(Name) =/= false].

windows_entry_cleanup_owned_port() ->
    case erase(windows_entry_owned_port) of
        {Port, Identity} ->
            _ = try kill_owned_child(Port) catch _:_ -> false end,
            _ = try await_child_exit(Port, new_output(Identity),
                    erlang:monotonic_time(millisecond) + 5000)
                catch _:_ -> {pending, undefined} end,
            unregister_owned_tree(Port);
        _ -> ok
    end.

windows_entry_executable(escript) ->
    Name = case os:type() of {win32, _} -> "escript.exe"; _ -> "escript" end,
    windows_entry_regular_executable(filename:join([code:root_dir(), "bin", Name]),
                                     ["escript", "escript.exe"]);
windows_entry_executable(powershell) ->
    Candidate = case os:find_executable("pwsh.exe") of
        false -> os:find_executable("pwsh");
        Found -> Found
    end,
    windows_entry_regular_executable(Candidate, ["pwsh", "pwsh.exe"]);
windows_entry_executable(bash) ->
    Candidate = case os:getenv("HTTP_BASH_EXECUTABLE") of
        Override when is_list(Override), Override =/= [] -> Override;
        _ -> case os:find_executable("bash.exe") of
            false -> os:find_executable("bash");
            Found -> Found
        end
    end,
    windows_entry_regular_executable(Candidate, ["bash", "bash.exe"]).

windows_entry_child_arguments(powershell, Script, Arguments) ->
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", Script |
     Arguments];
windows_entry_child_arguments(_Kind, Script, Arguments) ->
    [Script | Arguments].

windows_entry_regular_executable(false, _Names) ->
    erlang:error(windows_entry_runtime_missing);
windows_entry_regular_executable(Candidate, Names) when is_list(Candidate) ->
    Path = filename:absname(Candidate),
    Leaf = string:lowercase(filename:basename(Path)),
    case lists:member(Leaf, Names) andalso filelib:is_regular(Path) of
        true -> Path;
        false -> erlang:error(windows_entry_runtime_missing)
    end.

windows_entry_step_report(Name, Status, Output) ->
    Attested = process_completion_attestation_verified(Output),
    Passed = process_status_verified(Status, 0, Output),
    Failure = case Passed of
        true -> <<"none">>;
        false -> windows_entry_process_failure(Status, Output, Attested)
    end,
    #{step => windows_entry_step_name(Name),
      exit_status => windows_entry_exit_status(Status),
      completed => Attested,
      passed => Passed,
      failure_code => Failure,
      tree_empty => maps:get(native_tree_empty, Output, false),
      console_isolated => maps:get(native_console_isolated, Output, false),
      descendant_outlived => maps:get(native_descendant_outlived, Output, true),
      termination_requested => maps:get(
          native_termination_requested, Output, false),
      output_limit_exceeded => maps:get(output_limit_exceeded, Output, true),
      timed_out => maps:get(timed_out, Output, true)}.

windows_entry_unstarted_step(Name, Failure) ->
    #{step => windows_entry_step_name(Name), exit_status => -1,
      completed => false, passed => false, failure_code => Failure,
      tree_empty => false, console_isolated => false,
      descendant_outlived => false, termination_requested => false,
      output_limit_exceeded => false, timed_out => false}.

windows_entry_step_name(fresh_build) -> <<"fresh_build">>;
windows_entry_step_name(canonical_etf_wire_self_test) ->
    <<"canonical_etf_wire_self_test">>;
windows_entry_step_name(etf_boundary_audit_self_test) ->
    <<"etf_boundary_audit_self_test">>;
windows_entry_step_name(etf_boundary_audit) -> <<"etf_boundary_audit">>;
windows_entry_step_name(windows_console_inheritance_audit) ->
    <<"windows_console_inheritance_audit">>;
windows_entry_step_name(package_suite) -> <<"package_suite">>;
windows_entry_step_name(runtime_stage) -> <<"runtime_stage">>;
windows_entry_step_name(credential_self_test) -> <<"credential_self_test">>;
windows_entry_step_name(credential_fresh_build) ->
    <<"credential_fresh_build">>;
windows_entry_step_name(credential_matrix) -> <<"credential_matrix">>.

windows_entry_exit_status(Status)
  when is_integer(Status), Status >= 0, Status =< 255 -> Status;
windows_entry_exit_status(_) -> -1.

windows_entry_process_failure(124, Output, _Attested) ->
    case process_deadline_verified(124, Output) of
        true -> <<"deadline_exceeded">>;
        false -> <<"cleanup_unconfirmed">>
    end;
windows_entry_process_failure(125, Output, _Attested) ->
    case process_output_limit_verified(125, Output) of
        true -> <<"output_limit_exceeded">>;
        false -> <<"cleanup_unconfirmed">>
    end;
windows_entry_process_failure(_Status, _Output, false) ->
    <<"cleanup_unconfirmed">>;
windows_entry_process_failure(_Status, _Output, true) -> <<"child_failed">>.

windows_entry_exception_code(process_runner_worker_timeout) ->
    <<"deadline_exceeded">>;
windows_entry_exception_code(child_exit_unconfirmed) ->
    <<"cleanup_unconfirmed">>;
windows_entry_exception_code(process_supervisor_start_unconfirmed) ->
    <<"startup_unconfirmed">>;
windows_entry_exception_code(process_supervisor_runtime_missing) ->
    <<"runtime_missing">>;
windows_entry_exception_code(windows_entry_runtime_missing) ->
    <<"runtime_missing">>;
windows_entry_exception_code(_) -> <<"launcher_failed">>.

windows_entry_report(Request, RuntimeOtp, Failure, Results, Identity) ->
    Configured = length(maps:get(steps, Request)),
    Completed = length([ok || Result <- Results,
        maps:get(completed, Result, false)]),
    AllTreeEmpty = length(Results) =:= Configured andalso
        lists:all(fun(Result) -> maps:get(tree_empty, Result, false) end,
                  Results),
    AllConsoleIsolated = length(Results) =:= Configured andalso
        lists:all(fun(Result) ->
            maps:get(console_isolated, Result, false)
        end, Results),
    DescendantsJoined = AllTreeEmpty andalso lists:all(fun(Result) ->
        not maps:get(descendant_outlived, Result, true)
    end, Results),
    Passed = Failure =:= none andalso Completed =:= Configured andalso
        AllTreeEmpty andalso AllConsoleIsolated andalso DescendantsJoined andalso
        lists:all(fun(Result) -> maps:get(passed, Result, false) end, Results),
    #{schema => 1, report_kind => <<"windows_headless_entry">>,
      operation => maps:get(operation, Request),
      target => maps:get(target, Request),
      platform => maps:get(platform, Request), otp => RuntimeOtp,
      state => case Passed of true -> <<"Ready">>; false -> <<"Failed">> end,
      failure_code => case Passed of
          true -> <<"none">>;
          false when is_binary(Failure) -> Failure;
          false -> <<"launcher_failed">>
      end,
      scope => windows_entry_scope(Request),
      source_sha256 => maps:get(source_sha256, Identity),
      configuration_sha256 => maps:get(configuration_sha256, Identity),
      tool_sha256 => maps:get(tool_sha256, Identity),
      runtime_identity_verified => maps:get(verified, Identity),
      rerun_command => windows_entry_rerun_command(Request, RuntimeOtp),
      configured_steps => Configured, completed_steps => Completed,
      all_tree_empty => AllTreeEmpty,
      all_console_isolated => AllConsoleIsolated,
      descendants_joined => DescendantsJoined,
      steps => Results, passed => Passed}.

windows_entry_failed_report(Request, RuntimeOtp, Failure, Identity) ->
    Results = [windows_entry_unstarted_step(Name, Failure) ||
        {Name, _Kind, _Script, _Arguments} <- maps:get(steps, Request)],
    windows_entry_report(Request, RuntimeOtp, Failure, Results, Identity).

windows_entry_runtime_identity(Request, RuntimeOtp) ->
    Source = bounded_file_sha256(
        filename:absname(escript:script_name()), 2097152),
    ToolPath = windows_entry_executable(escript),
    Tool = bounded_file_sha256(ToolPath, 134217728),
    ToolPathIdentity = binary:encode_hex(crypto:hash(sha256,
        unicode:characters_to_binary(windows_entry_normal_path(ToolPath))),
        lowercase),
    Configuration = binary:encode_hex(crypto:hash(sha256,
        windows_entry_configuration_material(Request, RuntimeOtp)), lowercase),
    ExpectedSource = windows_entry_expected_sha256(
        os:getenv("HTTP_WINDOWS_RUNNER_SHA256")),
    ExpectedTool = windows_entry_expected_sha256(
        os:getenv("HTTP_WINDOWS_ESCRIPT_SHA256")),
    ExpectedToolPath = windows_entry_expected_sha256(
        os:getenv("HTTP_WINDOWS_ESCRIPT_PATH_ID")),
    ExpectedConfiguration = windows_entry_expected_sha256(
        os:getenv("HTTP_WINDOWS_CONFIGURATION_SHA256")),
    ExpectedOtp = case os:getenv("HTTP_WINDOWS_EXPECTED_OTP") of
        "28" -> <<"28">>;
        "29" -> <<"29">>;
        _ -> <<"unsupported">>
    end,
    #{source_sha256 => Source, tool_sha256 => Tool,
      configuration_sha256 => Configuration,
      verified => Source =:= ExpectedSource andalso Tool =:= ExpectedTool
          andalso ToolPathIdentity =:= ExpectedToolPath
          andalso Configuration =:= ExpectedConfiguration
          andalso RuntimeOtp =:= ExpectedOtp}.

windows_entry_expected_sha256(Value) when is_list(Value), length(Value) =:= 64 ->
    Binary = unicode:characters_to_binary(Value),
    case re:run(Binary, <<"^[0-9a-f]{64}$">>, [{capture, none}]) of
        match -> Binary;
        nomatch -> <<"invalid">>
    end;
windows_entry_expected_sha256(_) -> <<"invalid">>.

windows_entry_normal_path(Path) ->
    lists:flatten(string:replace(string:lowercase(filename:absname(Path)),
                                 "\\", "/", all)).

windows_entry_configuration_material(Request, RuntimeOtp) ->
    iolist_to_binary([<<"windows-entry-v1|">>, maps:get(operation, Request),
        <<"|">>, maps:get(target, Request), <<"|windows-2025|">>, RuntimeOtp]).

windows_entry_scope(Request) ->
    iolist_to_binary([maps:get(operation, Request), <<":">>,
        maps:get(target, Request), <<":windows-2025">>]).

windows_entry_rerun_command(Request, RuntimeOtp) ->
    case maps:get(operation, Request) of
        <<"fresh-build">> -> iolist_to_binary([
            <<"mise run windows-fresh-build -- -Target ">>,
            maps:get(target, Request)]);
        <<"package-suite">> -> iolist_to_binary([
            <<"mise run windows-package-suite -- -Target ">>,
            maps:get(target, Request)]);
        <<"runtime-stage">> -> iolist_to_binary([
            <<"mise run windows-runtime-stage -- -Target ">>,
            maps:get(target, Request),
            <<" -Platform windows-2025 -Otp ">>, RuntimeOtp]);
        <<"credential-local">> -> <<"mise run windows-credential-local">>
    end.

windows_entry_contract_self_test() ->
    current = windows_entry_configured_otp(false),
    <<"28">> = windows_entry_configured_otp("28"),
    <<"29">> = windows_entry_configured_otp("29.0.5"),
    unsupported = windows_entry_configured_otp("30"),
    unsupported = windows_entry_configured_otp("28.secret"),
    #{operation := <<"fresh-build">>, target := <<"all">>, steps := [_]} =
        windows_entry_request(["fresh-build", "all"]),
    #{operation := <<"package-suite">>, target := <<"http3">>, steps := [
        {canonical_etf_wire_self_test, escript,
         "scripts/canonical_etf_wire_self_test.escript", []},
        {etf_boundary_audit_self_test, escript,
         "scripts/etf_boundary_audit.escript", ["--self-test"]},
        {etf_boundary_audit, escript,
         "scripts/etf_boundary_audit.escript",
         ["matrix", runtime_package, "windows-2025", runtime_otp]},
        {windows_console_inheritance_audit, powershell,
         "scripts/windows_console_inheritance_audit.ps1",
         ["-OtpMajor", runtime_otp]},
        {package_suite, escript, "scripts/package_suite.escript", ["http3"]}
      ]} =
        windows_entry_request(["package-suite", "http3"]),
    CoreRequest = windows_entry_request(["package-suite", "core"]),
    [_, _, {etf_boundary_audit, escript,
            "scripts/etf_boundary_audit.escript",
            ["matrix", "quic_core", "windows-2025", "29"]},
     {windows_console_inheritance_audit, powershell,
      "scripts/windows_console_inheritance_audit.ps1",
      ["-OtpMajor", "29"]}, _] = windows_entry_bind_steps(
        maps:get(steps, CoreRequest), CoreRequest, <<"29">>),
    #{operation := <<"runtime-stage">>, requested_otp := <<"28">>,
      steps := [_]} = windows_entry_request(
        ["runtime-stage", "core", "windows-2025", "28"]),
    #{operation := <<"credential-local">>, steps := [_, _, _]} =
        windows_entry_request(["credential-local"]),
    Invalid = [["fresh-build", "unknown"], ["package-suite", "all"],
               ["runtime-stage", "http", "ubuntu-24.04", "29"],
               ["runtime-stage", "http", "windows-2025", "30"],
               ["credential-local", "extra"], ["arbitrary", "cmd.exe"]],
    true = lists:all(fun(InvalidArguments) ->
        process_runner_expect_error(fun() ->
            windows_entry_request(InvalidArguments)
        end)
    end, Invalid),
    io:format("windows_entry_operations=4 invalid_controls=~B~n",
              [length(Invalid)]),
    ok.

self_test() ->
    runtime_identity_self_test(),
    io:format("process_runner_stage=windows_entry_contract~n"),
    windows_entry_contract_self_test(),
    io:format("process_runner_stage=assertion_contract~n"),
    diagnostic_assertion_self_test(),
    io:format("process_runner_stage=owned_run_contract~n"),
    {OwnedRunStatus, OwnedRunOutput} =
        supervised_process_supervisor_self_test_control(60000),
    ensure(process_status_verified(OwnedRunStatus, 0, OwnedRunOutput) andalso
           binary:match(output_tail(OwnedRunOutput),
               <<"process_supervisor_self_test passed=true controls=60 "
                 "relay_settlement=verified owned_run=verified">>) =/= nomatch,
           owned_run_contract_failed),
    {ok, FixtureSource} = file:read_file(
        "scripts/diagnostic_assertion_fixture.erl"),
    ensure(binary:match(FixtureSource, <<"open_port(">>) =:= nomatch andalso
           binary:match(FixtureSource, <<"cmd.exe">>) =:= nomatch,
           assertion_fixture_starts_external_process),
    ensure(process_runner_expect_error(fun() ->
        run_child_evaluation(filename:absname("."), [],
            "open_port({spawn_executable,\"forbidden\"},[]).", 1000)
    end), external_child_evaluation_accepted),
    BeforeDeadlineRefusal = filelib:wildcard(
        "build/process-runner/evaluation-*.erl"),
    ensure(process_runner_expect_error(fun() ->
        run_child_evaluation(filename:absname("."), [], "halt(0).", 5400001)
    end), oversized_child_deadline_accepted),
    ensure(BeforeDeadlineRefusal =:= filelib:wildcard(
        "build/process-runner/evaluation-*.erl"),
        oversized_child_deadline_created_an_input),
    ExpectedSupervisor = process_supervisor_sha256(),
    ExpectedPython = bounded_file_sha256(process_supervisor_python(),
                                         134217728),
    Isolation = process_supervisor_isolation(),
    ExactMaximumHandshake = iolist_to_binary([
        <<"H|">>, ExpectedSupervisor, <<"|">>, ExpectedPython,
        <<"|CPython|3.14.0|5400000|16777216|">>,
        Isolation
    ]),
    {ok, _} = parse_supervisor_handshake(
        ExactMaximumHandshake, ExpectedSupervisor, ExpectedPython,
        5400000, 16777216),
    AboveMaximumHandshake = iolist_to_binary([
        <<"H|">>, ExpectedSupervisor, <<"|">>, ExpectedPython,
        <<"|CPython|3.14.0|5400001|16777216|">>,
        Isolation
    ]),
    {error, process_supervisor_identity_invalid} = parse_supervisor_handshake(
        AboveMaximumHandshake, ExpectedSupervisor, ExpectedPython,
        5400001, 16777216),
    io:format("process_runner_stage=file_identity_boundary~n"),
    file_identity_boundary_self_test(),
    io:format("process_runner_stage=owned_port_trap_lifecycle~n"),
    owned_port_trap_lifecycle_self_test(),
    io:format("process_runner_stage=caller_exit_semantics~n"),
    caller_exit_semantics_self_test(),
    io:format("process_runner_stage=handshake_failure_cleanup~n"),
    HandshakeReason = process_runner_error(fun() ->
        supervised_fault_open("handshake_invalid", 5000)
    end),
    ensure(HandshakeReason =:= process_supervisor_identity_invalid,
           handshake_failure_not_classified),
    ensure(process_owned_tree_count() =:= 0,
           handshake_failure_ownership_not_released),
    io:format("handshake_failure_tree_joined=true~n"),
    console_boundary_self_test(),
    io:format("process_runner_stage=child_start_failure~n"),
    {MissingStatus, MissingOutput} = supervised_missing_child_control(5000),
    MissingFailure = maps:get(process_supervisor_failure_code,
                              MissingOutput, invalid),
    ensure(MissingStatus =:= 127 andalso
           process_completion_attestation_verified(MissingOutput) andalso
           lists:member(MissingFailure,
                        [<<"child_start_failed">>,
                         <<"console_child_start_failed">>]) andalso
           maps:get(native_tree_empty, MissingOutput, false) andalso
           maps:get(native_console_isolated, MissingOutput, false) andalso
           not maps:get(native_descendant_outlived, MissingOutput, true),
           child_start_failure_not_reaped),
    io:format("child_start_failure_classified=true tree_joined=true~n"),
    ActivationPort = make_ref(),
    ActivationCloseKey = {activation_close_control, make_ref()},
    put(ActivationCloseKey, false),
    RegistrationRejected = process_runner_expect_error(fun() ->
        activate_process_supervisor(ActivationPort, #{},
            erlang:monotonic_time(millisecond) + 1000,
            fun(P, Identity) ->
                put({process_runner_owned_tree, P},
                    #{supervisor_identity => Identity,
                      os_pid => unavailable,
                      termination_requested => false}),
                self() ! {'EXIT', P, normal},
                self() ! {P, {data, <<"F|124|1|0|1|1">>}},
                self() ! {P, {exit_status, 124}},
                erlang:error(synthetic_registration_failure)
            end,
            fun(_) -> erlang:error(start_must_not_run) end,
            fun(_) -> put(ActivationCloseKey, true), ok end)
    end),
    RegistrationMailboxDrained = no_owned_port_message(ActivationPort),
    ensure(RegistrationRejected andalso RegistrationMailboxDrained andalso
           erase(ActivationCloseKey) =:= true andalso
           get({process_runner_owned_tree, ActivationPort}) =:= undefined,
           failed_registration_not_closed),
    StartPort = make_ref(),
    StartCloseKey = {activation_close_control, make_ref()},
    put(StartCloseKey, false),
    StartIdentity = #{fixture_identity => true},
    StartReason = process_runner_error(fun() ->
        activate_process_supervisor(StartPort, StartIdentity,
            erlang:monotonic_time(millisecond) + 1000,
            fun(P, Identity) ->
                put({process_runner_owned_tree, P},
                    #{supervisor_identity => Identity,
                      termination_requested => false}), ok
            end,
            fun(P) ->
                %% Model the ambiguous delivery edge: the callback reports
                %% failure after the supervisor has already finalized a STOP.
                self() ! {'EXIT', P, normal},
                self() ! {P, {data, <<"F|124|1|0|1|1">>}},
                self() ! {P, {exit_status, 124}},
                false
            end,
            fun(_) -> put(StartCloseKey, true), ok end)
    end),
    StartMailboxDrained = receive
        {StartPort, _} -> false
    after 0 -> true
    end,
    ensure(StartReason =:= process_supervisor_start_unconfirmed andalso
           StartMailboxDrained andalso erase(StartCloseKey) =:= true andalso
           get({process_runner_owned_tree, StartPort}) =:= undefined,
           failed_start_not_reaped),
    UnconfirmedPort = make_ref(),
    UnconfirmedCloseKey = {activation_close_control, make_ref()},
    put(UnconfirmedCloseKey, false),
    UnconfirmedReason = process_runner_error(fun() ->
        activate_process_supervisor(UnconfirmedPort, #{fixture_identity => true},
            erlang:monotonic_time(millisecond) - 5001,
            fun(P, Identity) ->
                put({process_runner_owned_tree, P},
                    #{supervisor_identity => Identity,
                      termination_requested => false}), ok
            end,
            fun(P) ->
                self() ! {P, {exit_status, 127}},
                false
            end,
            fun(_) -> put(UnconfirmedCloseKey, true), ok end)
    end),
    UnconfirmedMailboxDrained = no_owned_port_message(UnconfirmedPort),
    ensure(UnconfirmedReason =:= child_exit_unconfirmed andalso
           erase(UnconfirmedCloseKey) =:= true andalso
           UnconfirmedMailboxDrained andalso
           get({process_runner_owned_tree, UnconfirmedPort}) =:= undefined,
           failed_start_without_final_was_not_blocked),
    ExitFirstPort = make_ref(),
    ExitFirstIdentity = #{fixture_identity => exit_before_status},
    put({process_runner_owned_tree, ExitFirstPort},
        #{supervisor_identity => ExitFirstIdentity,
          os_pid => unavailable, termination_requested => false,
          trap_acquired => false}),
    self() ! {'EXIT', ExitFirstPort, normal},
    self() ! {ExitFirstPort, {data, <<"F|37|1|0|0|1">>}},
    self() ! {ExitFirstPort, {exit_status, 37}},
    {37, ExitFirstOutput} = collect_before_deadline(ExitFirstPort,
        new_output(ExitFirstIdentity),
        erlang:monotonic_time(millisecond) + 1000),
    ensure(maps:get(child_exit_observed, ExitFirstOutput, false) andalso
           maps:get(process_supervisor_reported_status,
                    ExitFirstOutput, -1) =:= 37 andalso
           maps:get(process_supervisor_observed_status,
                    ExitFirstOutput, -1) =:= 37,
           exit_before_status_not_attested),
    ok = unregister_owned_tree(ExitFirstPort),
    ensure(no_owned_port_message(ExitFirstPort),
           exit_before_status_mailbox_not_drained),
    {control, SupervisorLimitedState} = supervisor_packet(
        <<"E|supervisor_output_limit">>, new_output()),
    SupervisorLimitedProjection = finish_output(
        SupervisorLimitedState, false, true),
    ensure(maps:get(output_limit_exceeded, SupervisorLimitedProjection, false)
           andalso not maps:get(output_digest_complete,
                                SupervisorLimitedProjection, true),
           supervisor_output_limit_packet_not_classified),
    Forged = diagnostic_failure_details(error, <<"fixture_private_marker">>,
        [{fixture_private_marker, main, 0, []}, {erlang, fixture_private_marker, 0, []}]),
    ForgedRedacted = binary:match(iolist_to_binary(json:encode(Forged)),
                                 <<"fixture_private_marker">>) =:= nomatch,
    io:format("forged_stack_payload_redacted=~p~n", [ForgedRedacted]),
    ensure(ForgedRedacted, forged_stack_payload_retained),
    SavedPath = os:getenv("PATH"),
    io:format("process_runner_stage=runtime_identity~n"),
    Shadow = filename:absname(filename:join("build/process-runner",
        "path-shadow-" ++ binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8))))),
    {ShadowName, Separator} = case os:type() of
        {win32, _} -> {"erl.exe", ";"}; _ -> {"erl", ":"}
    end,
    ShadowFile = filename:join(Shadow, ShadowName),
    ok = filelib:ensure_dir(ShadowFile),
    ok = file:write_file(ShadowFile, <<"fixture: not an OTP executable">>),
    ok = file:change_mode(ShadowFile, 8#700),
    SameRuntime = try
        true = os:putenv("PATH", Shadow ++ Separator ++
            case SavedPath of false -> ""; _ -> SavedPath end),
        true = filename:absname(os:find_executable("erl")) =:= ShadowFile,
        {0, SameRun} = run_child_evaluation(filename:absname("."), [], "halt(0).", 5000),
        process_status_verified(0, 0, SameRun)
    catch _:_ -> false
    after
        case SavedPath of false -> os:unsetenv("PATH"); _ -> os:putenv("PATH", SavedPath) end,
        ok = file:delete(ShadowFile),
        ok = file:del_dir(Shadow)
    end,
    io:format("child_runtime_independent_of_path=~p~n", [SameRuntime]),
    ensure(SameRuntime, child_runtime_not_bound),
    {0, MaximumDurationRun} = run_child_evaluation(
        filename:absname("."), [], "halt(0).", 5400000),
    ensure(process_status_verified(0, 0, MaximumDurationRun),
           maximum_configured_duration_not_supported),
    io:format("maximum_configured_duration_supported=true~n"),
    Before = filelib:wildcard("build/process-runner/evaluation-*.erl"),
    LongEvaluation = "halt(0). %" ++ lists:duplicate(262144, $x),
    {0, LongRun} = run_child_evaluation(filename:absname("."), [], LongEvaluation, 5000),
    ensure(process_status_verified(0, 0, LongRun), long_evaluation_reaped),
    ensure(filelib:wildcard("build/process-runner/evaluation-*.erl") =:= Before,
           evaluation_input_released),
    io:format("long_evaluation_runs_without_native_argv_limit=true~n"),
    {124, LateCompletion} = finish_exit_status(0, new_output(), true),
    ensure(maps:get(timed_out, LateCompletion), late_completion_not_timed_out),
    ensure(maps:get(child_exit_observed, LateCompletion),
           late_completion_exit_not_observed),
    {0, EligibleCompletion} = finish_exit_status(0, new_output(), false),
    ensure(not maps:get(timed_out, EligibleCompletion),
           eligible_completion_timed_out),
    DelayedDirectory = filename:absname(filename:join("build/process-runner",
        "delayed-dump-control-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(8), lowercase)))),
    DelayedPath = filename:join(DelayedDirectory, "erl_crash.dump"),
    ok = filelib:ensure_dir(DelayedPath),
    try
        ok = cleanup_child_artifacts(DelayedPath, DelayedDirectory, running),
        ok = file:write_file(DelayedPath, <<"synthetic delayed dump">>, [exclusive]),
        ensure(filelib:is_regular(DelayedPath),
               unconfirmed_dump_location_removed),
        ok = cleanup_child_artifacts(DelayedPath, DelayedDirectory, confirmed),
        ensure(not filelib:is_regular(DelayedPath) andalso
               not filelib:is_dir(DelayedDirectory), delayed_dump_not_removed)
    after
        _ = file:delete(DelayedPath),
        _ = file:del_dir(DelayedDirectory)
    end,
    CrashDirectoriesBefore = filelib:wildcard("build/process-runner/crash-*"),
    DumpDirectory = filename:absname(filename:join("build/diagnostics/process-runner",
        "crash-probe-" ++ integer_to_list(erlang:unique_integer([positive])))),
    ok = filelib:ensure_dir(filename:join(DumpDirectory, "placeholder")),
    {1, Crashed} = run_child_evaluation(DumpDirectory, [],
        "erlang:halt(\"fixture-private-marker\").", 5000),
    ensure(process_status_verified(1, 1, Crashed), crashed_child_reaped),
    ensure(not filelib:is_regular(filename:join(DumpDirectory, "erl_crash.dump")),
           raw_heap_dump_not_written),
    ensure(filelib:wildcard("build/process-runner/crash-*") =:=
           CrashDirectoriesBefore, isolated_crash_directory_retained),
    io:format("process_runner_stage=heap_bound~n"),
    {HeapStatus, HeapOutput} = run_child_evaluation(filename:absname("."), [],
        "{P,R}=spawn_monitor(fun()->put(a,binary:copy(<<0>>,134217728)),"
        "put(b,binary:copy(<<1>>,134217728)),erlang:garbage_collect() end),"
        "receive {'DOWN',R,process,P,killed}->halt(0);"
        "{'DOWN',R,process,P,_}->halt(1) after 8000->halt(2) end.", 10000),
    HeapBounded = process_status_verified(HeapStatus, 0, HeapOutput),
    io:format("captured_output_heap_bounded=~p~n", [HeapBounded]),
    ensure(HeapBounded, child_heap_is_bounded),
    io:format("process_runner_stage=output_limit~n"),
    Started = erlang:monotonic_time(millisecond),
    {Status, Output} = run_child_evaluation(filename:absname("."), [],
        "io:put_chars(binary:copy(<<\"x\">>,8388609)),receive never->ok end.",
        20000),
    Elapsed = erlang:monotonic_time(millisecond) - Started,
    Observed = #{output_limit_status => process_output_limit_verified(Status, Output),
                 output_limit_classified => maps:get(output_limit_exceeded, Output, false),
                 independent_of_deadline => Elapsed < 15000,
                 child_reaped => maps:get(child_exit_observed, Output),
                 tail_bounded => byte_size(output_tail(Output)) =< 65536},
    io:format("~s~n", [json:encode(Observed)]),
    ensure(lists:all(fun(V) -> V end, maps:values(Observed)), output_limit_contract),
    io:format("process_runner_stage=absolute_deadline~n"),
    DeadlineStarted = erlang:monotonic_time(millisecond),
    {124, Streaming} = run_child_evaluation(filename:absname("."), [],
        "F=fun Loop()->io:put_chars(<<\"x\">>),timer:sleep(10),Loop() end,F().",
        750),
    DeadlineElapsed = erlang:monotonic_time(millisecond) - DeadlineStarted,
    DeadlineObserved = #{absolute_deadline => process_deadline_verified(124, Streaming),
        child_reaped => maps:get(child_exit_observed, Streaming),
        output_stayed_bounded => not maps:get(output_limit_exceeded, Streaming),
        output_was_streaming => maps:get(output_bytes, Streaming) > 0,
        teardown_bounded => DeadlineElapsed < 7000},
    io:format("~s~n", [json:encode(DeadlineObserved)]),
    ensure(lists:all(fun(V) -> V end, maps:values(DeadlineObserved)),
           absolute_deadline_contract),
    %% The lexical evaluation guard is deliberately bypassed here to model a
    %% repository BEAM loaded through `Paths`. The OS ownership boundary must
    %% still terminate the native descendant before it can write its sentinel.
    io:format("process_runner_stage=descendant_deadline~n"),
    DescendantDeadlineSentinel = descendant_sentinel("deadline"),
    DescendantDeadlineEvaluation = descendant_evaluation(
        DescendantDeadlineSentinel, deadline),
    {124, DescendantDeadline} = run_child_evaluation(filename:absname("."), [],
        DescendantDeadlineEvaluation, 500),
    receive after 3000 -> ok end,
    DeadlineTreeJoined = process_deadline_verified(124, DescendantDeadline) andalso
        not filelib:is_regular(DescendantDeadlineSentinel),
    _ = file:delete(DescendantDeadlineSentinel),
    io:format("native_descendant_deadline_tree_joined=~p~n",
              [DeadlineTreeJoined]),
    ensure(DeadlineTreeJoined, native_descendant_survived_deadline),
    io:format("process_runner_stage=descendant_output_limit~n"),
    DescendantFloodSentinel = descendant_sentinel("output"),
    DescendantFloodEvaluation = descendant_evaluation(
        DescendantFloodSentinel, output_limit),
    {125, DescendantFlood} = run_child_evaluation(filename:absname("."), [],
        DescendantFloodEvaluation, 20000),
    receive after 3000 -> ok end,
    FloodTreeJoined = process_output_limit_verified(125, DescendantFlood) andalso
        not filelib:is_regular(DescendantFloodSentinel),
    _ = file:delete(DescendantFloodSentinel),
    io:format("native_descendant_output_tree_joined=~p~n", [FloodTreeJoined]),
    ensure(FloodTreeJoined, native_descendant_survived_output_limit),
    io:format("process_runner_stage=descendant_normal_exit~n"),
    DescendantSuccessSentinel = descendant_sentinel("success"),
    DescendantSuccessEvaluation = descendant_evaluation(
        DescendantSuccessSentinel, normal_exit),
    {126, DescendantSuccess} = run_child_evaluation(filename:absname("."), [],
        DescendantSuccessEvaluation, 5000),
    receive after 3000 -> ok end,
    SuccessTreeJoined = process_completion_verified(DescendantSuccess) andalso
        maps:get(native_tree_empty, DescendantSuccess) andalso
        maps:get(native_console_isolated, DescendantSuccess) andalso
        maps:get(native_descendant_outlived, DescendantSuccess) andalso
        not maps:get(native_termination_requested, DescendantSuccess) andalso
        not filelib:is_regular(DescendantSuccessSentinel),
    _ = file:delete(DescendantSuccessSentinel),
    io:format("native_descendant_normal_exit_classified=~p~n",
              [SuccessTreeJoined]),
    ensure(SuccessTreeJoined, native_descendant_survived_normal_exit),
    io:format("process_runner_stage=supervisor_autonomous_deadline~n"),
    AutonomousDeadline = supervisor_autonomous_deadline_control(),
    ensure(AutonomousDeadline, supervisor_depended_on_parent_scheduler),
    io:format("supervisor_autonomous_deadline_tree_joined=~p~n",
              [AutonomousDeadline]),
    io:format("process_runner_stage=supervisor_output_limit~n"),
    SupervisorOutputLimit = supervisor_output_limit_control(),
    ensure(SupervisorOutputLimit, supervisor_output_limit_not_enforced),
    io:format("supervisor_output_limit_tree_joined=~p~n",
              [SupervisorOutputLimit]),
    io:format("process_runner_stage=supervisor_protocol_failure~n"),
    {127, ProtocolOutput} = supervised_fault_control(
        "protocol_after_start", 10000),
    ProtocolJoined = maps:get(child_exit_observed, ProtocolOutput, false)
        andalso maps:get(native_tree_empty, ProtocolOutput, false)
        andalso maps:get(native_console_isolated, ProtocolOutput, false)
        andalso not maps:get(process_supervisor_protocol_valid,
                             ProtocolOutput, true)
        andalso maps:get(process_supervisor_attestation_failure,
                         ProtocolOutput, invalid) =:= protocol_invalid,
    ensure(ProtocolJoined, supervisor_protocol_failure_not_reaped),
    io:format("supervisor_protocol_failure_tree_joined=true~n"),
    io:format("process_runner_stage=supervisor_parent_eof~n"),
    ensure(supervisor_parent_eof_control(), supervisor_parent_eof_left_tree),
    io:format("supervisor_parent_eof_tree_joined=true~n"),
    ok.

console_boundary_self_test() ->
    case os:type() of
        {win32, _} ->
            {Status, Output} = supervised_console_inheritance_control(15000),
            StatusVerified = process_status_verified(Status, 0, Output),
            Tail = output_tail(Output),
            MarkerObserved = binary:match(Tail,
                <<"console_inheritance_fixture passed=true generations=2">>)
                =/= nomatch,
            Passed = StatusVerified andalso MarkerObserved,
            Identity = maps:get(process_supervisor, Output, #{}),
            SafeProof = #{schema => 1,
                stage => <<"console_inheritance">>, passed => Passed,
                otp_release => list_to_binary(
                    erlang:system_info(otp_release)),
                erts_version => list_to_binary(
                    erlang:system_info(version)),
                status_verified => StatusVerified,
                marker_observed => MarkerObserved,
                output_bytes => maps:get(output_bytes, Output, -1),
                output_limit_exceeded => maps:get(
                    output_limit_exceeded, Output, true),
                output_digest_complete => maps:get(
                    output_digest_complete, Output, false),
                output_sha256 => maps:get(output_sha256, Output, <<>>),
                output_has_fatal_python => binary:match(
                    Tail, <<"Fatal Python error">>) =/= nomatch,
                output_has_invalid_handle => binary:match(
                    Tail, <<"handle is invalid">>) =/= nomatch,
                output_has_traceback => binary:match(
                    Tail, <<"Traceback">>) =/= nomatch,
                output_has_fixture_failure => binary:match(
                    Tail, <<"console_inheritance_fixture failed=true">>)
                    =/= nomatch,
                output_has_console_attached => binary:match(
                    Tail, <<"console_attached=true">>) =/= nomatch,
                generations => 2, exit_status => Status,
                child_exit_observed => maps:get(child_exit_observed, Output, false),
                process_supervisor_protocol_valid => maps:get(
                    process_supervisor_protocol_valid, Output, false),
                process_supervisor_failure_code => maps:get(
                    process_supervisor_failure_code, Output, invalid),
                process_supervisor_attestation_failure => maps:get(
                    process_supervisor_attestation_failure, Output, invalid),
                process_supervisor_reported_status => maps:get(
                    process_supervisor_reported_status, Output, -1),
                process_supervisor_observed_status => maps:get(
                    process_supervisor_observed_status, Output, -1),
                native_tree_empty => maps:get(native_tree_empty, Output, false),
                native_console_isolated => maps:get(
                    native_console_isolated, Output, false),
                native_descendant_outlived => maps:get(
                    native_descendant_outlived, Output, true),
                native_termination_requested => maps:get(
                    native_termination_requested, Output, true),
                supervisor_source_sha256 => maps:get(source_sha256, Identity, <<>>),
                python_executable_sha256 => maps:get(
                    python_executable_sha256, Identity, <<>>)},
            io:format("~s~n", [json:encode(SafeProof)]),
            ensure(Passed, console_inheritance_contract_failed);
        _ -> ok
    end.

-spec runtime_identity_self_test() -> ok.
runtime_identity_self_test() ->
    Python = process_supervisor_python(),
    _ = process_file_snapshot(Python, 134217728),
    runtime_link_controls(),
    io:format("discovered runtime identity: regular executable verified~n"),
    ok.

-spec runtime_link_controls() -> ok.
runtime_link_controls() ->
    case os:type() of
        {win32, _} -> ok;
        _ -> runtime_posix_link_controls()
    end.

-spec runtime_posix_link_controls() -> ok.
runtime_posix_link_controls() ->
    Directory = filename:absname(filename:join("build/process-runner",
        "runtime-links-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(8), lowercase)))),
    Input = filename:join(Directory, "runtime"),
    Alias = filename:join(Directory, "python3"),
    Chain = filename:join(Directory, "python"),
    ok = filelib:ensure_dir(Input),
    try
        ok = file:write_file(Input, <<"runtime-control">>, [exclusive]),
        ok = file:make_symlink("runtime", Alias),
        ok = file:make_symlink("python3", Chain),
        Input = process_runtime_executable(Alias, 32),
        Input = process_runtime_executable(Chain, 32),
        _ = process_file_snapshot(Input, 64),
        ok = file:delete(Input),
        {error, process_supervisor_runtime_missing} = runtime_link_error(Chain),
        ok = file:make_symlink("python", Input),
        {error, process_supervisor_runtime_missing} = runtime_link_error(Chain),
        ok
    after
        lists:foreach(fun file:delete/1, [Chain, Alias, Input]),
        _ = file:del_dir(Directory)
    end.

-spec runtime_link_error(string()) -> {error, atom()} | accepted.
runtime_link_error(Path) ->
    try process_runtime_executable(Path, 32) of
        _ -> accepted
    catch error:Reason -> {error, Reason}
    end.

file_identity_boundary_self_test() ->
    Root = filename:absname(filename:join("build/process-runner",
        "file-boundary-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(8), lowercase)))),
    Input = filename:join(Root, "input.bin"),
    Alias = filename:join(Root, "alias.bin"),
    ok = filelib:ensure_dir(Input),
    try
        ok = file:write_file(Input, <<"stable">>, [exclusive]),
        Stable = bounded_file_sha256(Input, 64),
        ensure(Stable =:= binary:encode_hex(
            crypto:hash(sha256, <<"stable">>), lowercase),
            regular_file_digest_mismatch),
        ok = file:make_link(Input, Alias),
        HardlinkRejected = process_runner_error(fun() ->
            bounded_file_sha256(Alias, 64)
        end),
        ensure(HardlinkRejected =:=
                   {process_file_rejected, file_hardlink_rejected},
               hardlink_was_accepted),
        ok = file:delete(Alias),
        ok = file:write_file(Input, <<"before">>),
        MutationRejected = process_runner_error(fun() ->
            bounded_file_sha256_with_hook(Input, 64, fun() ->
                ok = file:write_file(Input, <<"after-mutation">>)
            end)
        end),
        ensure(MutationRejected =:=
                   {process_file_rejected, file_changed_while_reading},
               file_mutation_was_accepted),
        ParentLink = process_runner_parent_link_control(),
        io:format("process_file_identity hardlink=verified mutation=verified "
                  "parent_link=~s~n", [ParentLink]),
        ok
    after
        _ = file:delete(Alias),
        _ = file:delete(Input),
        _ = file:del_dir(Root)
    end.

process_runner_parent_link_control() ->
    case os:getenv("HTTP_PROCESS_RUNNER_PARENT_PATH") of
        Path when is_list(Path), Path =/= [], length(Path) =< 4096 ->
            case filename:pathtype(Path) of
                absolute ->
                    Reason = process_runner_error(fun() ->
                        bounded_file_sha256(filename:absname(Path), 64)
                    end),
                    ensure(Reason =:=
                        {process_file_rejected, file_parent_link_rejected},
                        parent_link_was_accepted),
                    "verified";
                _ -> erlang:error(parent_link_fixture_not_absolute)
            end;
        _ -> "unavailable"
    end.

process_owned_tree_count() ->
    length([Key || {Key = {process_runner_owned_tree, _}, _} <- get()]).

owned_port_trap_lifecycle_self_test() ->
    Original = process_flag(trap_exit, false),
    try
        lists:foreach(fun(Previous) ->
            _ = process_flag(trap_exit, Previous),
            erase(process_runner_owned_port_trap),
            First = make_ref(),
            Second = make_ref(),
            ok = acquire_owned_port_trap(),
            ok = acquire_owned_port_trap(),
            true = process_flag(trap_exit, true),
            put({process_runner_owned_tree, First},
                #{supervisor_identity => #{}, os_pid => unavailable,
                  termination_requested => false, trap_acquired => true}),
            put({process_runner_owned_tree, Second},
                #{supervisor_identity => #{}, os_pid => unavailable,
                  termination_requested => false, trap_acquired => true}),
            self() ! {'EXIT', First, epipe},
            self() ! {First, {exit_status, 124}},
            self() ! {First, {data, <<"fixed-control">>}},
            ok = unregister_owned_tree(First),
            true = process_flag(trap_exit, true),
            #{count := 1} = get(process_runner_owned_port_trap),
            self() ! {'EXIT', Second, normal},
            ok = unregister_owned_tree(Second),
            Previous = process_flag(trap_exit, Previous),
            undefined = get(process_runner_owned_port_trap),
            ensure(no_owned_port_message(First) andalso
                   no_owned_port_message(Second),
                   owned_port_exit_message_leaked)
        end, [false, true])
    after
        erase(process_runner_owned_port_trap),
        _ = process_flag(trap_exit, Original)
    end,
    io:format("owned_port_trap_restore_false=true restore_true=true "
              "concurrent_owners=true mailbox_clean=true~n"),
    ok.

caller_exit_semantics_self_test() ->
    Root = filename:absname(filename:join("build/process-runner",
        "caller-exit-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(8), lowercase)))),
    Ready = filename:join(Root, "ready"),
    Late = filename:join(Root, "late"),
    TrapReady = filename:join(Root, "trap-ready"),
    ok = filelib:ensure_dir(Ready),
    Parent = self(),
    {Target, Monitor} = spawn_monitor(fun() ->
        false = process_flag(trap_exit, false),
        Linked = spawn_link(fun() ->
            receive fail -> exit(unrelated_link_failure) end
        end),
        Parent ! {caller_exit_target_ready, self(), Linked},
        Evaluation = lists:flatten(io_lib:format(
            "ok=file:write_file(~0tp,<<\"ready\">>),"
            "timer:sleep(1500),ok=file:write_file(~0tp,<<\"late\">>),"
            "halt(0).", [Ready, Late])),
        _ = run_child_evaluation(filename:absname("."), [],
                                 Evaluation, 5000),
        Parent ! {caller_exit_target_survived, self()}
    end),
    Linked = receive
        {caller_exit_target_ready, Target, LinkedProcess} -> LinkedProcess
    after 5000 -> erlang:error(caller_exit_target_start_timeout)
    end,
    try
        ensure(wait_regular_file(Ready,
                erlang:monotonic_time(millisecond) + 5000),
               caller_exit_sync_timeout),
        Linked ! fail,
        receive
            {'DOWN', Monitor, process, Target, unrelated_link_failure} -> ok;
            {caller_exit_target_survived, Target} ->
                erlang:error(unrelated_link_failure_was_trapped);
            {'DOWN', Monitor, process, Target, _} ->
                erlang:error(unrelated_link_failure_changed)
        after 7000 -> erlang:error(caller_exit_target_stop_timeout)
        end,
        ensure(wait_evaluation_marker_absent(
                unicode:characters_to_binary(Root),
                erlang:monotonic_time(millisecond) + 7000),
               caller_exit_evaluation_was_stranded),
        timer:sleep(1800),
        ensure(not filelib:is_regular(Late),
               caller_exit_native_child_outlived_owner),
        caller_trapping_exit_semantics(Parent, TrapReady),
        io:format("caller_trap_exit_unchanged=true unrelated_link_failure="
                  "propagated owner_cleanup=true evaluation_cleanup=true~n"),
        ok
    after
        exit(Target, kill),
        _ = file:delete(Ready),
        _ = file:delete(Late),
        _ = file:delete(TrapReady),
        _ = file:del_dir(Root)
    end.

caller_trapping_exit_semantics(Parent, Ready) ->
    {Target, Monitor} = spawn_monitor(fun() ->
        false = process_flag(trap_exit, true),
        Linked = spawn_link(fun() ->
            receive fail -> exit(expected_trapped_link_failure) end
        end),
        Parent ! {caller_trap_target_ready, self(), Linked},
        Evaluation = lists:flatten(io_lib:format(
            "ok=file:write_file(~0tp,<<\"ready\">>),"
            "timer:sleep(300),halt(0).", [Ready])),
        {0, Output} = run_child_evaluation(
            filename:absname("."), [], Evaluation, 5000),
        Trapped = receive
            {'EXIT', Linked, expected_trapped_link_failure} -> true
        after 1000 -> false
        end,
        Parent ! {caller_trap_result, self(),
                  process_flag(trap_exit, true), Trapped,
                  get(process_runner_owned_port_trap),
                  process_owned_tree_count(),
                  process_status_verified(0, 0, Output)}
    end),
    Linked = receive
        {caller_trap_target_ready, Target, LinkedProcess} -> LinkedProcess
    after 5000 -> erlang:error(caller_trap_target_start_timeout)
    end,
    ensure(wait_regular_file(Ready,
            erlang:monotonic_time(millisecond) + 5000),
           caller_trap_sync_timeout),
    Linked ! fail,
    receive
        {caller_trap_result, Target, true, true, undefined, 0, true} -> ok;
        {caller_trap_result, Target, _, _, _, _, _} ->
            erlang:error(caller_trap_semantics_changed);
        {'DOWN', Monitor, process, Target, _} ->
            erlang:error(caller_trap_target_failed)
    after 7000 -> erlang:error(caller_trap_result_timeout)
    end,
    receive
        {'DOWN', Monitor, process, Target, normal} -> ok;
        {'DOWN', Monitor, process, Target, _} ->
            erlang:error(caller_trap_target_failed)
    after 1000 -> erlang:error(caller_trap_target_exit_timeout)
    end.

wait_regular_file(Path, Deadline) ->
    case filelib:is_regular(Path) of
        true -> true;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> false;
                false -> timer:sleep(10), wait_regular_file(Path, Deadline)
            end
    end.

wait_evaluation_marker_absent(Marker, Deadline) ->
    Present = lists:any(fun(Path) ->
        case file:read_file(Path) of
            {ok, Bytes} when byte_size(Bytes) =< 2097152 ->
                binary:match(Bytes, Marker) =/= nomatch;
            _ -> false
        end
    end, filelib:wildcard("build/process-runner/evaluation-*.erl")),
    case Present of
        false -> true;
        true ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> false;
                false -> timer:sleep(10),
                         wait_evaluation_marker_absent(Marker, Deadline)
            end
    end.

no_owned_port_message(Port) ->
    receive
        {'EXIT', Port, _} -> false;
        {Port, _} -> false
    after 0 -> true
    end.

supervised_fault_open(Fault, Milliseconds) ->
    ErlName = case os:type() of {win32, _} -> "erl.exe"; _ -> "erl" end,
    Erl = filename:join([code:root_dir(), "bin", ErlName]),
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    case open_owned_process(Erl,
        ["+S", "1:1", "+SDcpu", "1", "+SDio", "1", "+A", "1",
         "-noshell", "-noinput", "-eval", "halt(0)."],
        filename:absname("."),
        [{"HTTP_PROCESS_SUPERVISOR_TEST_FAULT", Fault}], Deadline) of
        {Port, Identity} ->
            _ = kill_owned_child(Port),
            _ = await_child_exit(Port, new_output(Identity),
                                 erlang:monotonic_time(millisecond) + 5000),
            unregister_owned_tree(Port),
            erlang:error(handshake_fault_was_accepted)
    end.

supervised_fault_control(Fault, Milliseconds) ->
    ErlName = case os:type() of {win32, _} -> "erl.exe"; _ -> "erl" end,
    Erl = filename:join([code:root_dir(), "bin", ErlName]),
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    {Port, Identity} = open_owned_process(Erl,
        ["+S", "1:1", "+SDcpu", "1", "+SDio", "1", "+A", "1",
         "-noshell", "-noinput", "-eval",
         "receive process_runner_never -> ok end."],
        filename:absname("."),
        [{"HTTP_PROCESS_SUPERVISOR_TEST_FAULT", Fault}], Deadline),
    Result = collect_eunit(Port, new_output(Identity), Deadline),
    case Result of
        {_, #{child_exit_observed := true}} -> unregister_owned_tree(Port);
        _ -> ok
    end,
    Result.

supervised_console_inheritance_control(Milliseconds) ->
    supervised_python_script_control(
        "scripts/process_console_inheritance_fixture.py",
        ["-E", "-s", "-B"], ["--root"], Milliseconds).

supervised_process_supervisor_self_test_control(Milliseconds) ->
    supervised_python_script_control(
        "scripts/process_supervisor.py",
        ["-I", "-B"], ["--self-test"], Milliseconds).

supervised_missing_child_control(Milliseconds) ->
    Missing = filename:absname(filename:join(
        "build/process-runner", "intentionally-missing-native-child")),
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    {Port, Identity} = open_owned_process(
        Missing, [], filename:absname("."), [], Deadline),
    Result = collect_eunit(Port, new_output(Identity), Deadline),
    unregister_owned_tree(Port),
    Result.

supervised_python_script_control(RelativeScript, PythonFlags, Arguments,
                                 Milliseconds) ->
    Python = process_supervisor_python(),
    Script = filename:absname(RelativeScript),
    true = filelib:is_regular(Script),
    Deadline = erlang:monotonic_time(millisecond) + Milliseconds,
    {Port, Identity} = open_owned_process(Python,
        PythonFlags ++ [Script | Arguments], filename:absname("."), [], Deadline),
    Result = collect_eunit(Port, new_output(Identity), Deadline),
    unregister_owned_tree(Port),
    Result.

supervisor_autonomous_deadline_control() ->
    ErlName = case os:type() of {win32, _} -> "erl.exe"; _ -> "erl" end,
    Erl = filename:join([code:root_dir(), "bin", ErlName]),
    Deadline = erlang:monotonic_time(millisecond) + 600,
    {Port, Identity} = open_owned_process(Erl,
        ["+S", "1:1", "+SDcpu", "1", "+SDio", "1", "+A", "1",
         "-noshell", "-noinput", "-eval", "receive never -> ok end."],
        filename:absname("."), [], Deadline),
    receive after 1200 -> ok end,
    {Status, Output} = collect_before_deadline(
        Port, new_output(Identity), erlang:monotonic_time(millisecond) + 5000),
    unregister_owned_tree(Port),
    Status =:= 124 andalso maps:get(child_exit_observed, Output, false) andalso
        maps:get(process_supervisor_protocol_valid, Output, false) andalso
        maps:get(process_supervisor_failure_code, Output, none) =:=
            <<"supervisor_deadline">> andalso
        maps:get(native_tree_empty, Output, false) andalso
        maps:get(native_console_isolated, Output, false) andalso
        maps:get(native_termination_requested, Output, false).

supervisor_output_limit_control() ->
    ErlName = case os:type() of {win32, _} -> "erl.exe"; _ -> "erl" end,
    Erl = filename:join([code:root_dir(), "bin", ErlName]),
    Deadline = erlang:monotonic_time(millisecond) + 30000,
    {Port, Identity} = open_owned_process(Erl,
        ["+S", "1:1", "+SDcpu", "1", "+SDio", "1", "+A", "1",
         "-noshell", "-noinput", "-eval",
         "io:put_chars(binary:copy(<<\"x\">>,16777217)),"
         "receive never -> ok end."], filename:absname("."), [], Deadline),
    {Status, Output} = collect_without_parent_output_stop(
        Port, new_output(Identity), Deadline + 5000),
    unregister_owned_tree(Port),
    Status =:= 125 andalso maps:get(child_exit_observed, Output, false) andalso
        maps:get(output_limit_exceeded, Output, false) andalso
        not maps:get(output_digest_complete, Output, true) andalso
        maps:get(process_supervisor_protocol_valid, Output, false) andalso
        maps:get(process_supervisor_failure_code, Output, none) =:=
            <<"supervisor_output_limit">> andalso
        maps:get(native_tree_empty, Output, false) andalso
        maps:get(native_console_isolated, Output, false) andalso
        maps:get(native_termination_requested, Output, false).

collect_without_parent_output_stop(Port, Output, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true ->
            kill_owned_child(Port),
            await_child_exit(Port, Output, erlang:monotonic_time(millisecond) + 5000);
        false ->
            receive
                {Port, {data, Packet}} ->
                    case owned_port_packet(Port, Packet, Output) of
                        {output, Next} ->
                            collect_without_parent_output_stop(Port, Next, Deadline);
                        {control, Next} ->
                            collect_without_parent_output_stop(Port, Next, Deadline);
                        {error, Next} ->
                            collect_without_parent_output_stop(Port, Next, Deadline)
                    end;
                {Port, {exit_status, Status}} ->
                    case attest_owned_exit(Port, Status, Output) of
                        {ok, Attested} -> finish_exit_status(Status, Attested, false);
                        {error, Unattested} -> {Status, finish_output(Unattested,
                            Status =:= 124, false)}
                    end
            after Remaining ->
                kill_owned_child(Port),
                await_child_exit(Port, Output,
                                 erlang:monotonic_time(millisecond) + 5000)
            end
    end.

descendant_sentinel(Label) ->
    filename:absname(filename:join("build/process-runner",
        "descendant-" ++ Label ++ "-" ++ binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(8), lowercase)) ++ ".sentinel")).

descendant_evaluation(Sentinel, Mode) ->
    NativeEvaluation = lists:flatten(io_lib:format(
        "timer:sleep(2500),ok=file:write_file(~0tp,<<\"late\">>),halt(0).",
        [Sentinel])),
    AfterSpawn = case Mode of
        deadline -> "receive process_runner_never -> ok end.";
        output_limit ->
            "io:put_chars(binary:copy(<<\"x\">>,8388609)),"
            "receive process_runner_never -> ok end.";
        normal_exit -> "halt(0)."
    end,
    lists:flatten(io_lib:format(
        "Exe=filename:join([code:root_dir(),\"bin\","
        "case os:type() of {win32,_}->\"erl.exe\";_->\"erl\" end]),"
        "PortFunction=list_to_atom(\"open_\"++\"port\"),"
        "_Native=apply(erlang,PortFunction,[{spawn_executable,Exe},"
        "[binary,exit_status,use_stdio,stderr_to_stdout,hide,"
        "{args,[\"+S\",\"1:1\",\"+SDcpu\",\"1\",\"+SDio\",\"1\","
        "\"+A\",\"1\",\"-noshell\",\"-noinput\",\"-eval\",~0tp]}]]),~s",
        [NativeEvaluation, AfterSpawn])).

supervisor_parent_eof_control() ->
    Alive = descendant_sentinel("eof-alive"),
    Late = descendant_sentinel("eof-late"),
    Python = process_supervisor_python(),
    NativeProgram = "import pathlib,sys,time;"
        "pathlib.Path(sys.argv[1]).write_bytes(b'alive');"
        "time.sleep(2.5);pathlib.Path(sys.argv[2]).write_bytes(b'late')",
    RootEvaluation = lists:flatten(io_lib:format(
        "Exe=~0tp,"
        "PortFunction=list_to_atom(\"open_\"++\"port\"),"
        "_Native=apply(erlang,PortFunction,[{spawn_executable,Exe},"
        "[binary,exit_status,use_stdio,stderr_to_stdout,hide,"
        "{args,[\"-I\",\"-c\",~0tp,~0tp,~0tp]}]]),"
        "Wait=fun Loop(0)->halt(3);Loop(N)->case filelib:is_regular(~0tp) of "
        "true->ok;false->timer:sleep(10),Loop(N-1) end end,Wait(1000),"
        "io:put_chars(<<\"READY\">>),receive process_runner_never->ok end.",
        [Python, NativeProgram, Alive, Late, Alive])),
    {ok, RootTokens, _} = erl_scan:string(RootEvaluation),
    {ok, _RootExpressions} = erl_parse:parse_exprs(RootTokens),
    ErlName = case os:type() of {win32, _} -> "erl.exe"; _ -> "erl" end,
    Erl = filename:join([code:root_dir(), "bin", ErlName]),
    Args = ["+S", "1:1", "+SDcpu", "1", "+SDio", "1", "+A", "1",
            "-noshell", "-noinput", "-eval", RootEvaluation],
    Deadline = erlang:monotonic_time(millisecond) + 15000,
    {Port, Identity} = open_owned_process(Erl, Args, filename:absname("."),
                                          [], Deadline),
    ReadyResult = await_supervisor_ready(Port, new_output(Identity), Deadline),
    Ready = case ReadyResult of {ready, _} -> true; _ -> false end,
    close_owned_port(Port),
    unregister_owned_tree(Port),
    receive after 3000 -> ok end,
    Observed = #{ready_observed => Ready,
                 descendant_started => filelib:is_regular(Alive),
                 late_write_absent => not filelib:is_regular(Late),
                 pre_eof_status => eof_ready_status(ReadyResult),
                 pre_eof_output_bytes => eof_ready_output_bytes(ReadyResult),
                 pre_eof_final_seen => eof_ready_final_seen(ReadyResult)},
    io:format("~s~n", [json:encode(Observed)]),
    Joined = Ready andalso maps:get(descendant_started, Observed) andalso
        maps:get(late_write_absent, Observed),
    _ = file:delete(Alive),
    _ = file:delete(Late),
    Joined.

await_supervisor_ready(Port, Output, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining =< 0 of
        true -> {timeout, output_summary(Output)};
        false ->
            receive
                {Port, {data, Packet}} ->
                    case owned_port_packet(Port, Packet, Output) of
                        {output, Next} ->
                            case binary:match(output_tail(Next), <<"READY">>) of
                                nomatch -> await_supervisor_ready(Port, Next, Deadline);
                                _ -> {ready, output_summary(Next)}
                            end;
                        {control, Next} -> await_supervisor_ready(Port, Next, Deadline);
                        {error, Next} -> {protocol_error, output_summary(Next)}
                    end;
                {Port, {exit_status, Status}} ->
                    {exited, Status, output_summary(Output)}
            after Remaining -> {timeout, output_summary(Output)}
            end
    end.

output_summary(Output) ->
    #{output_bytes => maps:get(bytes, Output),
      final_seen => is_map(maps:get(supervisor_final, Output, undefined)),
      protocol_valid => maps:get(supervisor_protocol_valid, Output, false)}.

eof_ready_status({ready, _}) -> ready;
eof_ready_status({timeout, _}) -> timeout;
eof_ready_status({protocol_error, _}) -> protocol_error;
eof_ready_status({exited, Status, _}) when Status >= 0, Status =< 255 -> Status;
eof_ready_status(_) -> invalid.

eof_ready_summary({ready, Summary}) -> Summary;
eof_ready_summary({timeout, Summary}) -> Summary;
eof_ready_summary({protocol_error, Summary}) -> Summary;
eof_ready_summary({exited, _, Summary}) -> Summary;
eof_ready_summary(_) -> #{}.

eof_ready_output_bytes(Result) ->
    maps:get(output_bytes, eof_ready_summary(Result), 0).

eof_ready_final_seen(Result) ->
    maps:get(final_seen, eof_ready_summary(Result), false).

hex(Binary) -> binary:encode_hex(Binary).
process_runner_expect_error(Function) ->
    try Function() of _ -> false catch _:_ -> true end.
process_runner_error(Function) ->
    try Function() of _ -> no_error
    catch error:Reason -> Reason; _:_ -> unexpected_failure_class
    end.
ensure(true, _) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
