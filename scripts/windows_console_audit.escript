#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(OUTPUT, "build/test-runner/windows-console-audit.json").
-define(MAX_SOURCE_BYTES, 2097152).
-define(MAX_SOURCE_FILES, 2048).
-define(MAX_CONSOLE_TITLE_BYTES, 4096).

-include("execution_identity.hrl").
-include("file_identity.hrl").
-include("diagnostic_failure.hrl").
-include("command_capture.hrl").

main(["--self-test"]) ->
    try run() of
        ok -> ok
    catch
        Class:Reason:Stack ->
            io:format(standard_error, "windows console audit failed: ~p~n",
                      [diagnostic_failure_details(Class, Reason, Stack)]),
            halt(1)
    end;
main(_) -> halt(2).

run() ->
    Runtime = execution_runtime(),
    RuntimeOutput = runtime_output(Runtime),
    lists:foreach(fun invalidate_output/1, [?OUTPUT, RuntimeOutput]),
    SelfTests = lexical_self_tests() ++ ownership_self_tests() ++
        activation_recovery_self_tests() ++
        macro_self_tests() ++ dynamic_spawn_self_tests() ++
        native_script_self_tests() ++ python_console_payload_self_tests() ++
        windows_entry_contract_self_tests() ++ [python_ast_self_test()],
    ErlangPaths = authored_erlang_paths(),
    NativeScriptPaths = authored_native_script_paths(),
    WorkflowPaths = authored_workflow_paths(),
    Paths = lists:usort(ErlangPaths ++ NativeScriptPaths ++ WorkflowPaths),
    true = length(Paths) > 0 andalso length(Paths) =< ?MAX_SOURCE_FILES,
    IdentityPaths = [".mise.toml" | Paths],
    SourceRows = [{Path, bounded_source_bytes(Path)} || Path <- IdentityPaths],
    SourceBytes = maps:from_list(SourceRows),
    Audits = [source_audit(Path, maps:get(Path, SourceBytes)) || Path <- ErlangPaths],
    Calls = lists:append([maps:get(calls, Audit) || Audit <- Audits]),
    UnsafeMacros = lists:append([maps:get(command_macros, Audit) || Audit <- Audits]),
    DynamicSpawns = lists:append([maps:get(dynamic_spawns, Audit) || Audit <- Audits]),
    NativeAudits = [native_script_audit(Path, maps:get(Path, SourceBytes))
                    || Path <- NativeScriptPaths,
                       filename:extension(Path) =:= ".ps1"],
    PythonReport = python_ast_audit(NativeScriptPaths, SourceBytes),
    PythonLaunches = maps:get(<<"launches">>, PythonReport),
    PythonUnsafe = maps:get(<<"unsafe">>, PythonReport),
    RunnerBytes = maps:get("scripts/process_runner.hrl", SourceBytes),
    ActivationRecoveryVerified = activation_recovery_contract(RunnerBytes),
    ActivationRecoveryFailures = case ActivationRecoveryVerified of
        true -> [];
        false -> [#{classification => <<"supervisor_activation_unconfirmed">>,
                    path => <<"scripts/process_runner.hrl">>,
                    line => line_of(RunnerBytes,
                                    <<"activate_process_supervisor(">>),
                    rule => <<"start_delivery_requires_attested_reap">>}]
    end,
    NativeLaunches = PythonLaunches ++
        lists:append([maps:get(launches, Audit) || Audit <- NativeAudits]),
    UnsafeNativeFlags = lists:append([maps:get(unsafe_flags, Audit)
                                      || Audit <- NativeAudits]),
    WorkflowLaunches = lists:append([workflow_python_launches(
        Path, maps:get(Path, SourceBytes)) || Path <- WorkflowPaths]),
    WindowsWorkflowEntries = lists:append([workflow_windows_direct_entries(
        Path, maps:get(Path, SourceBytes)) || Path <- WorkflowPaths]),
    BootstrapBytes = source_bytes_by_normal_path(
        "scripts/windows_headless_entry.ps1", SourceBytes),
    RunnerEntryBytes = source_bytes_by_normal_path(
        "scripts/process_runner.escript", SourceBytes),
    InheritanceBytes = source_bytes_by_normal_path(
        "scripts/windows_console_inheritance_audit.ps1", SourceBytes),
    MiseBytes = maps:get(".mise.toml", SourceBytes),
    BootstrapVerified = windows_headless_bootstrap_contract(BootstrapBytes),
    RunnerEntryVerified = windows_entry_runner_contract(RunnerEntryBytes),
    InheritanceVerified = windows_inheritance_launcher_contract(
        InheritanceBytes),
    WorkflowEntryVerified = windows_workflow_entry_contract(
        WorkflowPaths, SourceBytes),
    MiseEntryVerified = windows_mise_entry_contract(MiseBytes),
    EntryContractFailures = windows_entry_contract_failures(
        BootstrapVerified, RunnerEntryVerified, InheritanceVerified,
        WorkflowEntryVerified, MiseEntryVerified),
    Missing = [Call || Call <- Calls, maps:get(hidden, Call) =:= false],
    Unowned = [Call || Call <- Calls, maps:get(owned_supervisor, Call) =:= false],
    ControlFailures = [#{classification => <<"self_test_failed">>,
                         kind => maps:get(kind, Row)}
                       || Row <- SelfTests, not maps:get(passed, Row)],
    Failures = [maps:remove(hidden,
                Call#{classification => <<"missing_windows_hide">>})
                || Call <- Missing] ++
        [maps:remove(hidden,
            Call#{classification => <<"unowned_native_process_tree">>})
         || Call <- Unowned] ++
        [Row#{classification => <<"dynamic_unowned_native_spawn">>}
         || Row <- DynamicSpawns] ++
        [Row#{classification => <<"unsafe_windows_console_capability">>}
         || Row <- UnsafeNativeFlags] ++
        [python_finding(Row) || Row <- PythonUnsafe] ++
        [Row#{classification => <<"direct_ci_python_entrypoint">>}
         || Row <- WorkflowLaunches] ++
        [Row#{classification => <<"direct_windows_workflow_entrypoint">>}
         || Row <- WindowsWorkflowEntries] ++
        [Macro#{classification => <<"unsafe_eunit_command_macro">>}
         || Macro <- UnsafeMacros] ++ EntryContractFailures ++
         ActivationRecoveryFailures ++
         ControlFailures,
    SourceIdentity = [source_identity(Path, maps:get(Path, SourceBytes))
                      || Path <- IdentityPaths],
    SourceDigest = file_identity_digest(IdentityPaths,
        fun(Path) -> maps:get(Path, SourceBytes) end, lowercase),
    Passed = Failures =:= [],
    Report = #{schema => 3,
        scope => <<"authored native processes are hidden and supervisor-owned">>,
        rerun_command => <<"escript scripts/windows_console_audit.escript --self-test">>,
        execution_environment => Runtime,
        tool => #{name => <<"OTP escript">>,
                  otp_version => maps:get(<<"otp_version">>, Runtime)},
        source_identity => SourceIdentity,
        source_set_sha256 => SourceDigest,
        source_files => length(IdentityPaths),
        completed_source_files => length(Audits) + length(NativeScriptPaths) +
            length(WorkflowPaths) + 1,
        controls => SelfTests,
        completed_controls => length(SelfTests),
        failed_controls => length(ControlFailures),
        external_port_calls => length(Calls),
        spawn_executable_calls => length([Call || Call <- Calls,
            maps:get(kind, Call) =:= spawn_executable]),
        shell_spawn_calls => length([Call || Call <- Calls,
            maps:get(kind, Call) =:= spawn]),
        missing_hide => Missing,
        unowned_native_process_calls => Unowned,
        unsafe_eunit_command_macros => UnsafeMacros,
        dynamic_native_spawns => DynamicSpawns,
        activation_recovery_verified => ActivationRecoveryVerified,
        native_script_process_launches => NativeLaunches,
        unsafe_native_script_flags => UnsafeNativeFlags,
        direct_ci_python_entrypoints => WorkflowLaunches,
        direct_windows_workflow_entrypoints => WindowsWorkflowEntries,
        windows_headless_bootstrap_verified => BootstrapVerified,
        windows_entry_runner_verified => RunnerEntryVerified,
        windows_inheritance_launcher_verified => InheritanceVerified,
        windows_workflow_entry_verified => WorkflowEntryVerified,
        windows_mise_entry_verified => MiseEntryVerified,
        failure_count => length(Failures),
        failures => Failures,
        overall_candidate_ready => false,
        passed => Passed},
    %% Refuse to publish a report assembled from a mixture of file revisions.
    SourceDigest = file_identity_digest(IdentityPaths,
        fun bounded_source_bytes/1, lowercase),
    Encoded = [json:encode(Report), <<"\n">>],
    ok = filelib:ensure_dir(RuntimeOutput),
    ok = file:write_file(RuntimeOutput, Encoded, [exclusive]),
    ok = filelib:ensure_dir(?OUTPUT),
    ok = file:write_file(?OUTPUT, Encoded, [exclusive]),
    io:format("windows console audit: calls=~B missing_hide=~B unowned=~B unsafe_macros=~B controls=~B~n",
              [length(Calls), length(Missing), length(Unowned),
               length(UnsafeMacros), length(SelfTests)]),
    true = Passed,
    ok.

runtime_output(Runtime) ->
    Version = maps:get(<<"otp_version">>, Runtime),
    "build/test-runner/windows-console-audit-otp-" ++
        binary_to_list(Version) ++ ".json".

authored_erlang_paths() ->
    Roots = ["src", "test", "scripts", "packages/http3/src",
             "packages/http3/test", "packages/quic_core/src",
             "packages/quic_core/test"],
    lists:usort(lists:append([case filelib:is_dir(Root) of
        true -> filelib:fold_files(Root, ".*\\.(?:erl|hrl|escript)$", true,
            fun(Path, Acc) -> [Path | Acc] end, []);
        false -> []
    end || Root <- Roots])).

authored_native_script_paths() ->
    Roots = ["src", "test", "scripts", "packages/http3/src",
             "packages/http3/test", "packages/quic_core/src",
             "packages/quic_core/test"],
    lists:usort(lists:append([case filelib:is_dir(Root) of
        true -> filelib:fold_files(Root, ".*\\.(?:py|ps1)$", true,
            fun(Path, Acc) -> [Path | Acc] end, []);
        false -> []
    end || Root <- Roots])).

authored_workflow_paths() ->
    lists:sort(filelib:wildcard(".github/workflows/*.yml") ++
               filelib:wildcard(".github/workflows/*.yaml")).

invalidate_output(Path) ->
    case file:delete(Path) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} -> erlang:error(cannot_invalidate_prior_console_audit)
    end.

windows_entry_contract_failures(true, true, true, true, true) -> [];
windows_entry_contract_failures(Bootstrap, Runner, Inheritance, Workflow,
                                Mise) ->
    [#{classification => <<"windows_entry_contract_failed">>,
       component => Component, rule => Rule}
     || {Component, Rule, Verified} <- [
        {<<"outer_bootstrap">>, <<"fixed_hidden_process_start">>, Bootstrap},
        {<<"owned_runner">>, <<"closed_owned_operation_dispatch">>, Runner},
        {<<"visibility_proof">>, <<"bounded_owner_bound_launcher">>,
         Inheritance},
        {<<"workflow">>, <<"windows_steps_use_outer_bootstrap">>, Workflow},
        {<<"mise">>, <<"windows_tasks_use_outer_bootstrap">>, Mise}
     ], not Verified].

windows_inheritance_launcher_contract(Bytes)
  when is_binary(Bytes), byte_size(Bytes) > 0 ->
    Code = powershell_code(Bytes),
    Required = [
        <<"$hardDeadlineMilliseconds =">>,
        <<"$cleanupReserveMilliseconds = 5000">>,
        <<"$ownedOutputLimitBytes = 133120L">>,
        <<"$watcherOutputLimitBytes = 524288L">>,
        <<"$resultPath = Join-Path $workDirectory">>,
        <<"windows-console-inheritance-otp">>,
        <<"Get-Command 'escript.exe' -CommandType Application">>,
        <<"$expectedEscriptHash = [string]$env:HTTP_WINDOWS_ESCRIPT_SHA256">>,
        <<"[string]$env:HTTP_WINDOWS_ESCRIPT_PATH_ID">>,
        <<"$escriptHashBefore -cne $expectedEscriptHash">>,
        <<"$actualEscriptPathIdentity -cne $expectedEscriptPathIdentity">>,
        <<"function New-DrainState">>,
        <<"function Start-DrainRead">>,
        <<"$State.Stream.ReadAsync(">>,
        <<"Task]::WaitAny(">>,
        <<"$Process.Kill($true)">>,
        <<"return $Process.WaitForExit($remaining)">>,
        <<"Write-PublicReport -Json $successJson">>,
        <<"Write-PublicReport -Json $failureJson">>,
        <<"$fixtureStart.UseShellExecute = $false">>,
        <<"$fixtureStart.CreateNoWindow = $true">>,
        <<"$fixtureStart.WindowStyle = ">>,
        <<"[System.Diagnostics.ProcessWindowStyle]::Hidden">>,
        <<"$outsiderStart.UseShellExecute = $false">>,
        <<"$outsiderStart.CreateNoWindow = $true">>,
        <<"$outsiderStart.WindowStyle = ">>,
        <<"-WindowStyle Hidden -PassThru">>,
        <<"-RedirectStandardOutput $watchOut">>,
        <<"-RedirectStandardError $watchErr">>,
        <<"-RequireOwnerBinding">>,
        <<"owned_streams_drained">>,
        <<"output_limit_exceeded">>,
        <<"deadline_expired">>
    ],
    Forbidden = [
        <<"(?i)\\.ReadToEnd(?:Async)?\\s*\\(">>,
        <<"(?i)\\.ReadAllText\\s*\\(">>,
        <<"(?i)\\.Arguments\\s*=">>,
        <<"(?i)\\[(?:System\\.)?Diagnostics\\.Process\\]"
          "\\s*::\\s*Start\\s*\\(">>,
        <<"(?i)(?:Invoke-Expression|iex|Start-Job|Import-Module|Add-Type)"
          "(?:$|[^A-Za-z0-9_-])">>,
        <<"(?i)(?:cmd|taskkill)(?:\\.exe)?(?:$|[^A-Za-z0-9_])">>
    ],
    lists:all(fun(Fragment) ->
        binary:match(Bytes, Fragment) =/= nomatch
    end, Required)
        andalso lists:all(fun(Pattern) ->
            not regex_match(Code, Pattern)
        end, Forbidden)
        andalso binary:match(Bytes, <<"HTTP_OTP">>) =:= nomatch
        andalso binary:match(Bytes,
            <<"[string] $EscriptExecutable">>) =:= nomatch
        andalso binary:match(Bytes,
            <<"[string] $PythonExecutable">>) =:= nomatch
        andalso binary_occurrences(
            Code, <<".UseShellExecute = $false">>) =:= 2
        andalso binary_occurrences(
            Code, <<".CreateNoWindow = $true">>) =:= 2
        andalso binary_occurrences(
            Code, <<"[System.Diagnostics.ProcessWindowStyle]::Hidden">>)
            >= 2
        andalso binary_occurrences(Code, <<".Start()">>) =:= 2;
windows_inheritance_launcher_contract(_) -> false.

windows_headless_bootstrap_contract(Bytes)
  when is_binary(Bytes), byte_size(Bytes) > 0 ->
    Code = powershell_code(Bytes),
    RequiredCode = [
        <<"\\$startInfo\\s*=\\s*\\[System\\.Diagnostics\\."
          "ProcessStartInfo\\]\\s*::\\s*new\\s*\\(">>,
        <<"\\$startInfo\\.FileName\\s*=\\s*\\$escript">>,
        <<"\\$startInfo\\.UseShellExecute\\s*=\\s*\\$false">>,
        <<"\\$startInfo\\.CreateNoWindow\\s*=\\s*\\$true">>,
        <<"\\$startInfo\\.WindowStyle\\s*=\\s*\\[System\\."
          "Diagnostics\\.ProcessWindowStyle\\]\\s*::\\s*Hidden">>,
        <<"\\$startInfo\\.RedirectStandardOutput\\s*=\\s*\\$true">>,
        <<"\\$startInfo\\.RedirectStandardError\\s*=\\s*\\$true">>,
        <<"\\$process\\.StartInfo\\s*=\\s*\\$startInfo">>,
        <<"\\$process\\.Start\\s*\\(\\s*\\)">>,
        <<"\\$Child\\.Kill\\s*\\(\\s*\\$true\\s*\\)">>,
        <<"\\.ReadAsync\\s*\\(">>,
        <<"Task\\]\\s*::\\s*WaitAny\\s*\\(">>,
        <<"Stopwatch\\]\\s*::\\s*StartNew\\s*\\(">>,
        <<"\\$hardDeadlineMilliseconds">>,
        <<"\\$outputLimitBytes\\s*=\\s*65536L">>,
        <<"Test-OuterFailureCode\\s+-Value\\s+\\$failureCode">>,
        <<"ConvertTo-Json(?:$|[^A-Za-z0-9_-])">>
    ],
    ForbiddenCode = [
        <<"(?i)(?:Start-Process|saps)(?:$|[^A-Za-z0-9_-])">>,
        <<"(?i)\\[(?:System\\.)?Diagnostics\\.Process\\]"
          "\\s*::\\s*Start\\s*\\(">>,
        <<"(?i)(?:Invoke-Expression|iex|Start-Job|Import-Module|Add-Type)"
          "(?:$|[^A-Za-z0-9_-])">>,
        <<"(?i)\\$env:HTTP_BASH_EXECUTABLE"
          "(?:$|[^A-Za-z0-9_-])">>,
        <<"(?i)(?:PSBoundParameters|ValueFromRemainingArguments|"
          "CmdletBinding)(?:$|[^A-Za-z0-9_-])">>,
        <<"(?i)\\.ReadToEnd(?:Async)?\\s*\\(">>,
        <<"(?i)\\.Arguments\\s*=">>,
        <<"(?i)(?:cmd|taskkill)(?:\\.exe)?(?:$|[^A-Za-z0-9_])">>,
        <<"(?:^|[;{}()\\s])&\\s*(?:[A-Za-z_$]|$)">>
    ],
    RequiredRaw = [
        <<"$entryInput = @($args)">>,
        <<"$entryInput.Count -eq 2">>,
        <<"$entryInput.Count -eq 4">>,
        <<"$entryInput.Count -eq 8">>,
        <<"$entryInput[0] -ceq '-Operation'">>,
        <<"$entryInput[2] -ceq '-Target'">>,
        <<"$entryInput[4] -ceq '-Platform'">>,
        <<"$entryInput[6] -ceq '-Otp'">>,
        <<"$Operation -cnotin @(">>,
        <<"$Target -cnotin @('all', 'http', 'http3', 'core')">>,
        <<"$Target -cnotin @('http', 'http3', 'core')">>,
        <<"$Platform -cne 'windows-2025'">>,
        <<"$Otp -cnotin @('28', '29')">>,
        <<"$entryArguments.Add('--windows-entry')">>,
        <<"$entryArguments.Add($Operation)">>,
        <<"Get-Command -Name 'escript.exe' -CommandType Application">>,
        <<"scripts\\process_runner.escript">>,
        <<"$runnerMaximumBytes = 2097152L">>,
        <<"$startInfo.Environment.Remove('HTTP_BASH_EXECUTABLE')">>,
        <<"Join-Path $env:ProgramFiles 'Git\\bin\\bash.exe'">>,
        <<"foreach ($entryArgument in $entryArguments)">>,
        <<"New-DrainState -Stream $process.StandardError.BaseStream "
          "-CaptureEnabled $false">>,
        <<"'fresh-build' = 600000">>,
        <<"'package-suite' = 1200000">>,
        <<"'runtime-stage' = 150000">>,
        <<"'credential-local' = 3480000">>,
        <<"'canonical_etf_wire_self_test'">>,
        <<"'etf_boundary_audit_self_test'">>,
        <<"'etf_boundary_audit'">>,
        <<"'windows_console_inheritance_audit'">>,
        <<"$configuredSteps = 5">>,
        <<"$configuredRuntime = [string]$env:MISE_ERLANG_VERSION">>,
        <<"$startInfo.Environment['HTTP_WINDOWS_EXPECTED_OTP'] = $safeOtp">>,
        <<"$startInfo.Environment['HTTP_WINDOWS_ESCRIPT_SHA256'] =">>,
        <<"$startInfo.Environment['HTTP_WINDOWS_ESCRIPT_PATH_ID'] =">>,
        <<"$startInfo.Environment['HTTP_WINDOWS_RUNNER_SHA256'] =">>,
        <<"$startInfo.Environment['HTTP_WINDOWS_CONFIGURATION_SHA256'] =">>,
        <<"$escriptMaximumBytes = 134217728L">>,
        <<"function Test-OuterFailureCode">>,
        <<"$safeSteps = @($inner.steps)">>,
        <<"    schema = 1">>,
        <<"    stage = 'windows-headless-entry'">>,
        <<"    operation = $safeOperation">>,
        <<"    target = $safeTarget">>,
        <<"    platform = 'windows-2025'">>,
        <<"    otp = $safeOtp">>,
        <<"    state = if ($passed) { 'Ready' } else { 'Failed' }">>,
        <<"    failure_code = $failureCode">>,
        <<"    configured_steps = $configuredSteps">>,
        <<"    completed_steps = $completedSteps">>,
        <<"    child_started = $childStarted">>,
        <<"    child_joined = $childJoined">>,
        <<"    child_exit_status = $childExitStatus">>,
        <<"    recursive_termination_requested = "
          "$recursiveTerminationRequested">>,
        <<"    deadline_expired = $deadlineExpired">>,
        <<"    output_limit_exceeded = $outputLimitExceeded">>,
        <<"    stdout_bytes = $stdoutBytes">>,
        <<"    stderr_bytes = $stderrBytes">>,
        <<"    streams_drained = (">>,
        <<"    runner_identity_stable = $runnerIdentityStable">>,
        <<"    launcher_identity_stable = $launcherIdentityStable">>,
        <<"    tool_identity_stable = $toolIdentityStable">>,
        <<"    runtime_identity_verified = $runtimeIdentityVerified">>,
        <<"    launcher_sha256 = if (">>,
        <<"    source_sha256 = if (">>,
        <<"    configuration_sha256 = if (">>,
        <<"    tool_name = 'otp-escript'">>,
        <<"    tool_sha256 = if (">>,
        <<"    scope = $safeScope">>,
        <<"    rerun_command = $safeRerunCommand">>,
        <<"    steps = $safeSteps">>,
        <<"    inner_contract_valid = $innerContractValid">>,
        <<"    inner_tree_empty = $innerTreeEmpty">>,
        <<"    inner_console_isolated = $innerConsoleIsolated">>,
        <<"    inner_descendants_joined = $innerDescendantsJoined">>,
        <<"    passed = $passed">>,
        <<"$summary | ConvertTo-Json -Compress -Depth 6">>
    ],
    ForbiddenSummaryFields = [
        <<"process_id =">>, <<"pid =">>, <<"path =">>, <<"argv =">>,
        <<"exception =">>, <<"output_tail =">>,
        <<"output_sha256 =">>
    ],
    lists:all(fun(Pattern) -> regex_match(Code, Pattern) end, RequiredCode)
        andalso lists:all(fun(Pattern) ->
            not regex_match(Code, Pattern)
        end, ForbiddenCode)
        andalso lists:all(fun(Fragment) ->
            binary:match(Bytes, Fragment) =/= nomatch
        end, RequiredRaw)
        andalso lists:all(fun(Fragment) ->
            binary:match(Bytes, Fragment) =:= nomatch
        end, ForbiddenSummaryFields)
        andalso windows_headless_summary_contract(Bytes)
        andalso binary_occurrences(
            Code, <<"$process.Start()">>) =:= 1
        andalso binary_occurrences(
            Code, <<"$Child.Kill($true)">>) =:= 1
        andalso binary_occurrences(
            Code, <<"$entryArguments.Add(">>) =:= 8
        andalso binary_occurrences(
            Bytes, <<"$entryArguments.Add($runner)">>) =:= 1
        andalso binary_occurrences(
            Bytes, <<"$entryArguments.Add('--windows-entry')">>) =:= 1
        andalso binary_occurrences(
            Bytes, <<"$entryArguments.Add($Operation)">>) =:= 1
        andalso binary_occurrences(
            Bytes, <<"$entryArguments.Add($Target)">>) =:= 3
        andalso binary_occurrences(
            Bytes, <<"$entryArguments.Add($Platform)">>) =:= 1
        andalso binary_occurrences(
            Bytes, <<"$entryArguments.Add($Otp)">>) =:= 1;
windows_headless_bootstrap_contract(_) -> false.

windows_headless_summary_contract(Bytes) ->
    case binary_section(Bytes, <<"$summary = [ordered]@{">>,
                        <<"\n}\n\n# Do not forward">>) of
        error -> false;
        {ok, Section} ->
            Fields = lists:filtermap(fun({_Number, Line}) ->
                case re:run(Line, <<"^\\s{4}([a-z_]+)\\s*=">>,
                            [{capture, [1], binary}, unicode]) of
                    {match, [Field]} -> {true, Field};
                    nomatch -> false
                end
            end, numbered_lines(Section)),
            Fields =:= [
                <<"schema">>, <<"stage">>, <<"operation">>, <<"target">>,
                <<"platform">>, <<"otp">>, <<"state">>, <<"failure_code">>,
                <<"configured_steps">>, <<"completed_steps">>,
                <<"child_started">>, <<"child_joined">>,
                <<"child_exit_status">>,
                <<"recursive_termination_requested">>,
                <<"deadline_expired">>, <<"output_limit_exceeded">>,
                <<"stdout_bytes">>, <<"stderr_bytes">>,
                <<"streams_drained">>, <<"runner_identity_stable">>,
                <<"launcher_identity_stable">>,
                <<"tool_identity_stable">>,
                <<"runtime_identity_verified">>,
                <<"launcher_sha256">>, <<"source_sha256">>,
                <<"configuration_sha256">>, <<"tool_name">>,
                <<"tool_sha256">>, <<"scope">>, <<"rerun_command">>,
                <<"steps">>,
                <<"inner_contract_valid">>, <<"inner_tree_empty">>,
                <<"inner_console_isolated">>,
                <<"inner_descendants_joined">>, <<"passed">>
            ]
    end.

windows_entry_runner_contract(Bytes)
  when is_binary(Bytes), byte_size(Bytes) > 0 ->
    case binary_section(Bytes, <<"main([\"--windows-entry\" | Arguments])">>,
                        <<"\nwindows_entry_contract_self_test() ->">>) of
        error -> false;
        {ok, Section} ->
            Required = [
                <<"windows_entry_main(Arguments)">>,
                <<"windows_entry_request([\"fresh-build\", Target])">>,
                <<"windows_entry_request([\"package-suite\", Target])">>,
                <<"windows_entry_request([\"runtime-stage\", Target, "
                  "\"windows-2025\", Otp])">>,
                <<"windows_entry_request([\"credential-local\"])">>,
                <<"when Target =:= \"all\"; Target =:= \"http\"; "
                  "Target =:= \"http3\";">>,
                <<"when Target =:= \"http\"; Target =:= \"http3\"; "
                  "Target =:= \"core\" ->">>,
                <<"Otp =:= \"28\" orelse Otp =:= \"29\"">>,
                <<"os:getenv(\"MISE_ERLANG_VERSION\")">>,
                <<"ConfiguredOtp =:= RuntimeOtp">>,
                <<"{fresh_build, bash, \"scripts/fresh_build.sh\", [Target]}">>,
                <<"{canonical_etf_wire_self_test, escript,">>,
                <<"\"scripts/canonical_etf_wire_self_test.escript\", []}">>,
                <<"{etf_boundary_audit_self_test, escript,">>,
                <<"\"scripts/etf_boundary_audit.escript\", "
                  "[\"--self-test\"]}">>,
                <<"{etf_boundary_audit, escript,">>,
                <<"[\"matrix\", runtime_package, \"windows-2025\", "
                  "runtime_otp]">>,
                <<"{windows_console_inheritance_audit, powershell,">>,
                <<"\"scripts/windows_console_inheritance_audit.ps1\"">>,
                <<"[\"-OtpMajor\", runtime_otp]">>,
                <<"{package_suite, escript, "
                  "\"scripts/package_suite.escript\"">>,
                <<"{runtime_stage, escript, "
                  "\"scripts/runtime_matrix.escript\"">>,
                <<"{credential_self_test, escript, "
                  "\"scripts/test_matrix.escript\"">>,
                <<"{credential_fresh_build, bash, "
                  "\"scripts/fresh_build.sh\", [\"all\"]}">>,
                <<"{credential_matrix, escript, "
                  "\"scripts/test_matrix.escript\"">>,
                <<"deadline_milliseconds => 570000">>,
                <<"deadline_milliseconds => 1170000">>,
                <<"deadline_milliseconds => 120000">>,
                <<"deadline_milliseconds => 3450000">>,
                <<"[\"stage\", Target, \"windows-2025\", Otp]">>,
                <<"[\"--self-test\"]">>,
                <<"[\"credential-local\"]">>,
                <<"Deadline = erlang:monotonic_time(millisecond) +">>,
                <<"maps:get(deadline_milliseconds, Request)">>,
                <<"windows_entry_run_steps(Rest, Deadline, "
                  "[Result | Acc], Failure)">>,
                <<"windows_entry_unstarted_step(Name, Failure)">>,
                <<"windows_entry_executable(powershell)">>,
                <<"[\"-NoLogo\", \"-NoProfile\", \"-NonInteractive\", "
                  "\"-File\", Script |">>,
                <<"run_process_runner_worker(fun() ->">>,
                <<"process_file_snapshot(Script, 2097152)">>,
                <<"process_verify_snapshot(Snapshot, 2097152)">>,
                <<"lists:member(Leaf, Names) andalso "
                  "filelib:is_regular(Path)">>,
                <<"open_owned_process(">>,
                <<"collect_eunit(">>,
                <<"process_completion_attestation_verified(Output)">>,
                <<"process_status_verified(Status, 0, Output)">>,
                <<"os:getenv(\"HTTP_WINDOWS_RUNNER_SHA256\")">>,
                <<"os:getenv(\"HTTP_WINDOWS_ESCRIPT_SHA256\")">>,
                <<"os:getenv(\"HTTP_WINDOWS_ESCRIPT_PATH_ID\")">>,
                <<"os:getenv(\"HTTP_WINDOWS_CONFIGURATION_SHA256\")">>,
                <<"os:getenv(\"HTTP_WINDOWS_EXPECTED_OTP\")">>,
                <<"windows_entry_identity_environment()">>,
                <<"runtime_identity_verified => maps:get(verified, Identity)">>,
                <<"rerun_command => windows_entry_rerun_command(">>,
                <<"windows_entry_request(_) -> "
                  "erlang:error(invalid_windows_entry_arguments)">>
            ],
            Forbidden = [<<"binary_to_atom">>, <<"list_to_atom">>,
                         <<"apply(">>, <<"os:cmd">>, <<"{spawn,">>,
                         <<"output_tail">>,
                         <<"#{command =>">>, <<"path =>">>, <<"pid =>">>,
                         <<"argv =>">>, <<"output =>">>,
                         <<"exception =>">>],
            lists:all(fun(Fragment) ->
                binary:match(Section, Fragment) =/= nomatch
            end, Required)
                andalso lists:all(fun(Fragment) ->
                    binary:match(Section, Fragment) =:= nomatch
                end, Forbidden)
                andalso binary_occurrences(
                    Section, <<"open_owned_process(">>) =:= 1
                andalso binary_occurrences(
                    Section, <<"windows_entry_request([\"">>) =:= 4
    end;
windows_entry_runner_contract(_) -> false.

windows_workflow_entry_contract(Paths, SourceBytes) ->
    Bytes = iolist_to_binary([maps:get(Path, SourceBytes) || Path <- Paths]),
    Required = [
        <<"run: ./scripts/windows_headless_entry.ps1 -Operation fresh-build "
          "-Target \"${{ matrix.target }}\"">>,
        <<"run: ./scripts/windows_headless_entry.ps1 -Operation package-suite "
          "-Target \"${{ matrix.target }}\"">>,
        <<"run: ./scripts/windows_headless_entry.ps1 -Operation runtime-stage "
          "-Target \"${{ matrix.target }}\" -Platform windows-2025 "
          "-Otp \"${{ matrix.otp }}\"">>,
        <<"run: ./scripts/windows_headless_entry.ps1 "
          "-Operation credential-local">>
    ],
    EvidenceRequired = [
        <<"name: etf-boundary-${{ matrix.package }}-${{ matrix.os }}-"
          "otp${{ matrix.otp }}">>,
        <<"path: build/evidence/etf-boundary-matrix/staging/"
          "etf-boundary-${{ matrix.package }}-${{ matrix.os }}-"
          "otp${{ matrix.otp }}/">>,
        <<"name: console-inheritance-${{ matrix.package }}-windows-2025-"
          "otp${{ matrix.otp }}">>,
        <<"path: build/test-runner/windows-console-inheritance-"
          "otp${{ matrix.otp }}.json">>,
        <<"pattern: etf-boundary-*">>,
        <<"path: build/evidence/etf-boundary-matrix/inputs">>,
        <<"run: escript scripts/canonical_etf_wire_self_test.escript">>,
        <<"run: escript scripts/etf_boundary_audit.escript --self-test">>,
        <<"run: escript scripts/etf_boundary_audit.escript matrix "
          "\"${{ matrix.package }}\" \"${{ matrix.os }}\" "
          "\"${{ matrix.otp }}\"">>,
        <<"escript scripts/etf_boundary_matrix.escript --self-test">>,
        <<"escript scripts/etf_boundary_matrix.escript">>
    ],
    lists:all(fun(Fragment) ->
        workflow_exact_line_occurrences(Paths, SourceBytes, Fragment) =:= 1
    end, Required)
        andalso workflow_code_occurrences(
            Bytes, <<"scripts/windows_headless_entry.ps1">>) =:= 4
        andalso lists:all(fun(Fragment) ->
            workflow_code_occurrences(Bytes, Fragment) >= 1
        end, EvidenceRequired)
        andalso workflow_matrix_evidence_verified(Paths, SourceBytes)
        andalso workflow_visibility_evidence_verified(Paths, SourceBytes)
        andalso lists:all(fun(Fragment) ->
            workflow_wrapper_line_verified(Paths, SourceBytes, Fragment)
        end, Required)
        andalso lists:all(fun(Path) ->
            workflow_windows_direct_entries(
                Path, maps:get(Path, SourceBytes)) =:= []
        end, Paths).

workflow_exact_line_occurrences(Paths, SourceBytes, Expected) ->
    length([{Path, Number}
            || Path <- Paths,
               {Number, Line} <- numbered_lines(maps:get(Path, SourceBytes)),
               trim_yaml_line(Line) =:= Expected]).

workflow_code_occurrences(Bytes, Fragment) ->
    Code = iolist_to_binary([[strip_yaml_comment(Line), <<"\n">>]
        || {_Number, Line} <- numbered_lines(Bytes)]),
    binary_occurrences(Code, Fragment).

workflow_wrapper_line_verified(Paths, SourceBytes, Expected) ->
    Matches = [{Number, Lines}
        || Path <- Paths,
           Lines <- [numbered_lines(maps:get(Path, SourceBytes))],
           {Number, Line} <- Lines,
           trim_yaml_line(Line) =:= Expected],
    case Matches of
        [{Number, Lines}] ->
            workflow_job_windows_capable(Number, Lines) andalso
            workflow_step_includes_windows(Number, Lines) andalso
            workflow_step_uses_pwsh(Number, Lines);
        _ -> false
    end.

workflow_matrix_evidence_verified(Paths, SourceBytes) ->
    ExpectedPath = <<"path: build/evidence/etf-boundary-matrix/staging/"
        "etf-boundary-${{ matrix.package }}-${{ matrix.os }}-"
        "otp${{ matrix.otp }}/">>,
    Matches = [{Number, Lines}
        || Path <- Paths,
           Lines <- [numbered_lines(maps:get(Path, SourceBytes))],
           {Number, Line} <- Lines,
           trim_yaml_line(Line) =:= ExpectedPath],
    case Matches of
        [{Number, Lines}] ->
            Step = workflow_step_lines(Number, Lines),
            StepCode = iolist_to_binary([[strip_yaml_comment(Line), <<"\n">>]
                || {_LineNumber, Line} <- Step]),
            workflow_job_windows_capable(Number, Lines) andalso
            binary:match(StepCode, <<"if: always()">>) =/= nomatch andalso
            binary:match(StepCode,
                <<"name: etf-boundary-${{ matrix.package }}-${{ matrix.os }}-"
                  "otp${{ matrix.otp }}">>) =/= nomatch andalso
            binary:match(StepCode, <<"uses: actions/upload-artifact@">>)
                =/= nomatch andalso
            binary:match(StepCode, <<"if-no-files-found: error">>)
                =/= nomatch;
        _ -> false
    end.

workflow_visibility_evidence_verified(Paths, SourceBytes) ->
    ExpectedPath = <<"path: build/test-runner/windows-console-inheritance-"
        "otp${{ matrix.otp }}.json">>,
    Matches = [{Number, Lines}
        || Path <- Paths,
           Lines <- [numbered_lines(maps:get(Path, SourceBytes))],
           {Number, Line} <- Lines,
           trim_yaml_line(Line) =:= ExpectedPath],
    case Matches of
        [{Number, Lines}] ->
            Step = workflow_step_lines(Number, Lines),
            StepCode = iolist_to_binary([[strip_yaml_comment(Line), <<"\n">>]
                || {_LineNumber, Line} <- Step]),
            workflow_job_windows_capable(Number, Lines) andalso
            workflow_step_includes_windows(Number, Lines) andalso
            binary:match(StepCode,
                <<"name: console-inheritance-${{ matrix.package }}-"
                  "windows-2025-otp${{ matrix.otp }}">>) =/= nomatch andalso
            binary:match(StepCode, <<"uses: actions/upload-artifact@">>)
                =/= nomatch andalso
            binary:match(StepCode, <<"if-no-files-found: error">>)
                =/= nomatch;
        _ -> false
    end.

trim_yaml_line(Line) ->
    unicode:characters_to_binary(string:trim(
        unicode:characters_to_list(strip_yaml_comment(Line)))).

windows_mise_entry_contract(Bytes) when is_binary(Bytes) ->
    Required = [
        <<"[tasks.windows-fresh-build]">>,
        <<"[tasks.windows-package-suite]">>,
        <<"[tasks.windows-runtime-stage]">>,
        <<"[tasks.windows-credential-local]">>,
        <<"run = \"pwsh -NoLogo -NoProfile -NonInteractive -File "
          "scripts/windows_headless_entry.ps1 -Operation fresh-build\"">>,
        <<"run = \"pwsh -NoLogo -NoProfile -NonInteractive -File "
          "scripts/windows_headless_entry.ps1 -Operation package-suite\"">>,
        <<"run = \"pwsh -NoLogo -NoProfile -NonInteractive -File "
          "scripts/windows_headless_entry.ps1 -Operation runtime-stage\"">>,
        <<"run = \"pwsh -NoLogo -NoProfile -NonInteractive -File "
          "scripts/windows_headless_entry.ps1 -Operation credential-local\"">>
    ],
    lists:all(fun(Fragment) ->
        binary_occurrences(Bytes, Fragment) =:= 1
    end, Required);
windows_mise_entry_contract(_) -> false.

windows_entry_contract_self_tests() ->
    Bootstrap = bounded_source_bytes("scripts/windows_headless_entry.ps1"),
    Runner = bounded_source_bytes("scripts/process_runner.escript"),
    Inheritance = bounded_source_bytes(
        "scripts/windows_console_inheritance_audit.ps1"),
    Mise = bounded_source_bytes(".mise.toml"),
    WorkflowPaths = authored_workflow_paths(),
    WorkflowBytes = maps:from_list([{Path, bounded_source_bytes(Path)}
                                    || Path <- WorkflowPaths]),
    [CiPath] = [Path || Path <- WorkflowPaths,
        console_normal_path(Path) =:= ".github/workflows/ci.yml"],
    CiBytes = maps:get(CiPath, WorkflowBytes),
    DirectWorkflowBytes = maps:put(CiPath, binary:replace(CiBytes,
        <<"run: ./scripts/windows_headless_entry.ps1 "
          "-Operation package-suite -Target \"${{ matrix.target }}\"">>,
        <<"run: escript scripts/package_suite.escript "
          "\"${{ matrix.target }}\"">>), WorkflowBytes),
    InjectedWorkflowBytes = maps:put(CiPath, binary:replace(CiBytes,
        <<"run: ./scripts/windows_headless_entry.ps1 "
          "-Operation package-suite -Target \"${{ matrix.target }}\"">>,
        <<"run: ./scripts/windows_headless_entry.ps1 "
          "-Operation package-suite -Target \"${{ matrix.target }}\"; "
          "cmd.exe /c injected">>), WorkflowBytes),
    MissingShellWorkflowBytes = maps:put(CiPath, binary:replace(CiBytes,
        <<"shell: pwsh">>, <<"shell: powershell">>), WorkflowBytes),
    MissingEtfEvidenceWorkflowBytes = maps:put(CiPath, binary:replace(CiBytes,
        <<"path: build/evidence/etf-boundary-matrix/staging/"
          "etf-boundary-${{ matrix.package }}-${{ matrix.os }}-"
          "otp${{ matrix.otp }}/">>,
        <<"path: build/evidence/other.json">>), WorkflowBytes),
    UnscopedVisibilityEvidenceWorkflowBytes = maps:put(CiPath,
        binary:replace(CiBytes,
            <<"- name: Preserve the owner-bound Windows visibility proof\n"
              "        if: ${{ always() && runner.os == 'Windows' }}">>,
            <<"- name: Preserve the owner-bound Windows visibility proof\n"
              "        if: always()">>), WorkflowBytes),
    UnboundedRunner = binary:replace(Runner,
        <<"deadline_milliseconds => 1170000">>,
        <<"deadline_milliseconds => infinity">>),
    LeakingRunner = binary:replace(Runner,
        <<"\nwindows_entry_contract_self_test() ->">>,
        <<"\nwindows_entry_leak(Output) -> #{output => Output}.\n"
          "\nwindows_entry_contract_self_test() ->">>),
    ExtraSummaryField = binary:replace(Bootstrap,
        <<"    passed = $passed\n}">>,
        <<"    secret_value = $env:SECRET_VALUE\n"
          "    passed = $passed\n}">>),
    SecretSummaryValue = binary:replace(Bootstrap,
        <<"    target = $safeTarget">>,
        <<"    target = $env:SECRET_VALUE">>),
    Cases = [
        {windows_outer_current,
         windows_headless_bootstrap_contract(Bootstrap), true},
        {windows_outer_missing_use_shell,
         windows_headless_bootstrap_contract(binary:replace(Bootstrap,
            <<"$startInfo.UseShellExecute = $false">>,
            <<"$startInfo.UseShellExecute = $true">>)), false},
        {windows_outer_missing_no_window,
         windows_headless_bootstrap_contract(binary:replace(Bootstrap,
            <<"$startInfo.CreateNoWindow = $true">>,
            <<"$startInfo.CreateNoWindow = $false">>)), false},
        {windows_outer_missing_hidden,
         windows_headless_bootstrap_contract(binary:replace(Bootstrap,
            <<"$startInfo.WindowStyle = "
              "[System.Diagnostics.ProcessWindowStyle]::Hidden">>,
            <<"$startInfo.WindowStyle = "
               "[System.Diagnostics.ProcessWindowStyle]::Normal">>)), false},
        {windows_outer_widened_target,
         windows_headless_bootstrap_contract(binary:replace(Bootstrap,
            <<"$Target -cnotin @('http', 'http3', 'core')">>,
            <<"$false">>)), false},
        {windows_outer_module_bypass,
         windows_headless_bootstrap_contract(<<Bootstrap/binary,
            "\nImport-Module private-launcher\n">>), false},
        {windows_outer_inherited_bash_override,
         windows_headless_bootstrap_contract(<<Bootstrap/binary,
            "\n$gitBash = $env:HTTP_BASH_EXECUTABLE\n">>), false},
        {windows_outer_dynamic_entry,
         windows_headless_bootstrap_contract(binary:replace(Bootstrap,
            <<"$entryArguments.Add('--windows-entry')">>,
            <<"$entryArguments.Add($untrustedEntry)">>)), false},
        {windows_outer_extra_argument_source,
         windows_headless_bootstrap_contract(binary:replace(Bootstrap,
            <<"$entryArguments.Add($Operation)">>,
            <<"$entryArguments.Add($Operation)\n"
              "$entryArguments.Add($RemainingArguments[0])">>)), false},
        {windows_outer_publishes_path,
         windows_headless_bootstrap_contract(<<Bootstrap/binary,
            "\n$summary.path = $runner\n">>), false},
        {windows_outer_extra_summary_field,
         windows_headless_bootstrap_contract(ExtraSummaryField), false},
        {windows_outer_secret_summary_value,
         windows_headless_bootstrap_contract(SecretSummaryValue), false},
        {windows_outer_unbound_escript_identity,
         windows_headless_bootstrap_contract(binary:replace(Bootstrap,
            <<"$startInfo.Environment['HTTP_WINDOWS_ESCRIPT_SHA256'] =">>,
            <<"$discardedIdentity =">>)), false},
        {windows_inheritance_current,
         windows_inheritance_launcher_contract(Inheritance), true},
        {windows_inheritance_unbounded_read,
         windows_inheritance_launcher_contract(<<Inheritance/binary,
            "\n$fixture.StandardOutput.ReadToEndAsync()\n">>), false},
        {windows_inheritance_missing_no_window,
         windows_inheritance_launcher_contract(binary:replace(Inheritance,
            <<"$outsiderStart.CreateNoWindow = $true">>,
            <<"$outsiderStart.CreateNoWindow = $false">>)), false},
        {windows_inheritance_module_bypass,
         windows_inheritance_launcher_contract(<<Inheritance/binary,
            "\nImport-Module private-launcher\n">>), false},
        {windows_inheritance_unbound_escript,
         windows_inheritance_launcher_contract(binary:replace(Inheritance,
            <<"$escriptHashBefore -cne $expectedEscriptHash">>,
            <<"$false">>)), false},
        {windows_runner_current,
         windows_entry_runner_contract(Runner), true},
        {windows_runner_dynamic_dispatch,
         windows_entry_runner_contract(binary:replace(Runner,
            <<"windows_entry_request(_) -> "
              "erlang:error(invalid_windows_entry_arguments)">>,
             <<"windows_entry_request(Arguments) -> apply(user_module, "
               "run, Arguments)">>)), false},
        {windows_runner_unbounded_operation,
         windows_entry_runner_contract(UnboundedRunner), false},
        {windows_runner_output_leak,
         windows_entry_runner_contract(LeakingRunner), false},
        {windows_runner_early_step_stop,
         windows_entry_runner_contract(binary:replace(Runner,
            <<"windows_entry_run_steps(Rest, Deadline, "
              "[Result | Acc], Failure).">>,
            <<"{lists:reverse([Result | Acc]), Failure}.">>)), false},
        {windows_runner_unbound_runtime,
         windows_entry_runner_contract(binary:replace(Runner,
            <<"os:getenv(\"HTTP_WINDOWS_ESCRIPT_SHA256\")">>,
            <<"os:getenv(\"IGNORED_ESCRIPT_SHA256\")">>)), false},
        {windows_mise_current, windows_mise_entry_contract(Mise), true},
        {windows_mise_direct_child,
         windows_mise_entry_contract(binary:replace(Mise,
            <<"scripts/windows_headless_entry.ps1 "
              "-Operation package-suite">>,
            <<"scripts/package_suite.escript">>)), false},
        {windows_workflow_current,
         windows_workflow_entry_contract(WorkflowPaths, WorkflowBytes), true},
        {windows_workflow_direct_escript,
          windows_workflow_entry_contract(
            WorkflowPaths, DirectWorkflowBytes), false},
        {windows_workflow_appended_command,
         windows_workflow_entry_contract(
            WorkflowPaths, InjectedWorkflowBytes), false},
        {windows_workflow_missing_pwsh,
         windows_workflow_entry_contract(
            WorkflowPaths, MissingShellWorkflowBytes), false},
        {windows_workflow_missing_etf_evidence,
         windows_workflow_entry_contract(
            WorkflowPaths, MissingEtfEvidenceWorkflowBytes), false},
        {windows_workflow_unscoped_visibility_evidence,
         windows_workflow_entry_contract(
            WorkflowPaths, UnscopedVisibilityEvidenceWorkflowBytes), false}
    ],
    [#{kind => Kind, expected => Expected, observed => Observed,
       passed => Observed =:= Expected}
     || {Kind, Observed, Expected} <- Cases].

binary_section(Bytes, Start, Finish) ->
    case binary:match(Bytes, Start) of
        nomatch -> error;
        {StartAt, _} ->
            Rest = binary:part(Bytes, StartAt, byte_size(Bytes) - StartAt),
            case binary:match(Rest, Finish) of
                nomatch -> error;
                {FinishAt, _} -> {ok, binary:part(Rest, 0, FinishAt)}
            end
    end.

binary_occurrences(Bytes, Fragment) when byte_size(Fragment) > 0 ->
    length(binary:matches(Bytes, Fragment)).

source_bytes_by_normal_path(Expected, SourceBytes) ->
    case [Bytes || {Path, Bytes} <- maps:to_list(SourceBytes),
                   console_normal_path(Path) =:= Expected] of
        [Bytes] -> Bytes;
        _ -> <<>>
    end.

lexical_self_tests() ->
    Cases = [
        {hidden, <<"f() -> open_port({spawn_executable, E}, [binary, hide]).">>, [true]},
        {missing, <<"f() -> open_port({spawn_executable, E}, [binary]).">>, [false]},
        {comment_decoy, <<"f() -> open_port({spawn_executable, E}, [binary % , hide\n]).">>, [false]},
        {string_decoy, <<"f() -> open_port({spawn_executable, E}, [binary, {env, [{\"X\", \"hide\"}]}]).">>, [false]},
        {nested_atom_decoy, <<"f() -> open_port({spawn_executable, E}, [binary, {env, [{x, hide}]}]).">>, [false]},
        {spawn_hidden, <<"f() -> open_port({spawn, E}, [binary, hide]).">>, [true]},
        {spawn_missing, <<"f() -> open_port({spawn, E}, [binary]).">>, [false]}
    ],
    [begin
        Observed = [maps:get(hidden, Row) || Row <- calls(lex(Source), <<"fixture">>)],
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Source, Expected} <- Cases].

ownership_self_tests() ->
    Safe = supervisor_fixture(<<>>),
    NamedBypass = <<"open_owned_process(E,A,D,V,T) ->\n"
        " P=open_port({spawn_executable,E},[binary,hide]), P.\n">>,
    StringDecoy = <<"open_owned_process(E,A,D,V,T) ->\n"
        " _=\"scripts/process_supervisor.py process_supervisor_sha256() "
        "{packet, 4} await_supervisor_handshake( activate_process_supervisor(\",\n"
        " open_port({spawn_executable,E},[binary,hide]).\n">>,
    CommentDecoy = <<"open_owned_process(E,A,D,V,T) ->\n"
        " %% scripts/process_supervisor.py process_supervisor_sha256() "
        "{packet, 4} await_supervisor_handshake( activate_process_supervisor(\n"
        " open_port({spawn_executable,E},[binary,hide]).\n">>,
    WrongHash = binary:replace(Safe, <<"binary_to_list(Expected)">>,
                               <<"binary_to_list(Executable)">>),
    MissingFlag = binary:replace(Safe, <<"\"--expected-sha256\"">>,
                                 <<"\"--wrong\"">>),
    NestedOptions = binary:replace(Safe, <<"[binary,exit_status,use_stdio,"
        "stderr_to_stdout,hide,{packet,4},">>, <<"[[binary,hide,{packet,4}],"
        "exit_status,use_stdio,stderr_to_stdout,">>),
    SiblingStart = binary:replace(Safe, <<"port_command(P,<<\"START\">>)">>,
                                  <<"port_command(Other,<<\"START\">>)">>),
    BranchedStart = binary:replace(Safe,
        <<"fun(P)->port_command(P,<<\"START\">>) end">>,
        <<"fun(P)->case true of true->port_command(P,<<\"START\">>) end end">>),
    WrongEnvironment = binary:replace(Safe,
        <<"SupervisorEnvironment=supervisor_environment(Environment)">>,
        <<"SupervisorEnvironment=Environment">>),
    ForgedIdentity = binary:replace(Safe, <<"Identity=Runtime">>,
                                    <<"Identity=ProvisionalIdentity">>),
    Reordered = binary:replace(Safe,
        <<" ScriptSnapshot=process_file_snapshot(Script,131072),\n"
          " Expected=maps:get(sha256,ScriptSnapshot),\n">>,
        <<" Expected=maps:get(sha256,ScriptSnapshot),\n"
          " ScriptSnapshot=process_file_snapshot(Script,131072),\n">>),
    MissingPythonAttestation = binary:replace(Safe,
        <<",\"--expected-python-sha256\",binary_to_list(PythonSha)">>, <<>>),
    MissingTrap = binary:replace(Safe,
        <<" ok=acquire_owned_port_trap(),\n">>, <<>>),
    MissingPostVerify = binary:replace(Safe,
        <<"   try ok=process_verify_snapshot(ScriptSnapshot,131072),\n"
          "       ok=process_verify_snapshot(PythonSnapshot,134217728)\n">>,
        <<"   try ok\n">>),
    EarlyUnregister = binary:replace(Safe,
        <<"case recover_owned_supervisor(Port,ProvisionalIdentity,"
          "fun close_owned_port/1) of\n"
          "    confirmed->erlang:error(Category);\n">>,
        <<"unregister_owned_tree(Port),\n"
          "   case recover_owned_supervisor(Port,ProvisionalIdentity,"
          "fun close_owned_port/1) of\n"
          "    confirmed->erlang:error(Category);\n">>),
    ReorderedPython = binary:replace(Safe,
        <<" PythonSnapshot=process_file_snapshot(Python,134217728),\n"
          " PythonSha=maps:get(sha256,PythonSnapshot),\n">>,
        <<" Python=process_supervisor_python(),\n"
          " PythonSha=maps:get(sha256,PythonSnapshot),\n">>),
    Duplicate = binary:replace(Safe, <<" Port=try open_port">>,
        <<"_Q=open_port({spawn_executable,Python},[binary,hide,{packet,4},"
          "{args,SupervisorArguments},{cd,Directory},{env,SupervisorEnvironment}]),\n"
          " Port=try open_port">>),
    VariableSpec = binary:replace(Safe,
        <<" Port=try open_port({spawn_executable,Python}">>,
        <<" Spec={spawn_executable,Python},\n Port=try open_port(Spec">>),
    BranchOpen0 = binary:replace(Safe, <<" Port=try open_port">>,
                                 <<" Port=case true of true -> try open_port">>),
    BranchOpen = binary:replace(BranchOpen0,
        <<"catch error:Reason -> erlang:error({child_start_failed,Reason}) end,\n"
          " HandshakeDeadline">>,
        <<"catch error:Reason -> erlang:error({child_start_failed,Reason}) end end,\n"
          " HandshakeDeadline">>),
    DuplicateOption = binary:replace(Safe,
        <<"[binary,exit_status,use_stdio,stderr_to_stdout,hide,{packet,4}">>,
        <<"[binary,binary,exit_status,use_stdio,stderr_to_stdout,hide,{packet,4}">>),
    InfiniteHandshake = binary:replace(Safe,
        <<"HandshakeDeadline=erlang:min(Deadline,"
          "erlang:monotonic_time(millisecond)+5000)">>,
        <<"HandshakeDeadline=infinity">>),
    WrongFailureClose = binary:replace(Safe,
        <<"recover_owned_supervisor(Port,ProvisionalIdentity,"
          "fun close_owned_port/1)">>,
        <<"recover_owned_supervisor(Other,ProvisionalIdentity,"
          "fun close_owned_port/1)">>),
    WrongActivationDeadline = binary:replace(Safe,
        <<"activate_process_supervisor(Port,Identity,Deadline,">>,
        <<"activate_process_supervisor(Port,Identity,HandshakeDeadline,">>),
    Sibling = <<(supervisor_fixture(<<>>))/binary,
        "unsafe(E) ->\n open_port({spawn_executable,E},[binary,hide]).\n">>,
    Cases = [
        {pinned_supervisor, "scripts/process_runner.hrl", Safe, [true]},
        {named_bypass, "scripts/process_runner.hrl", NamedBypass, [false]},
        {string_decoy, "scripts/process_runner.hrl", StringDecoy, [false]},
        {comment_decoy, "scripts/process_runner.hrl", CommentDecoy, [false]},
        {wrong_hash_variable, "scripts/process_runner.hrl", WrongHash, [false]},
        {missing_expected_flag, "scripts/process_runner.hrl", MissingFlag, [false]},
        {nested_option_decoy, "scripts/process_runner.hrl", NestedOptions, [false]},
        {start_on_sibling_port, "scripts/process_runner.hrl", SiblingStart, [false]},
        {branched_start_callback, "scripts/process_runner.hrl", BranchedStart,
         [false]},
        {wrong_environment_binding, "scripts/process_runner.hrl", WrongEnvironment,
         [false]},
        {forged_identity, "scripts/process_runner.hrl", ForgedIdentity, [false]},
        {reordered_handshake, "scripts/process_runner.hrl", Reordered, [false]},
        {missing_python_attestation, "scripts/process_runner.hrl",
         MissingPythonAttestation, [false]},
        {missing_trap_acquisition, "scripts/process_runner.hrl", MissingTrap,
         [false]},
        {missing_post_handshake_snapshot_verification,
         "scripts/process_runner.hrl", MissingPostVerify, [false]},
        {early_unregister, "scripts/process_runner.hrl", EarlyUnregister,
         [false]},
        {reordered_python_snapshot, "scripts/process_runner.hrl",
         ReorderedPython, [false]},
        {duplicate_launcher, "scripts/process_runner.hrl", Duplicate, [false, false]},
        {variable_spawn_spec, "scripts/process_runner.hrl", VariableSpec, [false]},
        {branch_distributed_launcher, "scripts/process_runner.hrl", BranchOpen,
         [false]},
        {duplicate_option, "scripts/process_runner.hrl", DuplicateOption, [false]},
        {unbounded_handshake_deadline, "scripts/process_runner.hrl",
         InfiniteHandshake, [false]},
        {wrong_failure_close_port, "scripts/process_runner.hrl",
         WrongFailureClose, [false]},
        {wrong_activation_deadline, "scripts/process_runner.hrl",
         WrongActivationDeadline, [false]},
        {untrusted_path, "scripts/other.hrl", Safe, [false]},
        {sibling_bypass, "scripts/process_runner.hrl", Sibling, [true, false]}
    ],
    [begin
        Calls = maps:get(calls, source_audit(Path, Source)),
        Observed = [maps:get(owned_supervisor, Call) || Call <- Calls],
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Path, Source, Expected} <- Cases].

supervisor_fixture(Suffix) ->
    <<"open_owned_process(Executable,Arguments,Directory,Environment,Deadline) ->\n"
      " Script=filename:absname(\"scripts/process_supervisor.py\"),\n"
      " Expected=process_supervisor_sha256(),\n"
      " ScriptSnapshot=process_file_snapshot(Script,131072),\n"
      " Expected=maps:get(sha256,ScriptSnapshot),\n"
      " Python=process_supervisor_python(),\n"
      " PythonSnapshot=process_file_snapshot(Python,134217728),\n"
      " PythonSha=maps:get(sha256,PythonSnapshot),\n"
      " SupervisorDuration=erlang:max(1,erlang:min(5400000,Deadline-"
      "erlang:monotonic_time(millisecond))),\n"
      " SupervisorOutputLimit=16777216,\n"
      " SupervisorArguments=[\"-I\",\"-B\",Script,\"--expected-sha256\","
      "binary_to_list(Expected),\"--expected-python-sha256\","
      "binary_to_list(PythonSha),\"--deadline-ms\","
      "integer_to_list(SupervisorDuration),\"--output-limit-bytes\","
      "integer_to_list(SupervisorOutputLimit),\"--\",Executable|Arguments],\n"
      " SupervisorEnvironment=supervisor_environment(Environment),\n"
      " ok=acquire_owned_port_trap(),\n"
      " Port=try open_port({spawn_executable,Python},[binary,exit_status,use_stdio,"
      "stderr_to_stdout,hide,{packet,4},{args,SupervisorArguments},"
      "{cd,Directory},{env,SupervisorEnvironment}]) "
      "catch error:Reason -> release_owned_port_trap(),"
      "erlang:error({child_start_failed,child_start_category(Reason)}) end,\n"
      " ProvisionalIdentity=#{source_sha256=>Expected,"
      "python_executable_sha256=>PythonSha,console_isolation=>conpty,"
      "python_implementation=><<\"pending\">>,python_version=><<>>},\n"
      " put({process_runner_owned_tree,Port},#{supervisor_identity=>"
      "ProvisionalIdentity,os_pid=>unavailable,termination_requested=>false,"
      "trap_acquired=>true}),\n"
      " case try_register_owned_tree(Port,ProvisionalIdentity) of\n"
      "  ok->ok; error->put({process_runner_owned_tree,Port},"
      "#{supervisor_identity=>ProvisionalIdentity,os_pid=>unavailable,"
      "termination_requested=>false,trap_acquired=>true}),\n"
      "   case recover_owned_supervisor(Port,ProvisionalIdentity,"
      "fun close_owned_port/1) of\n"
      "    confirmed->erlang:error(process_supervisor_registration_failed);\n"
      "    unconfirmed->erlang:error(child_exit_unconfirmed) end end,\n"
      " HandshakeDeadline=erlang:min(Deadline,"
      "erlang:monotonic_time(millisecond)+5000),\n"
      " case await_supervisor_handshake(Port,Expected,PythonSha,SupervisorDuration,"
      "SupervisorOutputLimit,HandshakeDeadline) of\n"
      "  {ok,Runtime}->Identity=Runtime,\n"
      "   try ok=process_verify_snapshot(ScriptSnapshot,131072),\n"
      "       ok=process_verify_snapshot(PythonSnapshot,134217728)\n"
      "   catch _:_ -> case recover_owned_supervisor(Port,ProvisionalIdentity,"
      "fun close_owned_port/1) of\n"
      "    confirmed->erlang:error(process_supervisor_identity_changed);\n"
      "    unconfirmed->erlang:error(child_exit_unconfirmed) end end,\n"
      "   ok=activate_process_supervisor(Port,Identity,Deadline,"
      "fun register_owned_tree/2,fun(P)->port_command(P,<<\"START\">>) end,"
      "fun close_owned_port/1),{Port,Identity};\n"
      "  {error,Category}->case recover_owned_supervisor(Port,"
      "ProvisionalIdentity,fun close_owned_port/1) of\n"
      "    confirmed->erlang:error(Category);\n"
      "    unconfirmed->erlang:error(child_exit_unconfirmed) end\n"
      " end.\n", Suffix/binary>>.

activation_recovery_self_tests() ->
    Safe = activation_recovery_fixture(),
    UnsafeImmediateClose = binary:replace(Safe,
        <<"case recover_owned_supervisor(Port,Identity,Close) of\n"
          "     confirmed->erlang:error(process_supervisor_registration_failed);\n"
          "     unconfirmed->erlang:error(child_exit_unconfirmed) end">>,
        <<"unregister_owned_tree(Port),Close(Port),\n"
          "   erlang:error(process_supervisor_registration_failed)">>),
    MissingStop = binary:replace(Safe, <<"_=kill_owned_child(Port),\n">>, <<>>),
    MissingJoin = binary:replace(Safe,
        <<"await_child_exit(Port,new_output(Identity),TeardownDeadline)">>,
        <<"{pending,undefined}">>),
    ForgedResult = binary:replace(Safe,
        <<"Result=try _=kill_owned_child(Port),\n"
          "   await_child_exit(Port,new_output(Identity),TeardownDeadline)\n"
          "  catch _:_->{pending,undefined} end">>,
        <<"Result={exited,forged}">>),
    WrongDeadline = binary:replace(Safe,
        <<"TeardownDeadline=erlang:monotonic_time(millisecond)+5000">>,
        <<"TeardownDeadline=infinity">>),
    EarlyUnregister = binary:replace(Safe,
        <<"_=kill_owned_child(Port),\n">>,
        <<"unregister_owned_tree(Port),\n   _=kill_owned_child(Port),\n">>),
    MissingClose = binary:replace(Safe,
        <<" safe_close_callback(Close,Port),\n">>, <<>>),
    PrematurePendingUnregister = binary:replace(Safe,
        <<" safe_close_callback(Close,Port),\n"
          " unregister_owned_tree(Port),\n">>,
        <<" unregister_owned_tree(Port),\n"
          " safe_close_callback(Close,Port),\n">>),
    MissingIdentityGuard = binary:replace(Safe,
        <<" ensure_owned_identity(Port,Identity),\n">>, <<>>),
    DeadlineCoupledCleanup = binary:replace(Safe,
        <<"TeardownDeadline=erlang:monotonic_time(millisecond)+5000">>,
        <<"TeardownDeadline=erlang:min(Deadline,"
          "erlang:monotonic_time(millisecond)+5000)">>),
    Cases = [
        {activation_recovery_safe, Safe, true},
        {activation_immediate_close, UnsafeImmediateClose, false},
        {activation_missing_stop, MissingStop, false},
        {activation_missing_join, MissingJoin, false},
        {activation_forged_final, ForgedResult, false},
        {activation_unbounded_teardown, WrongDeadline, false},
        {activation_early_unregister, EarlyUnregister, false},
        {activation_missing_failure_close, MissingClose, false},
        {activation_pending_unregistered, PrematurePendingUnregister, false},
        {activation_missing_identity_guard, MissingIdentityGuard, false},
        {activation_cleanup_coupled_to_operation_deadline,
         DeadlineCoupledCleanup, false}
    ],
    [begin
        Observed = activation_recovery_contract(Source),
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Source, Expected} <- Cases].

activation_recovery_fixture() ->
    <<"activate_process_supervisor(Port,Identity,Deadline,Register,Start,Close) ->\n"
      " ensure_owned_identity(Port,Identity),\n"
      " Registered=try Register(Port,Identity) of ok->true;_->false "
      "catch _:_ -> false end,\n"
      " case Registered of\n"
      "  false->case recover_owned_supervisor(Port,Identity,Close) of\n"
      "     confirmed->erlang:error(process_supervisor_registration_failed);\n"
      "     unconfirmed->erlang:error(child_exit_unconfirmed) end;\n"
      "  true->Started=try Start(Port) of true->true;_->false "
      "catch _:_ -> false end,\n"
      "   case Started of true->ok; false->\n"
      "    case recover_uncertain_supervisor_start(Port,Identity,Deadline,Close) of\n"
      "     confirmed->erlang:error(process_supervisor_start_unconfirmed);\n"
      "     unconfirmed->erlang:error(child_exit_unconfirmed) end\n"
      "   end end.\n"
      "recover_uncertain_supervisor_start(Port,Identity,Deadline,Close) ->\n"
      " true=is_integer(Deadline),\n"
      " recover_owned_supervisor(Port,Identity,Close).\n"
      "recover_owned_supervisor(Port,Identity,Close) ->\n"
      " TeardownDeadline=erlang:monotonic_time(millisecond)+5000,\n"
      " Result=try _=kill_owned_child(Port),\n"
      "   await_child_exit(Port,new_output(Identity),TeardownDeadline)\n"
      "  catch _:_->{pending,undefined} end,\n"
      " case Result of\n"
      "  {exited,_Attested}->unregister_owned_tree(Port),"
      "safe_close_callback(Close,Port),confirmed;\n"
      "  _->retire_unconfirmed_owned_tree(Port,Close),unconfirmed end.\n"
      "safe_close_callback(Close,Port) ->\n"
      " try Close(Port) of _->ok catch _:_ -> ok end.\n"
      "retire_unconfirmed_owned_tree(Port,Close) ->\n"
      " safe_close_callback(Close,Port),\n"
      " unregister_owned_tree(Port),\n"
      " ok.\n">>.

macro_self_tests() ->
    Cases = [
        {command_macro, <<"f() -> ?assertCmdStatus(0, \"fixed\").">>, 1},
        {command_macro_comment, <<"%% ?assertCmdOutput(\"x\", \"y\")\nf() -> ok.">>, 0},
        {command_macro_string, <<"f() -> \"?assertCmd(ignored)\".">>, 0}
    ],
    [begin
        Observed = length(command_macros(lex(Source), <<"fixture">>)),
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Source, Expected} <- Cases].

dynamic_spawn_self_tests() ->
    Cases = [
        {os_cmd, <<"f() -> os:cmd(\"fixed\").">>, [os_cmd]},
        {remote_open_port,
         <<"f() -> erlang:open_port({spawn_executable,E},[hide]).">>,
         [spawn_executable]},
        {apply_open_port,
         <<"f() -> apply(erlang, open_port, [{spawn_executable,E},[hide]]).">>,
         [dynamic_open_port]},
        {remote_apply_open_port,
         <<"f() -> erlang:apply(erlang,open_port,[{spawn_executable,E},[hide]]).">>,
         [dynamic_open_port]},
        {apply_os_cmd,
         <<"f() -> apply(os,cmd,[\"fixed\"]).">>, [dynamic_os_cmd]},
        {open_port_fun,
         <<"f() -> fun erlang:open_port/2.">>, [open_port_fun]},
        {os_cmd_fun,
         <<"f() -> fun os:cmd/1.">>, [os_cmd_fun]},
        {variable_open_port,
         <<"f(Spec,Opts) -> open_port(Spec,Opts).">>, [unknown]},
        {dynamic_comment, <<"%% os:cmd(\"ignored\")\nf() -> ok.">>, []},
        {dynamic_string, <<"f() -> \"apply(erlang, open_port, [])\".">>, []}
    ],
    [begin
        Tokens = lex(Source),
        Direct = [maps:get(kind, Row) || Row <- calls(Tokens, <<"fixture">>)],
        Dynamic = [maps:get(kind, Row) || Row <- dynamic_spawns(Tokens,
                                                                <<"fixture">>)],
        Observed = Direct ++ Dynamic,
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Source, Expected} <- Cases].

native_script_self_tests() ->
    PythonCases = [
        {python_subprocess, <<"subprocess.Popen([tool])\n">>, 1, 0},
        {python_comment, <<"# subprocess.Popen([tool])\n">>, 0, 0},
        {python_string, <<"note = 'subprocess.Popen([tool])'\n">>, 0, 0},
        {python_new_console,
         <<"subprocess.Popen([tool], creationflags=CREATE_NEW_CONSOLE)\n">>,
         1, 1},
        {python_detached,
         <<"subprocess.run([tool], creationflags=DETACHED_PROCESS)\n">>,
         1, 1},
        {python_alloc_console, <<"ctypes.windll.kernel32.AllocConsole()\n">>,
         0, 1}
    ],
    PythonRows = [begin
        Audit = native_script_audit("fixture.py", Source),
        Observed = [length(maps:get(launches, Audit)),
                    length(maps:get(unsafe_flags, Audit))],
        Expected = [Launches, Unsafe],
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Source, Launches, Unsafe} <- PythonCases],
    PowerShellCases = [
        {powershell_hidden,
         <<"Start-Process -FilePath $tool -WindowStyle Hidden -PassThru\n">>,
         1, 0},
        {powershell_visible,
         <<"Start-Process -FilePath $tool -PassThru\n">>, 1, 1},
        {powershell_comment,
         <<"# Start-Process -FilePath visible\n">>, 0, 0},
        {powershell_string,
         <<"$note = 'Start-Process -FilePath visible'\n">>, 0, 0},
        {powershell_diagnostics_start,
         <<"[System.Diagnostics.Process]::Start($info)\n">>, 1, 1},
        {powershell_short_diagnostics_start,
         <<"[Diagnostics.Process]::Start($info)\n">>, 1, 1},
        {powershell_instance_start_bypass,
         <<"$process = [Diagnostics.Process]::new()\n"
           "$process.Start()\n">>, 1, 1},
        {powershell_module_qualified_start,
         <<"Microsoft.PowerShell.Management\\Start-Process "
           "-FilePath $tool\n">>, 1, 1},
        {powershell_saps_alias,
         <<"saps -FilePath $tool\n">>, 1, 1},
        {powershell_call_operator,
         <<"& cmd.exe /c fixed\n">>, 1, 1},
        {powershell_invoke_expression,
         <<"Invoke-Expression $fixed\n">>, 1, 1},
        {powershell_iex_alias,
         <<"iex $fixed\n">>, 1, 1},
        {powershell_start_job,
         <<"Start-Job -ScriptBlock { fixed }\n">>, 1, 1},
        {powershell_dynamic_comment,
         <<"# & cmd.exe /c ignored\n">>, 0, 0},
        {powershell_dynamic_string,
         <<"$note = '[Diagnostics.Process]::Start()'\n">>, 0, 0}
    ],
    PowerShellRows = [begin
        Audit = native_script_audit("fixture.ps1", Source),
        Observed = [length(maps:get(launches, Audit)),
                    length(maps:get(unsafe_flags, Audit))],
        Expected = [Launches, Unsafe],
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Source, Launches, Unsafe} <- PowerShellCases],
    WorkflowCases = [
        {workflow_direct_python,
         <<"steps:\n  - run: python scripts/tool.py\n">>, 1},
        {workflow_comment,
         <<"steps:\n  # run: python scripts/tool.py\n  - run: echo fixed\n">>, 0}
    ],
    WorkflowRows = [begin
        Observed = length(workflow_python_launches("fixture.yml", Source)),
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Source, Expected} <- WorkflowCases],
    WindowsWorkflowCases = [
        {workflow_windows_bash,
         <<"jobs:\n  runtime:\n    runs-on: windows-2025\n"
           "    steps:\n      - name: bad\n"
           "        shell: bash\n        run: bash scripts/tool.sh\n">>, 2},
        {workflow_windows_escript_block,
         <<"jobs:\n  runtime:\n    runs-on: windows-2025\n"
           "    steps:\n      - name: bad\n        run: |\n"
           "          escript scripts/tool.escript\n">>, 1},
        {workflow_windows_cmd,
         <<"jobs:\n  runtime:\n    runs-on: windows-2025\n"
           "    steps:\n      - name: bad\n"
           "        run: cmd.exe /c fixed\n">>, 1},
        {workflow_windows_unix_only,
         <<"jobs:\n  runtime:\n    runs-on: windows-2025\n"
           "    steps:\n      - name: unix\n"
           "        if: runner.os != 'Windows'\n"
           "        run: mise run fixed\n">>, 0},
        {workflow_windows_exclusion_comment_decoy,
         <<"jobs:\n  runtime:\n    runs-on: windows-2025\n"
           "    steps:\n      - name: bad\n"
           "        # if: runner.os != 'Windows'\n"
           "        run: mise run fixed\n">>, 1},
        {workflow_windows_exclusion_run_decoy,
         <<"jobs:\n  runtime:\n    runs-on: windows-2025\n"
           "    steps:\n      - name: bad\n"
           "        run: echo \"if: runner.os != 'Windows'\"; "
           "mise run fixed\n">>, 1},
        {workflow_windows_quoted_hash_then_cmd,
         <<"jobs:\n  runtime:\n    runs-on: windows-2025\n"
           "    steps:\n      - name: bad\n"
           "        run: echo \"#\"; cmd.exe /c fixed\n">>, 1},
        {workflow_windows_headless_entry,
         <<"jobs:\n  runtime:\n    runs-on: windows-2025\n"
           "    steps:\n      - name: safe\n        shell: pwsh\n"
           "        run: ./scripts/windows_headless_entry.ps1 "
           "-Operation credential-local\n">>, 0},
        {workflow_windows_comment,
         <<"jobs:\n  runtime:\n    runs-on: windows-2025\n"
           "    steps:\n      # run: bash ignored\n"
           "      - name: safe\n        run: ./fixed.ps1\n">>, 0}
    ],
    WindowsWorkflowRows = [begin
        Observed = length(workflow_windows_direct_entries(
            "fixture.yml", Source)),
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Source, Expected} <- WindowsWorkflowCases],
    PythonRows ++ PowerShellRows ++ WorkflowRows ++ WindowsWorkflowRows.

python_ast_self_test() ->
    {Output, Proof} = run_python_audit("--self-test"),
    Expected = <<"windows_console_python_audit self_test passed=true controls=74\n">>,
    Passed = Output =:= Expected andalso command_success_verified(Proof),
    case Passed of
        true -> ok;
        false ->
            io:format(standard_error,
                      "python AST self-test contract mismatch: ~p~n",
                       [#{output_bytes => byte_size(Output),
                          failure_code => python_ast_marker_mismatch,
                          command_verified => command_success_verified(Proof)}])
    end,
    #{kind => python_ast_adversarial_controls, expected => true,
      observed => Passed, passed => Passed}.

python_ast_audit(Paths0, SourceBytes) ->
    PythonPaths = [Path || Path <- Paths0, filename:extension(Path) =:= ".py"],
    {Output, Proof} = run_python_audit("--audit"),
    true = command_success_verified(Proof),
    Report = json:decode(Output),
    true = lists:sort(maps:keys(Report)) =:= lists:sort([
        <<"schema">>, <<"source_files">>, <<"source_sha256">>,
        <<"launches">>, <<"unsafe">>, <<"passed">>]),
    true = maps:get(<<"schema">>, Report) =:= 1,
    true = maps:get(<<"source_files">>, Report) =:= length(PythonPaths),
    true = maps:get(<<"source_sha256">>, Report) =:=
        python_source_digest(PythonPaths, SourceBytes),
    lists:foreach(fun validate_python_finding/1,
        maps:get(<<"launches">>, Report) ++ maps:get(<<"unsafe">>, Report)),
    Report.

run_python_audit(Mode) ->
    Python = process_supervisor_python(),
    Script = filename:absname("scripts/windows_console_python_audit.py"),
    case command_capture(Python, ["-I", "-B", Script, Mode],
                         filename:absname("."), 30000, 2097152, []) of
        {ok, RawOutput, Proof} ->
            case python_console_payload(RawOutput) of
                {ok, Output} -> {Output, Proof};
                {error, FailureCode} ->
                    io:format(standard_error,
                        "python console transcript rejected: ~p~n",
                        [#{output_bytes => byte_size(RawOutput),
                           failure_code => FailureCode,
                           command_verified => command_success_verified(Proof)}]),
                    erlang:error(invalid_python_console_transcript)
            end;
        {error, Proof} ->
            Safe = maps:with([outcome, exit_status, child_exit_observed,
                process_supervisor_protocol_valid,
                process_supervisor_failure_code,
                process_supervisor_attestation_failure,
                native_tree_empty, native_console_isolated,
                native_descendant_outlived,
                native_termination_requested], Proof),
            io:format(standard_error,
                      "python console audit process failed: ~p~n", [Safe]),
            erlang:error(python_console_audit_failed)
    end.

python_console_payload(Output) when is_binary(Output),
                                    byte_size(Output) =< ?MAX_SOURCE_BYTES ->
    case plain_single_line_payload(Output) of
        {ok, _} = Plain -> Plain;
        error -> conpty_single_line_payload(Output)
    end;
python_console_payload(_) -> {error, console_transcript_too_large}.

plain_single_line_payload(Output) ->
    case single_safe_line(Output, <<"\r\n">>) of
        {ok, Line} -> {ok, <<Line/binary, "\n">>};
        error ->
            case single_safe_line(Output, <<"\n">>) of
                {ok, Line} -> {ok, <<Line/binary, "\n">>};
                error -> error
            end
    end.

conpty_single_line_payload(Output) ->
    Prefix = <<27, "[?9001h", 27, "[?1004h", 27, "[?25l",
               27, "[2J", 27, "[m", 27, "[H">>,
    TitlePrefix = <<27, "]0;">>,
    Suffix = <<27, "[?25h", 27, "[?9001l", 27, "[?1004l">>,
    PrefixSize = byte_size(Prefix),
    case Output of
        <<Prefix:PrefixSize/binary, Rest/binary>> ->
            case binary:split(Rest, TitlePrefix, [global]) of
                [Body, TitleAndSuffix] ->
                    case binary:split(TitleAndSuffix, <<7>>, [global]) of
                        [Title, Suffix] ->
                            case {safe_console_title(Title),
                                  single_safe_line(Body, <<"\r\n">>)} of
                                {true, {ok, Line}} -> {ok, <<Line/binary, "\n">>};
                                {false, _} -> {error, invalid_console_title};
                                {_, error} -> {error, invalid_console_payload}
                            end;
                        _ -> {error, invalid_console_suffix}
                    end;
                _ -> {error, invalid_console_title_boundary}
            end;
        _ -> {error, invalid_console_prefix}
    end.

single_safe_line(Output, Terminator) ->
    case binary:split(Output, Terminator, [global]) of
        [Line, <<>>] when byte_size(Line) > 0 ->
            case safe_console_bytes(Line) of
                true -> {ok, Line};
                false -> error
            end;
        _ -> error
    end.

safe_console_title(Title) ->
    byte_size(Title) > 0 andalso
    byte_size(Title) =< ?MAX_CONSOLE_TITLE_BYTES andalso
    safe_console_bytes(Title).

safe_console_bytes(Bytes) ->
    lists:all(fun(Byte) -> Byte >= 32 andalso Byte =/= 127 end,
              binary_to_list(Bytes)).

python_console_payload_self_tests() ->
    Prefix = <<27, "[?9001h", 27, "[?1004h", 27, "[?25l",
               27, "[2J", 27, "[m", 27, "[H">>,
    Suffix = <<27, "]0;fixed-tool.exe", 7, 27, "[?25h",
               27, "[?9001l", 27, "[?1004l">>,
    Valid = <<Prefix/binary, "fixed=true\r\n", Suffix/binary>>,
    Cases = [
        {plain_single_line, <<"fixed=true\n">>, true},
        {plain_crlf_single_line, <<"fixed=true\r\n">>, true},
        {conpty_single_line, Valid, true},
        {multiple_payload_lines,
         <<Prefix/binary, "fixed=true\r\nsecond=true\r\n", Suffix/binary>>,
         false},
        {missing_console_suffix,
         <<Prefix/binary, "fixed=true\r\n", 27, "]0;fixed-tool.exe", 7>>,
         false},
        {control_in_console_title,
         <<Prefix/binary, "fixed=true\r\n", 27, "]0;bad", 10, "title", 7,
           27, "[?25h", 27, "[?9001l", 27, "[?1004l">>, false},
        {oversized_console_title,
         <<Prefix/binary, "fixed=true\r\n", 27, "]0;",
           (binary:copy(<<"a">>, ?MAX_CONSOLE_TITLE_BYTES + 1))/binary, 7,
           27, "[?25h", 27, "[?9001l", 27, "[?1004l">>, false}
    ],
    AcceptanceRows = [begin
        Observed = case python_console_payload(Input) of
            {ok, _} -> true;
            {error, _} -> false
        end,
        #{kind => Kind, expected => Expected, observed => Observed,
          passed => Observed =:= Expected}
    end || {Kind, Input, Expected} <- Cases],
    NormalizationRows = [begin
        Result = python_console_payload(Input),
        Observed = case Result of
            {ok, Line} -> Line;
            {error, Code} -> atom_to_binary(Code)
        end,
        #{kind => Kind, expected => <<"fixed=true\n">>,
          observed => Observed,
          passed => Result =:= {ok, <<"fixed=true\n">>}}
    end || {Kind, Input} <- [
        {plain_lf_normalized, <<"fixed=true\n">>},
        {plain_crlf_normalized, <<"fixed=true\r\n">>},
        {conpty_crlf_normalized, Valid}
    ]],
    AcceptanceRows ++ NormalizationRows.

python_source_digest(Paths, SourceBytes) ->
    Context = lists:foldl(fun(Path, Acc0) ->
        PathBytes = unicode:characters_to_binary(console_normal_path(Path)),
        Acc1 = crypto:hash_update(Acc0, <<PathBytes/binary, 0>>),
        crypto:hash_update(Acc1, <<(maps:get(Path, SourceBytes))/binary, 0>>)
    end, crypto:hash_init(sha256), lists:sort(Paths)),
    binary:encode_hex(crypto:hash_final(Context), lowercase).

console_normal_path(Path) ->
    lists:flatten(string:replace(Path, "\\", "/", all)).

validate_python_finding(Row) ->
    true = lists:sort(maps:keys(Row)) =:=
        [<<"line">>, <<"path">>, <<"rule">>],
    Path = maps:get(<<"path">>, Row),
    Rule = maps:get(<<"rule">>, Row),
    true = is_binary(Path) andalso byte_size(Path) > 0 andalso
        byte_size(Path) =< 512 andalso
        is_integer(maps:get(<<"line">>, Row)) andalso
        maps:get(<<"line">>, Row) > 0 andalso
        is_binary(Rule) andalso byte_size(Rule) > 0 andalso
        byte_size(Rule) =< 64,
    ok.

python_finding(Row) ->
    #{path => maps:get(<<"path">>, Row), line => maps:get(<<"line">>, Row),
      rule => maps:get(<<"rule">>, Row),
      classification => <<"unowned_python_native_process">>}.

source_audit(Path, Bytes) ->
    BinaryPath = list_to_binary(Path),
    Tokens = lex(strip_shebang(Bytes)),
    #{calls => [Call#{path => BinaryPath,
                      owned_supervisor => owned_supervisor_call(
                          Path, Bytes, maps:get(line, Call))}
                || Call <- calls(Tokens, BinaryPath)],
      dynamic_spawns => dynamic_spawns(Tokens, BinaryPath),
      command_macros => command_macros(Tokens, BinaryPath)}.

owned_supervisor_call("scripts/process_runner.hrl", Bytes, Line) ->
    Window = containing_function(Bytes, Line),
    case erl_scan:string(unicode:characters_to_list(Window)) of
        {ok, Tokens, _} ->
            case erl_parse:parse_form(Tokens) of
                {ok, Form} -> owned_supervisor_form(Form);
                _ -> false
            end;
        _ -> false
    end;
owned_supervisor_call(_, _, _) -> false.

owned_supervisor_form({function, _, open_owned_process, 5,
        [{clause, _, [{var, _, 'Executable'}, {var, _, 'Arguments'},
                      {var, _, 'Directory'}, {var, _, 'Environment'},
                      {var, _, 'Deadline'}], [], Body}]} = Form) ->
    Script = top_expression_index(Body, fun script_binding/1),
    Expected = top_expression_index(Body, fun expected_binding/1),
    ExpectedProof = top_expression_index(Body, fun expected_proof_binding/1),
    ExpectedDigest = top_expression_index(
        Body, fun expected_snapshot_digest_binding/1),
    Python = top_expression_index(Body, fun python_binding/1),
    PythonProof = top_expression_index(Body, fun python_proof_binding/1),
    PythonDigest = top_expression_index(Body, fun python_digest_binding/1),
    Duration = top_expression_index(Body, fun duration_binding/1),
    OutputLimit = top_expression_index(Body, fun output_limit_binding/1),
    Arguments = top_expression_index(Body, fun arguments_binding/1),
    Environment = top_expression_index(Body, fun environment_binding/1),
    Trap = top_expression_index(Body, fun trap_acquisition/1),
    Port = top_expression_index(Body, fun port_binding/1),
    Provisional = top_expression_index(Body,
                                       fun provisional_identity_binding/1),
    Ownership = top_expression_index(Body, fun provisional_ownership_put/1),
    Registration = top_expression_index(Body, fun initial_registration_case/1),
    HandshakeDeadline = top_expression_index(Body,
                                             fun handshake_deadline_binding/1),
    Case = top_expression_index(Body, fun handshake_case/1),
    Indices = [Script, Expected, ExpectedProof, ExpectedDigest, Python,
               PythonProof, PythonDigest, Duration, OutputLimit, Arguments,
               Environment, Trap, Port, Provisional, Ownership, Registration,
               HandshakeDeadline, Case],
    UniqueBindings = binding_count(Form, 'Script') =:= 1 andalso
        binding_count(Form, 'Expected') =:= 2 andalso
        binding_count(Form, 'ScriptSnapshot') =:= 1 andalso
        binding_count(Form, 'Python') =:= 1 andalso
        binding_count(Form, 'PythonSnapshot') =:= 1 andalso
        binding_count(Form, 'PythonSha') =:= 1 andalso
        binding_count(Form, 'SupervisorDuration') =:= 1 andalso
        binding_count(Form, 'SupervisorOutputLimit') =:= 1 andalso
        binding_count(Form, 'SupervisorArguments') =:= 1 andalso
        binding_count(Form, 'SupervisorEnvironment') =:= 1 andalso
        binding_count(Form, 'Port') =:= 1 andalso
        binding_count(Form, 'ProvisionalIdentity') =:= 1 andalso
        binding_count(Form, 'Identity') =:= 1,
    Ordered = lists:all(fun(I) -> is_integer(I) end, Indices) andalso
        Indices =:= lists:sort(Indices) andalso
        length(Indices) =:= length(lists:usort(Indices)),
    OneOpen = length(local_call_lines(Form, open_port, 2)) =:= 1,
    OneHandshake = length(local_call_lines(Form,
                                           await_supervisor_handshake, 6)) =:= 1,
    OneActivation = length(local_call_lines(Form,
                                            activate_process_supervisor, 6)) =:= 1,
    Lifecycle = length(local_call_lines(Form, acquire_owned_port_trap, 0)) =:= 1
        andalso length(local_call_lines(Form,
                                        release_owned_port_trap, 0)) =:= 1
        andalso length(local_call_lines(Form,
                                        try_register_owned_tree, 2)) =:= 1
        andalso length(local_call_lines(Form,
                                        recover_owned_supervisor, 3)) =:= 3,
    Snapshots = length(local_call_lines(Form, process_file_snapshot, 2)) =:= 2
        andalso length(local_call_lines(Form,
                                        process_verify_snapshot, 2)) =:= 2,
    UniqueBindings andalso Ordered andalso OneOpen andalso OneHandshake andalso
        OneActivation andalso Lifecycle andalso Snapshots;
owned_supervisor_form(_) -> false.

top_expression_index(Body, Predicate) ->
    top_expression_index(Body, Predicate, 1, []).

top_expression_index([], _Predicate, _Index, [Found]) -> Found;
top_expression_index([], _Predicate, _Index, _) -> false;
top_expression_index([Expression | Rest], Predicate, Index, Found) ->
    Next = case Predicate(Expression) of true -> [Index | Found]; false -> Found end,
    top_expression_index(Rest, Predicate, Index + 1, Next).

script_binding({match, _, {var, _, 'Script'},
    {call, _, {remote, _, {atom, _, filename}, {atom, _, absname}},
     [{string, _, "scripts/process_supervisor.py"}]}}) -> true;
script_binding(_) -> false.

expected_binding({match, _, {var, _, 'Expected'},
                  {call, _, {atom, _, process_supervisor_sha256}, []}}) -> true;
expected_binding(_) -> false.

expected_proof_binding({match, _, {var, _, 'ScriptSnapshot'},
    {call, _, {atom, _, process_file_snapshot},
     [{var, _, 'Script'}, {integer, _, 131072}]}}) -> true;
expected_proof_binding(_) -> false.

expected_snapshot_digest_binding({match, _, {var, _, 'Expected'},
    {call, _, {remote, _, {atom, _, maps}, {atom, _, get}},
     [{atom, _, sha256}, {var, _, 'ScriptSnapshot'}]}}) -> true;
expected_snapshot_digest_binding(_) -> false.

python_binding({match, _, {var, _, 'Python'},
                {call, _, {atom, _, process_supervisor_python}, []}}) -> true;
python_binding(_) -> false.

python_proof_binding({match, _, {var, _, 'PythonSnapshot'},
    {call, _, {atom, _, process_file_snapshot},
     [{var, _, 'Python'}, {integer, _, 134217728}]}}) -> true;
python_proof_binding(_) -> false.

python_digest_binding({match, _, {var, _, 'PythonSha'},
    {call, _, {remote, _, {atom, _, maps}, {atom, _, get}},
     [{atom, _, sha256}, {var, _, 'PythonSnapshot'}]}}) -> true;
python_digest_binding(_) -> false.

duration_binding({match, _, {var, _, 'SupervisorDuration'},
    {call, _, {remote, _, {atom, _, erlang}, {atom, _, max}},
     [{integer, _, 1},
      {call, _, {remote, _, {atom, _, erlang}, {atom, _, min}},
       [{integer, _, 5400000},
        {op, _, '-', {var, _, 'Deadline'},
         {call, _, {remote, _, {atom, _, erlang},
                    {atom, _, monotonic_time}}, [{atom, _, millisecond}]}}]}]}}) ->
    true;
duration_binding(_) -> false.

output_limit_binding({match, _, {var, _, 'SupervisorOutputLimit'},
                      {integer, _, 16777216}}) -> true;
output_limit_binding(_) -> false.

arguments_binding({match, _, {var, _, 'SupervisorArguments'}, Value}) ->
    supervisor_arguments(Value);
arguments_binding(_) -> false.

environment_binding({match, _, {var, _, 'SupervisorEnvironment'},
    {call, _, {atom, _, supervisor_environment},
     [{var, _, 'Environment'}]}}) -> true;
environment_binding(_) -> false.

trap_acquisition({match, _, {atom, _, ok},
    {call, _, {atom, _, acquire_owned_port_trap}, []}}) -> true;
trap_acquisition(_) -> false.

port_binding({match, _, {var, _, 'Port'},
              {'try', _, [Open], [], Catch, []}}) ->
    owned_open_port_node(Open) andalso open_failure_releases_trap(Catch);
port_binding(_) -> false.

open_failure_releases_trap([Clause]) ->
    length(local_call_lines(Clause, release_owned_port_trap, 0)) =:= 1 andalso
    length(local_call_lines(Clause, child_start_category, 1)) =:= 1 andalso
    ast_contains_atom(Clause, child_start_failed);
open_failure_releases_trap(_) -> false.

provisional_identity_binding({match, _, {var, _, 'ProvisionalIdentity'},
                              {map, _, Fields}}) ->
    lists:any(fun(Field) -> map_field_var(Field, source_sha256, 'Expected') end,
              Fields) andalso
    lists:any(fun(Field) -> map_field_var(Field, python_executable_sha256,
                                          'PythonSha') end, Fields) andalso
    lists:member(console_isolation,
                 [map_field_name(Field) || Field <- Fields]);
provisional_identity_binding(_) -> false.

provisional_ownership_put(Expression) ->
    exact_owned_put(Expression) andalso
    ast_has(Expression, fun
        ({map_field_assoc, _, {atom, _, trap_acquired},
          {atom, _, true}}) -> true;
        (_) -> false
    end).

exact_owned_put({call, _, {atom, _, put},
        [{tuple, _, [{atom, _, process_runner_owned_tree}, {var, _, 'Port'}]},
         Map]}) ->
    ast_contains_var(Map, 'ProvisionalIdentity') andalso
    ast_contains_atom(Map, unavailable) andalso
    ast_contains_atom(Map, false);
exact_owned_put(_) -> false.

initial_registration_case({'case', _, Call,
                           [{clause, _, [{atom, _, ok}], [], [{atom, _, ok}]},
                            Failure]}) ->
    exact_local_call(Call, try_register_owned_tree,
                     ['Port', 'ProvisionalIdentity']) andalso
    initial_registration_failure(Failure);
initial_registration_case(_) -> false.

initial_registration_failure({clause, _, [{atom, _, error}], [],
                              [Put, Recovery]}) ->
    exact_owned_put(Put) andalso recovery_classification_case(
        Recovery, 'ProvisionalIdentity',
        process_supervisor_registration_failed);
initial_registration_failure(_) -> false.

handshake_deadline_binding({match, _, {var, _, 'HandshakeDeadline'},
    {call, _, {remote, _, {atom, _, erlang}, {atom, _, min}},
     [{var, _, 'Deadline'},
      {op, _, '+',
       {call, _, {remote, _, {atom, _, erlang},
                  {atom, _, monotonic_time}}, [{atom, _, millisecond}]},
       {integer, _, 5000}}]}}) -> true;
handshake_deadline_binding(_) -> false.

handshake_case({'case', _,
    {call, _, {atom, _, await_supervisor_handshake},
     [{var, _, 'Port'}, {var, _, 'Expected'},
      {var, _, 'PythonSha'},
      {var, _, 'SupervisorDuration'}, {var, _, 'SupervisorOutputLimit'},
      {var, _, 'HandshakeDeadline'}]}, [Success, Failure]}) ->
    success_handshake_clause(Success) andalso failure_handshake_clause(Failure);
handshake_case(_) -> false.

success_handshake_clause({clause, _,
        [{tuple, _, [{atom, _, ok}, {var, _, 'Runtime'}]}], [], Body}) ->
    case Body of
        [{match, _, {var, _, 'Identity'}, {var, _, 'Runtime'}}, Verify,
         {match, _, {atom, _, ok}, Activation},
         {tuple, _, [{var, _, 'Port'}, {var, _, 'Identity'}]}] ->
            post_handshake_verification(Verify) andalso
                activation_node(Activation);
        _ -> false
    end;
success_handshake_clause(_) -> false.

failure_handshake_clause({clause, _,
        [{tuple, _, [{atom, _, error}, {var, _, 'Category'}]}], [],
        [Recovery]}) ->
    recovery_classification_case(Recovery, 'ProvisionalIdentity', 'Category');
failure_handshake_clause(_) -> false.

post_handshake_verification({'try', _, Body, [], Catch, []}) ->
    Verified = lists:any(fun(Expression) -> exact_snapshot_verify(
        Expression, 'ScriptSnapshot', 131072) end, Body) andalso
        lists:any(fun(Expression) -> exact_snapshot_verify(
        Expression, 'PythonSnapshot', 134217728) end, Body),
    case catch_body(Catch) of
        [Recovery] -> Verified andalso recovery_classification_case(
            Recovery, 'ProvisionalIdentity',
            process_supervisor_identity_changed);
        _ -> false
    end;
post_handshake_verification(_) -> false.

catch_body([{clause, _, _Patterns, _Guards, Body}]) -> Body;
catch_body(_) -> [].

exact_snapshot_verify({match, _, {atom, _, ok},
    {call, _, {atom, _, process_verify_snapshot},
     [{var, _, Snapshot}, {integer, _, Limit}]}}, Snapshot, Limit) -> true;
exact_snapshot_verify(_, _, _) -> false.

recovery_classification_case({'case', _, Recovery,
        [Confirmed, Unconfirmed]}, IdentityVariable, ConfirmedError) ->
    exact_recover_call(Recovery, IdentityVariable) andalso
    recovery_error_clause(Confirmed, confirmed, ConfirmedError) andalso
    recovery_error_clause(Unconfirmed, unconfirmed, child_exit_unconfirmed);
recovery_classification_case(_, _, _) -> false.

exact_recover_call({call, _, {atom, _, recover_owned_supervisor},
        [{var, _, 'Port'}, {var, _, IdentityVariable},
         {'fun', _, {function, close_owned_port, 1}}]}, IdentityVariable) -> true;
exact_recover_call({call, _, {atom, _, recover_owned_supervisor},
        [{var, _, 'Port'}, {var, _, IdentityVariable},
         {var, _, 'Close'}]}, IdentityVariable) -> true;
exact_recover_call(_, _) -> false.

map_field_name({map_field_assoc, _, {atom, _, Name}, _}) -> Name;
map_field_name({map_field_exact, _, {atom, _, Name}, _}) -> Name;
map_field_name(_) -> invalid.

map_field_var({Kind, _, {atom, _, Name}, {var, _, Variable}}, Name, Variable)
  when Kind =:= map_field_assoc; Kind =:= map_field_exact -> true;
map_field_var(_, _, _) -> false.

binding_count(Form, Variable) ->
    length(ast_collect(Form, fun
        ({match, _, {var, _, Found}, _}) when Found =:= Variable -> {true, found};
        (_) -> false
    end)).

owned_open_port_node({call, _, {atom, _, open_port},
        [{tuple, _, [{atom, _, spawn_executable}, {var, _, 'Python'}]},
         Options]}) ->
    case ast_list(Options) of
        {ok, [{atom, _, binary}, {atom, _, exit_status},
              {atom, _, use_stdio}, {atom, _, stderr_to_stdout},
              {atom, _, hide}, Packet, Args, Cd, Env]} ->
            exact_tuple(Packet, packet, 4) andalso
            exact_tuple_var(Args, args, 'SupervisorArguments') andalso
            exact_tuple_var(Cd, cd, 'Directory') andalso
            exact_tuple_var(Env, env, 'SupervisorEnvironment');
        {ok, _} -> false;
        error -> false
    end;
owned_open_port_node(_) -> false.

activation_node({call, _, {atom, _, activate_process_supervisor},
        [{var, _, 'Port'}, {var, _, 'Identity'}, {var, _, 'Deadline'},
         {'fun', _, {function, register_owned_tree, 2}}, Start,
         {'fun', _, {function, close_owned_port, 1}}]}) ->
    start_fun_for_port(Start);
activation_node(_) -> false.

activation_recovery_contract(Bytes) ->
    case {named_function_form(Bytes, <<"activate_process_supervisor">>),
          named_function_form(Bytes, <<"recover_uncertain_supervisor_start">>),
          named_function_form(Bytes, <<"recover_owned_supervisor">>),
          named_function_form(Bytes, <<"safe_close_callback">>),
          named_function_form(Bytes,
                              <<"retire_unconfirmed_owned_tree">>)} of
        {{ok, Activation}, {ok, Uncertain}, {ok, Recovery}, {ok, SafeClose},
         {ok, Retire}} ->
            activation_contract_form(Activation) andalso
            uncertain_recovery_contract_form(Uncertain) andalso
            recovery_contract_form(Recovery) andalso
            safe_close_contract_form(SafeClose) andalso
            retire_unconfirmed_contract_form(Retire);
        _ -> false
    end.

activation_contract_form({function, _, activate_process_supervisor, 6,
        [{clause, _, [{var, _, 'Port'}, {var, _, 'Identity'},
                      {var, _, 'Deadline'}, {var, _, 'Register'},
                      {var, _, 'Start'}, {var, _, 'Close'}], [],
          [IdentityGuard, Registered, RegisteredCase]}]}) ->
    exact_local_call(IdentityGuard, ensure_owned_identity,
                     ['Port', 'Identity']) andalso
    boolean_try_binding(Registered, 'Registered', 'Register',
                        ['Port', 'Identity'], ok) andalso
    activation_registered_case(RegisteredCase);
activation_contract_form(_) -> false.

activation_registered_case({'case', _, {var, _, 'Registered'},
                             [Failure, Success]}) ->
    registration_failure_clause(Failure) andalso
    registered_success_clause(Success);
activation_registered_case(_) -> false.

registration_failure_clause({clause, _, [{atom, _, false}], [],
        [Recovery]}) ->
    recovery_classification_case(Recovery, 'Identity',
                                 process_supervisor_registration_failed);
registration_failure_clause(_) -> false.

registered_success_clause({clause, _, [{atom, _, true}], [],
                           [Started, StartedCase]}) ->
    boolean_try_binding(Started, 'Started', 'Start', ['Port'], true) andalso
    activation_started_case(StartedCase);
registered_success_clause(_) -> false.

activation_started_case({'case', _, {var, _, 'Started'}, [Started, Uncertain]}) ->
    normalize_line(Started) =:= normalize_line(
        {clause, 0, [{atom, 0, true}], [], [{atom, 0, ok}]}) andalso
    uncertain_start_clause(Uncertain);
activation_started_case(_) -> false.

uncertain_start_clause({clause, _, [{atom, _, false}], [], [RecoveryCase]}) ->
    case RecoveryCase of
        {'case', _, RecoveryCall, [Confirmed, Unconfirmed]} ->
            exact_local_call(RecoveryCall, recover_uncertain_supervisor_start,
                             ['Port', 'Identity', 'Deadline', 'Close']) andalso
            recovery_error_clause(Confirmed, confirmed,
                                  process_supervisor_start_unconfirmed) andalso
            recovery_error_clause(Unconfirmed, unconfirmed,
                                  child_exit_unconfirmed);
        _ -> false
    end;
uncertain_start_clause(_) -> false.

recovery_error_clause({clause, _, [{atom, _, Result}], [], [Failure]},
                      Result, 'Category') ->
    exact_error_variable(Failure, 'Category');
recovery_error_clause({clause, _, [{atom, _, Result}], [], [Failure]},
                      Result, Error) ->
    exact_error_atom(Failure, Error);
recovery_error_clause(_, _, _) -> false.

exact_error_variable({call, _,
        {remote, _, {atom, _, erlang}, {atom, _, error}},
        [{var, _, Variable}]}, Variable) -> true;
exact_error_variable(_, _) -> false.

boolean_try_binding({match, _, {var, _, Bound},
        {'try', _, [Call], OfClauses, CatchClauses, []}},
        Bound, Callable, Arguments, SuccessPattern) ->
    exact_variable_call(Call, Callable, Arguments) andalso
    boolean_of_clauses(OfClauses, SuccessPattern) andalso
    catch_false_only(CatchClauses);
boolean_try_binding(_, _, _, _, _) -> false.

boolean_of_clauses([Success, Failure], SuccessPattern) ->
    normalize_line(Success) =:= normalize_line(
        {clause, 0, [{atom, 0, SuccessPattern}], [], [{atom, 0, true}]}) andalso
    normalize_line(Failure) =:= normalize_line(
        {clause, 0, [{var, 0, '_'}], [], [{atom, 0, false}]});
boolean_of_clauses(_, _) -> false.

catch_false_only([{clause, _, _Patterns, [], [{atom, _, false}]}]) -> true;
catch_false_only(_) -> false.

uncertain_recovery_contract_form({function, _,
        recover_uncertain_supervisor_start, 4,
        [{clause, _, [{var, _, 'Port'}, {var, _, 'Identity'},
                      {var, _, 'Deadline'}, {var, _, 'Close'}], [],
          [DeadlineGuard, Recovery]}]}) ->
    deadline_guard(DeadlineGuard) andalso
    exact_recover_call(Recovery, 'Identity');
uncertain_recovery_contract_form(_) -> false.

deadline_guard({match, _, {atom, _, true},
    {call, _, {atom, _, is_integer}, [{var, _, 'Deadline'}]}}) -> true;
deadline_guard(_) -> false.

recovery_contract_form({function, _, recover_owned_supervisor, 3,
        [{clause, _, [{var, _, 'Port'}, {var, _, 'Identity'},
                      {var, _, 'Close'}], [],
          [TeardownDeadline, Result, Outcome]}]}) ->
    recovery_deadline_binding(TeardownDeadline) andalso
    recovery_result_binding(Result) andalso recovery_outcome_case(Outcome);
recovery_contract_form(_) -> false.

recovery_now_binding({match, _, {var, _, 'Now'},
    {call, _, {remote, _, {atom, _, erlang}, {atom, _, monotonic_time}},
     [{atom, _, millisecond}]}}) -> true;
recovery_now_binding(_) -> false.

recovery_deadline_binding({match, _, {var, _, 'TeardownDeadline'},
    {op, _, '+',
     {call, _, {remote, _, {atom, _, erlang}, {atom, _, monotonic_time}},
      [{atom, _, millisecond}]}, {integer, _, 5000}}}) -> true;
recovery_deadline_binding(_) -> false.

recovery_result_binding({match, _, {var, _, 'Result'},
        {'try', _, [Stop, Await], [], Catch, []}}) ->
    match_ignored_local_call(Stop, kill_owned_child, ['Port']) andalso
    exact_await_call(Await) andalso recovery_pending_catch(Catch);
recovery_result_binding(_) -> false.

exact_await_call({call, _, {atom, _, await_child_exit},
        [{var, _, 'Port'},
         {call, _, {atom, _, new_output}, [{var, _, 'Identity'}]},
         {var, _, 'TeardownDeadline'}]}) -> true;
exact_await_call(_) -> false.

recovery_pending_catch([{clause, _, _Patterns, [],
        [{tuple, _, [{atom, _, pending}, {atom, _, undefined}]}]}]) -> true;
recovery_pending_catch(_) -> false.

recovery_outcome_case({'case', _, {var, _, 'Result'}, [Exited, Pending]}) ->
    recovery_exited_clause(Exited) andalso recovery_pending_clause(Pending);
recovery_outcome_case(_) -> false.

recovery_exited_clause({clause, _,
        [{tuple, _, [{atom, _, exited}, {var, _, '_Attested'}]}], [],
        [Unregister, Close, {atom, _, confirmed}]}) ->
    exact_local_call(Unregister, unregister_owned_tree, ['Port']) andalso
    exact_local_call(Close, safe_close_callback, ['Close', 'Port']);
recovery_exited_clause(_) -> false.

recovery_pending_clause({clause, _, [{var, _, '_'}], [],
        [Retire, {atom, _, unconfirmed}]}) ->
    exact_local_call(Retire, retire_unconfirmed_owned_tree,
                     ['Port', 'Close']);
recovery_pending_clause(_) -> false.

retire_unconfirmed_contract_form({function, _,
        retire_unconfirmed_owned_tree, 2,
        [{clause, _, [{var, _, 'Port'}, {var, _, 'Close'}], [],
          [CloseCall, Unregister, {atom, _, ok}]}]}) ->
    exact_local_call(CloseCall, safe_close_callback, ['Close', 'Port']) andalso
    exact_local_call(Unregister, unregister_owned_tree, ['Port']);
retire_unconfirmed_contract_form(_) -> false.

safe_close_contract_form({function, _, safe_close_callback, 2,
        [{clause, _, [{var, _, 'Close'}, {var, _, 'Port'}], [],
          [{'try', _, [Call], OfClauses, CatchClauses, []}]}]}) ->
    exact_variable_call(Call, 'Close', ['Port']) andalso
    clauses_return_ok(OfClauses) andalso clauses_return_ok(CatchClauses);
safe_close_contract_form(_) -> false.

clauses_return_ok([{clause, _, _Patterns, [], [{atom, _, ok}]}]) -> true;
clauses_return_ok(_) -> false.

erase_owned_port_call({call, _, {atom, _, erase},
    [{tuple, _, [{atom, _, process_runner_owned_tree}, {var, _, 'Port'}]}]}) -> true;
erase_owned_port_call(_) -> false.

close_callback_match({match, _, {var, _, '_'}, Call}) ->
    exact_variable_call(Call, 'Close', ['Port']);
close_callback_match(_) -> false.

match_ignored_local_call({match, _, {var, _, '_'}, Call}, Name, Arguments) ->
    exact_local_call(Call, Name, Arguments);
match_ignored_local_call(_, _, _) -> false.

exact_local_call({call, _, {atom, _, Name}, Arguments}, Name, Variables) ->
    exact_variable_arguments(Arguments, Variables);
exact_local_call(_, _, _) -> false.

exact_variable_call({call, _, {var, _, Name}, Arguments}, Name, Variables) ->
    exact_variable_arguments(Arguments, Variables);
exact_variable_call(_, _, _) -> false.

exact_variable_arguments(Arguments, Variables) when length(Arguments) =:=
                                                       length(Variables) ->
    lists:all(fun({Argument, Variable}) ->
        case Argument of {var, _, Found} -> Found =:= Variable; _ -> false end
    end, lists:zip(Arguments, Variables));
exact_variable_arguments(_, _) -> false.

exact_error_atom({call, _,
        {remote, _, {atom, _, erlang}, {atom, _, error}},
        [{atom, _, Error}]}, Error) -> true;
exact_error_atom(_, _) -> false.

normalize_line(Term) when is_tuple(Term) ->
    list_to_tuple([normalize_line(Element) || Element <- tuple_to_list(Term)]);
normalize_line(Term) when is_list(Term) -> [normalize_line(Element) || Element <- Term];
normalize_line(Term) when is_integer(Term) -> 0;
normalize_line(Term) -> Term.

named_function_form(Bytes, Name) ->
    Lines = binary:split(Bytes, <<"\n">>, [global]),
    case named_function_line(Lines, Name, 1) of
        false -> error;
        Line ->
            Window = containing_function(Bytes, Line),
            case erl_scan:string(unicode:characters_to_list(Window)) of
                {ok, Tokens, _} -> erl_parse:parse_form(Tokens);
                _ -> error
            end
    end.

named_function_line([], _Name, _Line) -> false;
named_function_line([Candidate | Rest], Name, Line) ->
    Pattern = <<"^", Name/binary, "\\(">>,
    case re:run(Candidate, Pattern, [{capture, none}, unicode]) of
        match -> Line;
        nomatch -> named_function_line(Rest, Name, Line + 1)
    end.

start_fun_for_port({'fun', _, {clauses,
        [{clause, _, [{var, _, Variable}], [],
          [{call, _, {atom, _, port_command},
            [{var, _, Found}, Binary]}]}]}}) ->
    Found =:= Variable andalso ast_binary_equals(Binary, <<"START">>);
start_fun_for_port(_) -> false.

supervisor_arguments(Value) ->
    case ast_improper_list(Value, []) of
        {ok, [{string, _, "-I"}, {string, _, "-B"},
              {var, _, 'Script'}, {string, _, "--expected-sha256"},
              {call, _, {atom, _, binary_to_list}, [{var, _, 'Expected'}]},
              {string, _, "--expected-python-sha256"},
              {call, _, {atom, _, binary_to_list}, [{var, _, 'PythonSha'}]},
              {string, _, "--deadline-ms"},
              {call, _, {atom, _, integer_to_list},
               [{var, _, 'SupervisorDuration'}]},
              {string, _, "--output-limit-bytes"},
              {call, _, {atom, _, integer_to_list},
               [{var, _, 'SupervisorOutputLimit'}]},
              {string, _, "--"}, {var, _, 'Executable'}],
             {var, _, 'Arguments'}} -> true;
        _ -> false
    end.

ast_improper_list({cons, _, Head, Tail}, Acc) ->
    ast_improper_list(Tail, [Head | Acc]);
ast_improper_list(Tail, Acc) -> {ok, lists:reverse(Acc), Tail}.

ast_list({nil, _}) -> {ok, []};
ast_list({cons, _, Head, Tail}) ->
    case ast_list(Tail) of
        {ok, Rest} -> {ok, [Head | Rest]};
        error -> error
    end;
ast_list(_) -> error.

exact_tuple({tuple, _, [{atom, _, Name}, {integer, _, Value}]},
            Name, Value) -> true;
exact_tuple(_, _, _) -> false.

exact_tuple_var({tuple, _, [{atom, _, Name}, {var, _, Variable}]},
                Name, Variable) -> true;
exact_tuple_var(_, _, _) -> false.

ast_binary_equals({bin, _, [{bin_element, _, {string, _, Text}, default,
                             default}]}, Expected) ->
    unicode:characters_to_binary(Text) =:= Expected;
ast_binary_equals(_, _) -> false.

binding_local_call(Form, Variable, Name, Arity) ->
    ast_has(Form, fun
        ({match, _, {var, _, FoundVariable},
          {call, _, {atom, _, FoundName}, Arguments}}) ->
            FoundVariable =:= Variable andalso FoundName =:= Name andalso
                length(Arguments) =:= Arity;
        (_) -> false
    end).

ordered_single_calls([Hash], [Open], [Handshake], [Activate]) ->
    Hash < Open andalso Open < Handshake andalso Handshake < Activate;
ordered_single_calls(_, _, _, _) -> false.

local_call_lines(Form, Name, Arity) ->
    lists:sort(ast_collect(Form, fun
        ({call, Annotation, {atom, _, FoundName}, Arguments})
          when FoundName =:= Name, length(Arguments) =:= Arity ->
            {true, erl_anno:line(Annotation)};
        (_) -> false
    end)).

ast_contains_var(Term, Name) ->
    ast_has(Term, fun({var, _, Found}) -> Found =:= Name; (_) -> false end).

ast_contains_string(Term, Value) ->
    ast_has(Term, fun({string, _, Found}) -> Found =:= Value; (_) -> false end).

ast_contains_atom(Term, Value) ->
    ast_has(Term, fun({atom, _, Found}) -> Found =:= Value; (_) -> false end).

ast_contains_call(Term, Name, Arity) ->
    ast_has(Term, fun
        ({call, _, {atom, _, FoundName}, Arguments}) ->
            FoundName =:= Name andalso length(Arguments) =:= Arity;
        (_) -> false
    end).

ast_contains_tuple(Term, Name, Value) ->
    ast_has(Term, fun
        ({tuple, _, [{atom, _, FoundName}, {integer, _, FoundValue}]}) ->
            FoundName =:= Name andalso FoundValue =:= Value;
        (_) -> false
    end).

ast_contains_tuple_var(Term, Name, Variable) ->
    ast_has(Term, fun
        ({tuple, _, [{atom, _, FoundName}, {var, _, FoundVariable}]}) ->
            FoundName =:= Name andalso FoundVariable =:= Variable;
        (_) -> false
    end).

ast_has(Term, Predicate) -> ast_collect(Term, fun(Node) ->
    case Predicate(Node) of true -> {true, true}; false -> false end
end) =/= [].

ast_collect(Term, Predicate) when is_tuple(Term) ->
    Here = case Predicate(Term) of {true, Value} -> [Value]; false -> [] end,
    Here ++ lists:append([ast_collect(Element, Predicate)
                          || Element <- tuple_to_list(Term)]);
ast_collect(Term, Predicate) when is_list(Term) ->
    lists:append([ast_collect(Element, Predicate) || Element <- Term]);
ast_collect(_, _) -> [].

containing_function(Bytes, Line) ->
    Lines = binary:split(Bytes, <<"\n">>, [global]),
    Before = lists:sublist(Lines, erlang:min(Line, length(Lines))),
    Start = function_start_line(lists:reverse(Before), Line),
    Remaining = lists:nthtail(Start - 1, Lines),
    iolist_to_binary(function_lines(Remaining, true, [])).

function_start_line([], _Line) -> 1;
function_start_line([Candidate | Rest], Line) ->
    case re:run(Candidate, <<"^[a-z][a-zA-Z0-9_]*\\(.*\\)\\s*->\\s*$">>,
                [{capture, none}, unicode]) of
        match -> Line;
        nomatch -> function_start_line(Rest, Line - 1)
    end.

function_lines([], _First, Acc) -> lists:reverse(Acc);
function_lines([Line | Rest], First, Acc) ->
    IsStart = re:run(Line,
        <<"^[a-z][a-zA-Z0-9_]*\\(.*\\)\\s*->\\s*$">>,
        [{capture, none}, unicode]) =:= match,
    IsAttribute = re:run(Line, <<"^-">>,
                         [{capture, none}, unicode]) =:= match,
    case (IsStart orelse IsAttribute) andalso not First of
        true -> lists:reverse(Acc);
        false -> function_lines(Rest, false, [Line, <<"\n">> | Acc])
    end.

source_identity(Path, Bytes) ->
    #{path => unicode:characters_to_binary(Path),
      bytes => byte_size(Bytes),
      sha256 => binary:encode_hex(crypto:hash(sha256, Bytes), lowercase)}.

line_of(Bytes, Needle) ->
    case binary:match(Bytes, Needle) of
        {Offset, _} ->
            Prefix = binary:part(Bytes, 0, Offset),
            length(binary:split(Prefix, <<"\n">>, [global]));
        nomatch -> 1
    end.

bounded_source_bytes(Path) ->
    Size = filelib:file_size(Path),
    true = is_integer(Size) andalso Size >= 0 andalso Size =< ?MAX_SOURCE_BYTES,
    {ok, Bytes} = file:read_file(Path),
    true = byte_size(Bytes) =:= Size,
    Bytes.

strip_shebang(<<"#!", Rest/binary>>) ->
    case binary:split(Rest, <<"\n">>) of
        [_First, Remaining] -> Remaining;
        [_Only] -> <<>>
    end;
strip_shebang(Bytes) -> Bytes.

lex(Bytes) ->
    {ok, Tokens, _} = erl_scan:string(unicode:characters_to_list(Bytes)),
    Tokens.

calls([], _Path) -> [];
calls([{atom, Annotation, open_port}, {'(', _}, {'{', _},
       {atom, _, Kind} | Rest] = Tokens, Path)
  when Kind =:= spawn_executable; Kind =:= spawn ->
    Hidden = second_argument_has_hide(Rest),
    [#{path => Path, line => erl_anno:line(Annotation), kind => Kind,
       hidden => Hidden}
     | calls(Rest, Path)];
calls([{atom, _, erlang}, {':', _}, {atom, Annotation, open_port},
       {'(', _}, {'{', _}, {atom, _, Kind} | Rest] = Tokens, Path)
  when Kind =:= spawn_executable; Kind =:= spawn ->
    Hidden = second_argument_has_hide(Rest),
    [#{path => Path, line => erl_anno:line(Annotation), kind => Kind,
       hidden => Hidden}
     | calls(Rest, Path)];
calls([{atom, Annotation, open_port}, {'(', _} | Rest], Path) ->
    [#{path => Path, line => erl_anno:line(Annotation), kind => unknown,
       hidden => general_second_argument_has_hide(Rest)}
     | calls(Rest, Path)];
calls([{atom, _, erlang}, {':', _}, {atom, Annotation, open_port},
       {'(', _} | Rest], Path) ->
    [#{path => Path, line => erl_anno:line(Annotation), kind => unknown,
       hidden => general_second_argument_has_hide(Rest)}
     | calls(Rest, Path)];
calls([_ | Rest], Path) -> calls(Rest, Path).

dynamic_spawns([], _Path) -> [];
dynamic_spawns([{atom, _, os}, {':', _}, {atom, Annotation, cmd},
                {'(', _} | Rest], Path) ->
    [#{path => Path, line => erl_anno:line(Annotation), kind => os_cmd}
     | dynamic_spawns(Rest, Path)];
dynamic_spawns([{atom, Annotation, apply}, {'(', _}, {atom, _, erlang},
                {',', _}, {atom, _, open_port}, {',', _} | Rest], Path) ->
    [#{path => Path, line => erl_anno:line(Annotation),
       kind => dynamic_open_port} | dynamic_spawns(Rest, Path)];
dynamic_spawns([{atom, _, erlang}, {':', _}, {atom, Annotation, apply},
                {'(', _}, {atom, _, erlang}, {',', _},
                {atom, _, open_port}, {',', _} | Rest], Path) ->
    [#{path => Path, line => erl_anno:line(Annotation),
       kind => dynamic_open_port} | dynamic_spawns(Rest, Path)];
dynamic_spawns([{atom, Annotation, apply}, {'(', _}, {atom, _, os},
                {',', _}, {atom, _, cmd}, {',', _} | Rest], Path) ->
    [#{path => Path, line => erl_anno:line(Annotation), kind => dynamic_os_cmd}
     | dynamic_spawns(Rest, Path)];
dynamic_spawns([{atom, _, erlang}, {':', _}, {atom, Annotation, apply},
                {'(', _}, {atom, _, os}, {',', _}, {atom, _, cmd},
                {',', _} | Rest], Path) ->
    [#{path => Path, line => erl_anno:line(Annotation), kind => dynamic_os_cmd}
     | dynamic_spawns(Rest, Path)];
dynamic_spawns([{'fun', Annotation}, {atom, _, erlang}, {':', _},
                {atom, _, open_port}, {'/', _}, {integer, _, 2} | Rest], Path) ->
    [#{path => Path, line => erl_anno:line(Annotation), kind => open_port_fun}
     | dynamic_spawns(Rest, Path)];
dynamic_spawns([{'fun', Annotation}, {atom, _, open_port}, {'/', _},
                {integer, _, 2} | Rest], Path) ->
    [#{path => Path, line => erl_anno:line(Annotation), kind => open_port_fun}
     | dynamic_spawns(Rest, Path)];
dynamic_spawns([{'fun', Annotation}, {atom, _, os}, {':', _},
                {atom, _, cmd}, {'/', _}, {integer, _, 1} | Rest], Path) ->
    [#{path => Path, line => erl_anno:line(Annotation), kind => os_cmd_fun}
     | dynamic_spawns(Rest, Path)];
dynamic_spawns([_ | Rest], Path) -> dynamic_spawns(Rest, Path).

native_script_audit(Path, Bytes) ->
    case filename:extension(Path) of
        ".py" -> python_script_audit(Path, python_code(Bytes));
        ".ps1" -> powershell_script_audit(Path, Bytes)
    end.

python_script_audit(Path, Code) ->
    LaunchPattern = <<"(?:^|[^A-Za-z0-9_])(?:subprocess\\s*\\.\\s*"
        "(?:Popen|run|call|check_call|check_output)|os\\s*\\.\\s*system)"
        "\\s*\\(">>,
    Launches = matching_lines(Path, Code, LaunchPattern,
        python_subprocess, #{execution_contract => supervisor_boundary_required}),
    Forbidden = [{create_new_console, <<"(?:^|[^A-Za-z0-9_])"
                                      "CREATE_NEW_CONSOLE(?:$|[^A-Za-z0-9_])">>},
                 {detached_process, <<"(?:^|[^A-Za-z0-9_])"
                                    "DETACHED_PROCESS(?:$|[^A-Za-z0-9_])">>},
                 {alloc_console, <<"(?:^|[^A-Za-z0-9_])"
                                "AllocConsole\\s*\\(">>}],
    Unsafe = lists:append([matching_lines(Path, Code, Pattern, Kind, #{})
                           || {Kind, Pattern} <- Forbidden]),
    #{launches => Launches, unsafe_flags => Unsafe}.

powershell_script_audit(Path, Bytes) ->
    Code = powershell_code(Bytes),
    Lines = numbered_lines(Code),
    CmdletLaunches = [#{path => list_to_binary(Path), line => Number,
                        kind => powershell_start_process,
                        hidden => powershell_hidden_window(Lines, Number)}
                || {Number, Line} <- Lines,
                   regex_match(Line, <<"(?i)(?:^|[^A-Za-z0-9_-])"
                                      "(?:Start-Process|saps)"
                                      "(?:$|[^A-Za-z0-9_-])">>)],
    InstanceLaunches = [
        #{path => list_to_binary(Path), line => Number,
          kind => powershell_instance_process_start,
          hidden => powershell_instance_start_hidden(Path, Lines, Number, Bytes)}
        || {Number, Line} <- Lines,
           regex_match(Line, <<"(?i)\\$[A-Za-z_][A-Za-z0-9_]*"
                               "\\s*\\.\\s*Start\\s*\\(">>)],
    Launches = CmdletLaunches ++ InstanceLaunches,
    UnsafeStart = [maps:remove(hidden,
        Row#{kind => start_process_without_hidden})
        || Row <- Launches, not maps:get(hidden, Row)],
    DynamicPatterns = [
        {diagnostics_process_start,
         <<"(?i)\\[(?:System\\.)?Diagnostics\\.Process\\]\\s*::\\s*Start\\s*\\(">>},
        {powershell_call_operator,
         <<"(?:^|[;{}()\\s])&\\s*(?:[A-Za-z_$]|$)">>},
        {invoke_expression,
         <<"(?i)(?:^|[^A-Za-z0-9_-])(?:Invoke-Expression|iex)"
           "(?:$|[^A-Za-z0-9_-])">>},
        {powershell_background_process,
         <<"(?i)(?:^|[^A-Za-z0-9_-])Start-Job(?:$|[^A-Za-z0-9_-])">>},
        {wmi_process_create,
         <<"(?i)(?:Win32_Process|WMIClass)[^\\r\\n]{0,160}\\.Create\\s*\\(">>}
    ],
    Dynamic = lists:append([matching_lines(Path, Code, Pattern, Kind,
        #{hidden => false}) || {Kind, Pattern} <- DynamicPatterns]),
    UnsafeDynamic = [maps:remove(hidden, Row) || Row <- Dynamic],
    #{launches => Launches ++ Dynamic,
      unsafe_flags => UnsafeStart ++ UnsafeDynamic}.

powershell_instance_start_hidden(Path0, Lines, Start, Code) ->
    Path = lists:flatten(string:replace(
        string:lowercase(Path0), "\\", "/", all)),
    case Path of
        "scripts/windows_headless_entry.ps1" ->
            windows_headless_bootstrap_contract(Code);
        "scripts/windows_console_inheritance_audit.ps1" ->
            Window = iolist_to_binary([Line || {Number, Line} <- Lines,
                Number >= erlang:max(1, Start - 32), Number =< Start]),
            Required = [
                <<"(?i)\\.UseShellExecute\\s*=\\s*\\$false">>,
                <<"(?i)\\.CreateNoWindow\\s*=\\s*\\$true">>,
                <<"(?i)\\.WindowStyle\\s*=\\s*\\[System\\."
                  "Diagnostics\\.ProcessWindowStyle\\]\\s*::\\s*Hidden">>,
                <<"(?i)\\.RedirectStandardOutput\\s*=\\s*\\$true">>,
                <<"(?i)\\.RedirectStandardError\\s*=\\s*\\$true">>
            ],
            lists:all(fun(Pattern) -> regex_match(Window, Pattern) end,
                      Required);
        _ -> false
    end.

powershell_hidden_window(Lines, Start) ->
    Window = iolist_to_binary([Line || {Number, Line} <- Lines,
        Number >= Start, Number =< Start + 7]),
    regex_match(Window, <<"(?i)-WindowStyle\\s+Hidden"
                          "(?:$|[^A-Za-z0-9_-])">>).

workflow_python_launches(Path, Bytes) ->
    [#{path => list_to_binary(Path), line => Number,
       kind => direct_python_entrypoint}
     || {Number, Line0} <- numbered_lines(Bytes),
        Line <- [strip_yaml_comment(Line0)],
        regex_match(Line, <<"(?i)\\brun\\s*:\\s*[^\\r\\n#]*"
                            "\\bpython(?:3|\\.exe)?\\b[^\\r\\n#]*\\.py\\b">>)].

workflow_windows_direct_entries(Path, Bytes) ->
    Lines = numbered_lines(Bytes),
    [#{path => list_to_binary(Path), line => Number,
       kind => direct_windows_shell_entry}
     || {Number, Line0} <- Lines,
        Line <- [strip_yaml_comment(Line0)],
        workflow_forbidden_windows_command(Line),
        workflow_line_is_command(Number, Lines),
        workflow_job_windows_capable(Number, Lines),
        not workflow_step_excludes_windows(Number, Lines)].

workflow_forbidden_windows_command(Line) ->
    regex_match(Line,
        <<"(?i)(?:^|[^A-Za-z0-9_.-])"
          "(?:bash(?:\\.exe)?|escript(?:\\.exe)?|mise(?:\\.exe)?|"
          "cmd(?:\\.exe)?)(?:$|[^A-Za-z0-9_.-])">>).

workflow_line_is_command(Number, Lines) ->
    Step = workflow_step_lines(Number, Lines),
    RunLines = [LineNumber || {LineNumber, Line} <- Step,
        regex_match(Line, <<"^\\s{8}run\\s*:">>)],
    ShellLine = lists:any(fun({LineNumber, Line}) ->
        LineNumber =:= Number andalso
        regex_match(Line, <<"^\\s{8}shell\\s*:">>)
    end, Step),
    ShellLine orelse case RunLines of
        [Run | _] -> Number >= Run;
        [] -> false
    end.

workflow_job_windows_capable(Number, Lines) ->
    Job = workflow_job_lines(Number, Lines),
    Bytes = iolist_to_binary([[strip_yaml_comment(Line), <<"\n">>]
                              || {_LineNumber, Line} <- Job]),
    DirectWindows = regex_match(Bytes,
        <<"(?i)runs-on\\s*:\\s*windows(?:-|$)">>),
    MatrixWindows = regex_match(Bytes,
        <<"runs-on\\s*:\\s*\\$\\{\\{\\s*matrix\\.os\\s*\\}\\}">>)
        andalso regex_match(Bytes, <<"(?i)windows-2025">>),
    DirectWindows orelse MatrixWindows.

workflow_step_excludes_windows(Number, Lines) ->
    Step = workflow_step_lines(Number, Lines),
    lists:any(fun({_LineNumber, Line}) ->
        regex_match(strip_yaml_comment(Line),
            <<"(?i)^\\s{8}if\\s*:\\s*(?:\\$\\{\\{\\s*)?"
              "(?:always\\(\\)\\s*&&\\s*)?runner\\.os\\s*!=\\s*"
              "['\"]Windows['\"](?:\\s*\\}\\})?\\s*$">>)
    end, Step).

workflow_step_includes_windows(Number, Lines) ->
    Step = workflow_step_lines(Number, Lines),
    lists:any(fun({_LineNumber, Line}) ->
        regex_match(strip_yaml_comment(Line),
            <<"(?i)^\\s{8}if\\s*:\\s*(?:\\$\\{\\{\\s*)?"
              "(?:always\\(\\)\\s*&&\\s*)?runner\\.os\\s*==\\s*"
              "['\"]Windows['\"](?:\\s*\\}\\})?\\s*$">>)
    end, Step).

workflow_step_uses_pwsh(Number, Lines) ->
    Step = workflow_step_lines(Number, Lines),
    lists:any(fun({_LineNumber, Line}) ->
        regex_match(strip_yaml_comment(Line),
            <<"(?i)^\\s{8}shell\\s*:\\s*pwsh\\s*$">>)
    end, Step).

workflow_step_lines(Number, Lines) ->
    workflow_indented_section(Number, Lines,
        <<"^\\s{6}-\\s+(?:name|run|uses)\\s*:">>).

workflow_job_lines(Number, Lines) ->
    workflow_indented_section(Number, Lines,
        <<"^\\s{2}[A-Za-z0-9_-]+\\s*:\\s*$">>).

workflow_indented_section(Number, Lines, StartPattern) ->
    Starts = [LineNumber || {LineNumber, Line} <- Lines,
        LineNumber =< Number, regex_match(Line, StartPattern)],
    case Starts of
        [] -> [];
        _ ->
            Start = lists:last(Starts),
            Ends = [LineNumber || {LineNumber, Line} <- Lines,
                LineNumber > Start, regex_match(Line, StartPattern)],
            Finish = case Ends of
                [First | _] -> First;
                [] -> 2147483647
            end,
            [Row || Row = {LineNumber, _Line} <- Lines,
                    LineNumber >= Start, LineNumber < Finish]
    end.

strip_yaml_comment(Line) ->
    iolist_to_binary(lists:reverse(strip_yaml_comment(
        binary_to_list(Line), plain, true, []))).

strip_yaml_comment([], _State, _PreviousWhitespace, Acc) -> Acc;
strip_yaml_comment([$# | _Rest], plain, true, Acc) -> Acc;
strip_yaml_comment([$', $' | Rest], single, _PreviousWhitespace, Acc) ->
    strip_yaml_comment(Rest, single, false, [<<"''">> | Acc]);
strip_yaml_comment([$' | Rest], single, _PreviousWhitespace, Acc) ->
    strip_yaml_comment(Rest, plain, false, [$' | Acc]);
strip_yaml_comment([$\\, Escaped | Rest], double, _PreviousWhitespace, Acc) ->
    strip_yaml_comment(Rest, double, false, [Escaped, $\\ | Acc]);
strip_yaml_comment([$" | Rest], double, _PreviousWhitespace, Acc) ->
    strip_yaml_comment(Rest, plain, false, [$" | Acc]);
strip_yaml_comment([Char | Rest], single, _PreviousWhitespace, Acc) ->
    strip_yaml_comment(Rest, single, yaml_whitespace(Char), [Char | Acc]);
strip_yaml_comment([Char | Rest], double, _PreviousWhitespace, Acc) ->
    strip_yaml_comment(Rest, double, yaml_whitespace(Char), [Char | Acc]);
strip_yaml_comment([$' | Rest], plain, _PreviousWhitespace, Acc) ->
    strip_yaml_comment(Rest, single, false, [$' | Acc]);
strip_yaml_comment([$" | Rest], plain, _PreviousWhitespace, Acc) ->
    strip_yaml_comment(Rest, double, false, [$" | Acc]);
strip_yaml_comment([Char | Rest], plain, _PreviousWhitespace, Acc) ->
    strip_yaml_comment(Rest, plain, yaml_whitespace(Char), [Char | Acc]).

yaml_whitespace(32) -> true;
yaml_whitespace(9) -> true;
yaml_whitespace(_) -> false.

matching_lines(Path, Code, Pattern, Kind, Extra) ->
    [maps:merge(#{path => list_to_binary(Path), line => Number, kind => Kind},
                Extra)
     || {Number, Line} <- numbered_lines(Code), regex_match(Line, Pattern)].

numbered_lines(Bytes) ->
    lists:zip(lists:seq(1, length(binary:split(Bytes, <<"\n">>, [global]))),
              binary:split(Bytes, <<"\n">>, [global])).

regex_match(Bytes, Pattern) ->
    re:run(Bytes, Pattern, [{capture, none}, unicode]) =:= match.

python_code(Bytes) ->
    iolist_to_binary(python_code(binary_to_list(Bytes), code, [])).

python_code([], _State, Acc) -> lists:reverse(Acc);
python_code([$\n | Rest], line_comment, Acc) ->
    python_code(Rest, code, [$\n | Acc]);
python_code([_ | Rest], line_comment, Acc) ->
    python_code(Rest, line_comment, [$\s | Acc]);
python_code([$',$',$' | Rest], code, Acc) ->
    python_code(Rest, triple_single, [$\s,$\s,$\s | Acc]);
python_code([$",$",$" | Rest], code, Acc) ->
    python_code(Rest, triple_double, [$\s,$\s,$\s | Acc]);
python_code([$# | Rest], code, Acc) ->
    python_code(Rest, line_comment, [$\s | Acc]);
python_code([$' | Rest], code, Acc) -> python_code(Rest, single, [$\s | Acc]);
python_code([$" | Rest], code, Acc) -> python_code(Rest, double, [$\s | Acc]);
python_code([Char | Rest], code, Acc) -> python_code(Rest, code, [Char | Acc]);
python_code([$\\, _Escaped | Rest], State, Acc)
  when State =:= single; State =:= double ->
    python_code(Rest, State, [$\s,$\s | Acc]);
python_code([$' | Rest], single, Acc) -> python_code(Rest, code, [$\s | Acc]);
python_code([$" | Rest], double, Acc) -> python_code(Rest, code, [$\s | Acc]);
python_code([$\n | Rest], State, Acc)
  when State =:= single; State =:= double ->
    python_code(Rest, code, [$\n | Acc]);
python_code([_ | Rest], State, Acc)
  when State =:= single; State =:= double ->
    python_code(Rest, State, [$\s | Acc]);
python_code([$',$',$' | Rest], triple_single, Acc) ->
    python_code(Rest, code, [$\s,$\s,$\s | Acc]);
python_code([$",$",$" | Rest], triple_double, Acc) ->
    python_code(Rest, code, [$\s,$\s,$\s | Acc]);
python_code([$\n | Rest], State, Acc)
  when State =:= triple_single; State =:= triple_double ->
    python_code(Rest, State, [$\n | Acc]);
python_code([_ | Rest], State, Acc)
  when State =:= triple_single; State =:= triple_double ->
    python_code(Rest, State, [$\s | Acc]).

powershell_code(Bytes) ->
    iolist_to_binary(powershell_code(binary_to_list(Bytes), code, [])).

powershell_code([], _State, Acc) -> lists:reverse(Acc);
powershell_code([$\n | Rest], line_comment, Acc) ->
    powershell_code(Rest, code, [$\n | Acc]);
powershell_code([_ | Rest], line_comment, Acc) ->
    powershell_code(Rest, line_comment, [$\s | Acc]);
powershell_code([$<,$# | Rest], code, Acc) ->
    powershell_code(Rest, block_comment, [$\s,$\s | Acc]);
powershell_code([$# | Rest], code, Acc) ->
    powershell_code(Rest, line_comment, [$\s | Acc]);
powershell_code([$' | Rest], code, Acc) ->
    powershell_code(Rest, single, [$\s | Acc]);
powershell_code([$" | Rest], code, Acc) ->
    powershell_code(Rest, double, [$\s | Acc]);
powershell_code([Char | Rest], code, Acc) ->
    powershell_code(Rest, code, [Char | Acc]);
powershell_code([$#,$> | Rest], block_comment, Acc) ->
    powershell_code(Rest, code, [$\s,$\s | Acc]);
powershell_code([$\n | Rest], block_comment, Acc) ->
    powershell_code(Rest, block_comment, [$\n | Acc]);
powershell_code([_ | Rest], block_comment, Acc) ->
    powershell_code(Rest, block_comment, [$\s | Acc]);
powershell_code([$',$' | Rest], single, Acc) ->
    powershell_code(Rest, single, [$\s,$\s | Acc]);
powershell_code([$' | Rest], single, Acc) ->
    powershell_code(Rest, code, [$\s | Acc]);
powershell_code([$` , _Escaped | Rest], double, Acc) ->
    powershell_code(Rest, double, [$\s,$\s | Acc]);
powershell_code([$" | Rest], double, Acc) ->
    powershell_code(Rest, code, [$\s | Acc]);
powershell_code([$\n | Rest], State, Acc)
  when State =:= single; State =:= double ->
    powershell_code(Rest, State, [$\n | Acc]);
powershell_code([_ | Rest], State, Acc)
  when State =:= single; State =:= double ->
    powershell_code(Rest, State, [$\s | Acc]).

command_macros([], _Path) -> [];
command_macros([{'?', Annotation}, {atom, _, Name} | Rest], Path) ->
    case lists:prefix("assertCmd", atom_to_list(Name)) of
        true -> [#{path => Path, line => erl_anno:line(Annotation)} |
                 command_macros(Rest, Path)];
        false -> command_macros(Rest, Path)
    end;
command_macros([{'?', Annotation}, {var, _, Name} | Rest], Path) ->
    case lists:prefix("assertCmd", atom_to_list(Name)) of
        true -> [#{path => Path, line => erl_anno:line(Annotation)} |
                 command_macros(Rest, Path)];
        false -> command_macros(Rest, Path)
    end;
command_macros([_ | Rest], Path) -> command_macros(Rest, Path).

second_argument_has_hide(Tokens) ->
    case after_first_argument(Tokens, 1, 1, 0) of
        [{'[' , _} | Rest] -> option_list_has_hide(Rest, 1, 0, 0, false);
        _ -> false
    end.

general_second_argument_has_hide(Tokens) ->
    case after_first_argument(Tokens, 1, 0, 0) of
        [{'[' , _} | Rest] -> option_list_has_hide(Rest, 1, 0, 0, false);
        _ -> false
    end.

after_first_argument([], _Parentheses, _Braces, _Brackets) -> [];
after_first_argument([{',', _} | Rest], 1, 0, 0) -> Rest;
after_first_argument([{'(', _} | Rest], P, C, B) -> after_first_argument(Rest, P + 1, C, B);
after_first_argument([{')', _} | Rest], P, C, B) -> after_first_argument(Rest, P - 1, C, B);
after_first_argument([{'{', _} | Rest], P, C, B) -> after_first_argument(Rest, P, C + 1, B);
after_first_argument([{'}', _} | Rest], P, C, B) -> after_first_argument(Rest, P, C - 1, B);
after_first_argument([{'[', _} | Rest], P, C, B) -> after_first_argument(Rest, P, C, B + 1);
after_first_argument([{']', _} | Rest], P, C, B) -> after_first_argument(Rest, P, C, B - 1);
after_first_argument([_ | Rest], P, C, B) -> after_first_argument(Rest, P, C, B).

option_list_has_hide([], _Brackets, _Braces, _Parentheses, _Found) -> false;
option_list_has_hide([{']', _} | _], 1, 0, 0, Found) -> Found;
option_list_has_hide([{atom, _, hide} | Rest], 1, 0, 0, _Found) ->
    option_list_has_hide(Rest, 1, 0, 0, true);
option_list_has_hide([{'[', _} | Rest], B, C, P, Found) -> option_list_has_hide(Rest, B + 1, C, P, Found);
option_list_has_hide([{']', _} | Rest], B, C, P, Found) -> option_list_has_hide(Rest, B - 1, C, P, Found);
option_list_has_hide([{'{', _} | Rest], B, C, P, Found) -> option_list_has_hide(Rest, B, C + 1, P, Found);
option_list_has_hide([{'}', _} | Rest], B, C, P, Found) -> option_list_has_hide(Rest, B, C - 1, P, Found);
option_list_has_hide([{'(', _} | Rest], B, C, P, Found) -> option_list_has_hide(Rest, B, C, P + 1, Found);
option_list_has_hide([{')', _} | Rest], B, C, P, Found) -> option_list_has_hide(Rest, B, C, P - 1, Found);
option_list_has_hide([_ | Rest], B, C, P, Found) -> option_list_has_hide(Rest, B, C, P, Found).
