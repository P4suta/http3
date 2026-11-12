%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("suite_evidence.hrl").
-include("json_evidence.hrl").

diagnostic_assertion_self_test() ->
    Root = filename:absname("."),
    Nonce = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    Directory = filename:join([Root, "build", "diagnostic-assertions", binary_to_list(Nonce)]),
    SourcePaths = ["scripts/diagnostic_failure.hrl", "scripts/diagnostic_assertion_fixture.erl",
        "scripts/diagnostic_assertion_tests.hrl", "scripts/qualification_eunit_listener.erl",
        "scripts/suite_evidence.hrl", "scripts/json_evidence.hrl",
        "scripts/execution_beam_identity.hrl", "scripts/canonical_etf_wire.hrl",
        "scripts/evidence_publication.hrl",
        "scripts/process_runner.hrl", "scripts/process_runner.escript"],
    Sources = [{Path, diagnostic_assertion_bytes(Path)} || Path <- SourcePaths],
    Runtime = diagnostic_assertion_runtime(),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    lists:foreach(fun({Path, Bytes}) ->
        ok = file:write_file(filename:join(Directory, filename:basename(Path)), Bytes, [exclusive])
    end, Sources),
    Captured = [{filename:join(Directory, filename:basename(Path)), Bytes} || {Path, Bytes} <- Sources],
    %% Compile inside the same finite owned-VM contract as the tests. No
    %% compiler warnings/errors or captured output are copied into evidence.
    Evaluation = lists:flatten(io_lib:format(
        "Fs=[~0tp,~0tp],"
        "Good=lists:all(fun(F)->case compile:file(F,[binary,return_errors,return_warnings]) of "
        "{ok,M,B,[]}->ok=file:write_file(atom_to_list(M)++\".beam\",B,[exclusive]),true;"
        "_->false end end,Fs),"
        "case Good of true->ok=file:write_file(\"cases.json\","
        "json:encode(diagnostic_assertion_fixture:manifest()),[exclusive]),halt(0);"
        "false->halt(2) end.",
        ["diagnostic_assertion_fixture.erl", "qualification_eunit_listener.erl"])),
    {CompileStatus, CompileOutput} = run_child_evaluation(Directory, [Directory], Evaluation, 15000),
    Compiled = diagnostic_assertion_process_ok(CompileStatus, CompileOutput, 0),
    {Cases, Runs, Beams} = case Compiled of
        true ->
            Manifest = evidence_json_decode(diagnostic_assertion_bytes(filename:join(Directory, "cases.json"))),
            BeamFiles = [filename:join(Directory, Name ++ ".beam") || Name <-
                ["diagnostic_assertion_fixture", "qualification_eunit_listener"]],
            BeamBefore = [{Path, diagnostic_assertion_bytes(Path)} || Path <- BeamFiles],
            Ordinary = diagnostic_assertion_run(Directory, Nonce, contract, Manifest),
            Negative = diagnostic_assertion_run(Directory, Nonce, failure, Manifest),
            {Manifest, [Ordinary, Negative], BeamBefore};
        false -> {[], [], []}
    end,
    Stable = lists:all(fun({Path, Bytes}) -> diagnostic_assertion_bytes(Path) =:= Bytes end,
                      Sources ++ Captured ++ Beams) andalso Runtime =:= diagnostic_assertion_runtime(),
    Passed = Compiled andalso Stable andalso length(Runs) =:= 2 andalso
             lists:all(fun(Run) -> maps:get(passed, Run) end, Runs),
    Report = #{schema => 1, run_nonce => Nonce, scope => <<"diagnostic assertion contract">>,
        passed => Passed, overall_candidate_ready => false, source_and_beams_unchanged => Stable,
        source_identity => diagnostic_assertion_identity(Sources),
        runtime_identity => Runtime,
        beam_identity => diagnostic_assertion_identity(Beams), cases => Cases,
        compiler => #{exit_status => CompileStatus,
            process => maps:without([tail, output_sha256], CompileOutput)}, runs => Runs},
    ReportPath = filename:join(Directory, "execution.json"),
    Bytes = iolist_to_binary(json:encode(Report)),
    ensure(binary:match(Bytes, <<"diagnostic-assertion-private-marker">>) =:= nomatch,
           assertion_report_private_payload),
    ok = file:write_file(ReportPath, Bytes, [exclusive]),
    io:format("assertion_contract_passed=~p evidence_present=~p~n",
              [Passed, filelib:is_regular(ReportPath)]),
    ensure(Passed, assertion_classification_contract).

diagnostic_assertion_run(Directory, Nonce, Kind, Cases) ->
    Function = case Kind of contract -> <<"contract_test_">>; failure -> <<"failure_test_">> end,
    Units = [#{module => <<"diagnostic_assertion_fixture">>, function => Function, kind => <<"generator">>}],
    Path = filename:join(Directory, atom_to_list(Kind) ++ ".json"),
    Evaluation = lists:flatten(io_lib:format(
        "{module,diagnostic_assertion_fixture}=code:ensure_loaded(diagnostic_assertion_fixture),"
        "qualification_eunit_listener:run(~0tp,~0tp,~0tp).",
        [Units, Path, Nonce])),
    {Status, Output} = run_child_evaluation(Directory, [Directory], Evaluation, 15000),
    Raw = case filelib:is_regular(Path) of true -> diagnostic_assertion_bytes(Path); false -> <<>> end,
    Redacted = binary:match(Raw, <<"diagnostic-assertion-private-marker">>) =:= nomatch,
    Child = try evidence_json_decode(Raw) catch _:_ -> #{} end,
    Schema = suite_child_schema_valid(Child, Units, Nonce),
    ExpectedStatus = case Kind of contract -> 0; failure -> 1 end,
    Exact = case Schema andalso Redacted of
        true -> diagnostic_assertion_counts(Kind, Child, Units, Nonce, Cases);
        false -> false
    end,
    OutputPositive = Kind =:= contract orelse
        binary:match(output_tail(Output), <<"diagnostic-assertion-private-marker">>) =/= nomatch,
    SafeChild = case Schema andalso Redacted of true -> Child; false -> #{invalid => true} end,
    %% Keep only the checked projection even when an intentionally broken
    %% formatter produces an unsafe report. Raw evidence is never an artifact.
    ok = file:write_file(Path, json:encode(SafeChild)),
    #{kind => Kind, exit_status => Status, schema_valid => Schema, redacted => Redacted,
      output_positive_control => OutputPositive, child => SafeChild,
      process => maps:without([tail, output_sha256], Output),
      passed => Exact andalso OutputPositive andalso
          diagnostic_assertion_process_ok(Status, Output, ExpectedStatus)}.

diagnostic_assertion_counts(contract, Child, Units, Nonce, Cases) ->
    suite_child_valid(Child, Units, Nonce) andalso suite_completed_tests(Child) =:= length(Cases);
diagnostic_assertion_counts(failure, Child, _, _, Cases) ->
    [Row] = maps:get(<<"units">>, Child),
    Counts = maps:get(<<"counts">>, Row),
    N = length(Cases),
    Counts =:= #{<<"started">> => N, <<"completed">> => N, <<"passed">> => 0,
        <<"failed">> => N, <<"skipped">> => 0, <<"cancelled">> => 0} andalso
    maps:get(<<"eunit_completed">>, Child) andalso
    maps:get(<<"unexpected_events">>, Child) =:= 0 andalso
    maps:get(<<"failure_count">>, Child) =:= N andalso
    maps:get(<<"failures_dropped">>, Child) =:= 0 andalso
    [maps:get(<<"classification">>, F) || F <- maps:get(<<"failures">>, Child)] =:=
        [maps:get(<<"category">>, C) || C <- Cases].

diagnostic_assertion_process_ok(Status, Output, Expected) ->
    process_status_verified(Status, Expected, Output).

diagnostic_assertion_bytes(Path) ->
    {ok, File} = file:open(Path, [read, binary, raw]),
    try
        {ok, Bytes} = file:read(File, 1048577),
        true = byte_size(Bytes) =< 1048576,
        eof = file:read(File, 1), Bytes
    after ok = file:close(File) end.

diagnostic_assertion_identity(Rows) ->
    [#{path => unicode:characters_to_binary(Path), bytes => byte_size(Bytes),
       sha256 => hex(crypto:hash(sha256, Bytes))} || {Path, Bytes} <- Rows].

diagnostic_assertion_runtime() ->
    Names = case os:type() of
        {win32, _} -> ["bin/erl.exe", "erts-" ++ erlang:system_info(version) ++ "/bin/beam.smp.dll"];
        _ -> ["bin/erl", "erts-" ++ erlang:system_info(version) ++ "/bin/beam.smp"]
    end,
    RuntimeFiles = [filename:join(code:root_dir(), Name) || Name <- Names] ++
        [filename:join([code:lib_dir(stdlib), "include", "assert.hrl"]),
         filename:join([code:lib_dir(eunit), "include", "eunit.hrl"]),
         code:which(eunit_proc), code:which(eunit_test)],
    #{otp_release => unicode:characters_to_binary(erlang:system_info(otp_release)),
      erts_version => unicode:characters_to_binary(erlang:system_info(version)),
      architecture => unicode:characters_to_binary(erlang:system_info(system_architecture)),
      files => [diagnostic_assertion_runtime_file(Path) || Path <- RuntimeFiles]}.

diagnostic_assertion_runtime_file(Path) ->
    {ok, File} = file:open(Path, [read, binary, raw]),
    try diagnostic_assertion_hash(File, Path, crypto:hash_init(sha256), 0)
    after ok = file:close(File) end.

diagnostic_assertion_hash(File, Path, Digest, Count) ->
    case file:read(File, 1048576) of
        eof -> #{path => unicode:characters_to_binary(Path), bytes => Count,
                 sha256 => hex(crypto:hash_final(Digest))};
        {ok, Bytes} when Count + byte_size(Bytes) =< 67108864 ->
            diagnostic_assertion_hash(File, Path, crypto:hash_update(Digest, Bytes),
                                      Count + byte_size(Bytes));
        _ -> erlang:error(runtime_identity_unavailable)
    end.
