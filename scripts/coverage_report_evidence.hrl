%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_COVERAGE_REPORT_EVIDENCE_HRL).
-define(HTTP_COVERAGE_REPORT_EVIDENCE_HRL, true).
-include("suite_evidence.hrl").
-include("json_evidence.hrl").
-include("runtime_matrix_evidence.hrl").

coverage_report_process_files(Mode) when Mode =:= <<"full">>; Mode =:= <<"changed">> ->
    Prefix = "build/coverage/report-" ++ binary_to_list(Mode),
    [Prefix ++ ".process.json", Prefix ++ ".attempt.json"].

coverage_report_process_audit(Mode, Report, Evidence, Identity) ->
    try
        [ProcessPath, AttemptPath] = coverage_report_process_files(Mode),
        Process = evidence_json_decode(coverage_process_read(ProcessPath, 65536)),
        Attempt = evidence_json_decode(coverage_process_read(AttemptPath, 4096)),
        Source = coverage_process_read("scripts/coverage.escript", 2097152),
        coverage_report_process_contract(Mode, Report, Evidence, Identity,
                                         Process, Attempt, Source)
    catch _:_ -> false end.

coverage_report_process_contract(Mode, ReportBytes, EvidenceBytes, Identity,
                                 Process, Attempt, SourceBytes) ->
    try
        true = Mode =:= <<"full">> orelse Mode =:= <<"changed">>,
        true = suite_exact_keys(Attempt, [schema, mode, nonce]),
        1 = maps:get(<<"schema">>, Attempt), Mode = maps:get(<<"mode">>, Attempt),
        Nonce = maps:get(<<"nonce">>, Attempt),
        true = is_binary(Nonce) andalso byte_size(Nonce) =:= 32,
        match = re:run(Nonce, <<"^[0-9a-f]{32}$">>, [{capture, none}]),
        true = suite_exact_keys(Process, [schema, scope, shareable, status, command,
            package, run_nonce, runner_source_sha256, completion, deadline_milliseconds,
            child_exit_status, process, evidence_identity, execution_environment]),
        1 = maps:get(<<"schema">>, Process), <<"CoverageProcess">> = maps:get(<<"scope">>, Process),
        true = maps:get(<<"shareable">>, Process), <<"Ready">> = maps:get(<<"status">>, Process),
        <<"report">> = maps:get(<<"command">>, Process), Mode = maps:get(<<"package">>, Process),
        Nonce = maps:get(<<"run_nonce">>, Process),
        300000 = maps:get(<<"deadline_milliseconds">>, Process),
        0 = maps:get(<<"child_exit_status">>, Process),
        Identity = maps:get(<<"evidence_identity">>, Process),
        SourceHash = coverage_process_hash(SourceBytes),
        SourceHash = maps:get(<<"runner_source_sha256">>, Process),
        Inner = maps:get(<<"process">>, Process),
        true = suite_exact_keys(Inner, runtime_matrix_process_keys()),
        true = runtime_matrix_process_valid(Inner),
        true = maps:get(<<"child_exit_observed">>, Inner),
        false = maps:get(<<"timed_out">>, Inner), false = maps:get(<<"output_limit_exceeded">>, Inner),
        true = maps:get(<<"output_digest_complete">>, Inner),
        8388608 = maps:get(<<"output_limit_bytes">>, Inner),
        33554432 = maps:get(<<"vm_process_heap_words">>, Inner),
        true = maps:get(<<"vm_heap_includes_shared_binaries">>, Inner),
        true = maps:get(<<"crash_dumps_disabled">>, Inner),
        Count = maps:get(<<"output_bytes">>, Inner),
        true = is_integer(Count) andalso Count >= 0 andalso Count =< 8388608,
        Count = maps:get(<<"output_hashed_bytes">>, Inner),
        Receipt = maps:get(<<"completion">>, Process),
        true = suite_exact_keys(Receipt, [schema, nonce, mode, child_exit_status,
                                         report_sha256, evidence_sha256]),
        1 = maps:get(<<"schema">>, Receipt), Nonce = maps:get(<<"nonce">>, Receipt),
        Mode = maps:get(<<"mode">>, Receipt), 0 = maps:get(<<"child_exit_status">>, Receipt),
        ReportHash = coverage_process_hash(ReportBytes),
        EvidenceHash = coverage_process_hash(EvidenceBytes),
        ReportHash = maps:get(<<"report_sha256">>, Receipt),
        EvidenceHash = maps:get(<<"evidence_sha256">>, Receipt),
        Report = evidence_json_decode(ReportBytes), Evidence = evidence_json_decode(EvidenceBytes),
        2 = maps:get(<<"schema">>, Report), 2 = maps:get(<<"schema">>, Evidence),
        Mode = maps:get(<<"mode">>, Report), <<"Ready">> = maps:get(<<"status">>, Report),
        <<"Ready">> = maps:get(Mode, maps:get(<<"statuses">>, Evidence)),
        Identity = maps:get(<<"evidence_identity">>, Report),
        Identity = maps:get(<<"evidence_identity">>, Evidence),
        Runtime = maps:get(<<"execution_environment">>, Process),
        Runtime = maps:get(<<"execution_environment">>, Report),
        Runtime = maps:get(<<"execution_environment">>, Evidence),
        true = suite_exact_keys(Runtime, [otp_version, erts_version, os_family,
                                         os_name, system_architecture, word_size]),
        true = lists:member(maps:get(<<"word_size">>, Runtime), [4, 8]),
        true = lists:all(fun(Key) ->
            Value = maps:get(Key, Runtime),
            is_binary(Value) andalso byte_size(Value) > 0 andalso byte_size(Value) =< 128 andalso
                re:run(Value, <<"^[A-Za-z0-9_.-]+$">>, [{capture, none}]) =:= match
        end, [<<"otp_version">>, <<"erts_version">>, <<"os_family">>, <<"os_name">>, <<"system_architecture">>]),
        true
    catch _:_ -> false end.

coverage_report_thresholds_match(Mode, Report, Evidence) ->
    try maps:get(<<"thresholds_basis_points">>, Report) =:=
            maps:get(Mode, maps:get(<<"thresholds_basis_points">>, Evidence))
    catch _:_ -> false end.

coverage_process_read(Path, Limit) ->
    {ok, Handle} = file:open(Path, [read, binary, raw]),
    try
        {ok, Bytes} = file:read(Handle, Limit + 1),
        true = byte_size(Bytes) =< Limit,
        eof = file:read(Handle, 1), Bytes
    after file:close(Handle) end.

coverage_process_hash(Bytes) -> binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).
-endif.
