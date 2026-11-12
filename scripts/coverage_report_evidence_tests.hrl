%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_COVERAGE_REPORT_EVIDENCE_TESTS_HRL).
-define(HTTP_COVERAGE_REPORT_EVIDENCE_TESTS_HRL, true).
-include("coverage_report_evidence.hrl").

coverage_report_process_self_test() ->
    %% These are explicitly synthetic document-shape controls. Actual report
    %% dispatch and owned-VM completion are exercised by coverage_report_test.
    Identity = #{<<"schema">> => 2, <<"source_sha256">> => binary:copy(<<"A">>, 64), <<"files">> => 1},
    Runtime = json:decode(iolist_to_binary(json:encode(execution_runtime()))),
    {ok, Source} = file:read_file("scripts/coverage.escript"),
    Nonce = binary:copy(<<"a">>, 32), NewNonce = binary:copy(<<"b">>, 32),
    Attempt = #{<<"schema">> => 1, <<"mode">> => <<"full">>, <<"nonce">> => Nonce},
    Thresholds = #{<<"full">> => #{<<"lines">> => 9500, <<"branches">> => 9000},
                   <<"changed">> => #{<<"lines">> => 10000, <<"branches">> => 10000}},
    Report = #{<<"schema">> => 2, <<"mode">> => <<"full">>, <<"status">> => <<"Ready">>,
        <<"evidence_identity">> => Identity, <<"execution_environment">> => Runtime,
        <<"thresholds_basis_points">> => maps:get(<<"full">>, Thresholds)},
    Evidence = #{<<"schema">> => 2, <<"statuses">> => #{<<"full">> => <<"Ready">>, <<"changed">> => <<"Ready">>},
        <<"evidence_identity">> => Identity, <<"execution_environment">> => Runtime,
        <<"thresholds_basis_points">> => Thresholds},
    RB = iolist_to_binary(json:encode(Report)), EB = iolist_to_binary(json:encode(Evidence)),
    Inner = runtime_matrix_json(runtime_matrix_process_fixture(#{
        output_bytes => 0, output_hashed_bytes => 0,
        output_limit_bytes => 8388608, output_digest_complete => true,
        output_limit_exceeded => false, vm_process_heap_words => 33554432,
        vm_heap_includes_shared_binaries => true, crash_dumps_disabled => true,
        timed_out => false, child_exit_observed => true})),
    Receipt = #{<<"schema">> => 1, <<"nonce">> => Nonce, <<"mode">> => <<"full">>, <<"child_exit_status">> => 0,
        <<"report_sha256">> => coverage_process_hash(RB), <<"evidence_sha256">> => coverage_process_hash(EB)},
    Process = #{<<"schema">> => 1, <<"scope">> => <<"CoverageProcess">>, <<"shareable">> => true,
        <<"status">> => <<"Ready">>, <<"command">> => <<"report">>, <<"package">> => <<"full">>,
        <<"run_nonce">> => Nonce, <<"runner_source_sha256">> => coverage_process_hash(Source),
        <<"completion">> => Receipt, <<"deadline_milliseconds">> => 300000, <<"child_exit_status">> => 0,
        <<"process">> => Inner, <<"evidence_identity">> => Identity, <<"execution_environment">> => Runtime},
    Accept = fun(P, A, R, E, S) -> coverage_report_process_contract(<<"full">>, R, E, Identity, P, A, S) end,
    true = Accept(Process, Attempt, RB, EB, Source),
    false = Accept(Process, Attempt#{<<"nonce">> => NewNonce}, RB, EB, Source),
    false = Accept(Process#{<<"completion">> => Receipt#{<<"nonce">> => NewNonce}}, Attempt, RB, EB, Source),
    false = Accept(Process#{<<"completion">> => Receipt#{<<"mode">> => <<"changed">>}}, Attempt, RB, EB, Source),
    false = Accept(Process, Attempt, <<RB/binary, " ">>, EB, Source),
    false = Accept(Process, Attempt, RB, <<EB/binary, " ">>, Source),
    false = Accept(Process, Attempt, RB, EB, <<Source/binary, " ">>),
    false = Accept(Process#{<<"process">> => Inner#{<<"child_exit_observed">> => false}}, Attempt, RB, EB, Source),
    false = Accept(Process#{<<"process">> => Inner#{<<"timed_out">> => true}}, Attempt, RB, EB, Source),
    false = Accept(Process#{<<"process">> => Inner#{<<"output_limit_exceeded">> => true}}, Attempt, RB, EB, Source),
    false = Accept(Process#{<<"child_exit_status">> => 1}, Attempt, RB, EB, Source),
    false = Accept(Process#{<<"private">> => <<"coverage-process-private">>}, Attempt, RB, EB, Source),
    true = coverage_report_thresholds_match(<<"full">>, Report, Evidence),
    true = coverage_report_thresholds_match(<<"changed">>,
        Report#{<<"thresholds_basis_points">> => maps:get(<<"changed">>, Thresholds)}, Evidence),
    false = coverage_report_thresholds_match(<<"full">>,
        Report#{<<"thresholds_basis_points">> => Thresholds}, Evidence),
    coverage_report_retained_controls(Process, Attempt, RB, EB, Identity, Source),
    io:format("coverage process evidence: 18 synthetic/retained controls passed~n"), ok.

coverage_report_retained_controls(Process, Attempt, RB, EB, Identity, Source) ->
    {ok, Root} = file:get_cwd(),
    {ok, SupervisorSource} = file:read_file("scripts/process_supervisor.py"),
    Directory = filename:absname("build/coverage-report-audit-tests/" ++
        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16)))),
    ok = filelib:ensure_dir(filename:join(Directory, "scripts/coverage.escript")),
    ok = file:write_file(filename:join(Directory, "scripts/coverage.escript"), Source),
    ok = file:write_file(
        filename:join(Directory, "scripts/process_supervisor.py"),
        SupervisorSource),
    try
        ok = file:set_cwd(Directory),
        [PP, AP] = coverage_report_process_files(<<"full">>),
        ok = filelib:ensure_dir(PP),
        ok = file:write_file(PP, json:encode(Process)),
        ok = file:write_file(AP, json:encode(Attempt)),
        true = coverage_report_process_audit(<<"full">>, RB, EB, Identity),
        ok = file:delete(PP),
        false = coverage_report_process_audit(<<"full">>, RB, EB, Identity),
        ok = file:write_file(PP, json:encode(Process)),
        ok = file:delete(AP),
        false = coverage_report_process_audit(<<"full">>, RB, EB, Identity),
        ok = file:write_file("result.json", json:encode(#{schema => 1,
            scope => <<"Synthetic metric/parent records; actual bounded retained-file reads">>,
            passed => true, missing_process_rejected => true, missing_attempt_rejected => true}))
    after file:set_cwd(Root) end.
-endif.
