%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_EXAMPLES_EVIDENCE).
-define(HTTP_EXAMPLES_EVIDENCE, true).
-include("suite_evidence.hrl").
-include("examples_source.hrl").
-include("runtime_matrix_evidence.hrl").

%% The caller supplies its independently verified current source and fresh
%% build identities. Expected examples come from examples_sources/0, never
%% from the report. Retained generated inputs and executable bytes are checked
%% again here, so a report cannot silently describe replaced BEAMs.
examples_validate_report(Report, Identity, Build, Expected) ->
    try
        true = suite_exact_keys(Report, [schema, status, shareable, count,
            markdown_files_scanned, run_nonce, build_identity, runner_sha256,
            compiler, beam_compiler, examples, completed_tests,
            evidence_identity, execution_environment]),
        2 = maps:get(<<"schema">>, Report),
        <<"Ready">> = maps:get(<<"status">>, Report),
        true = maps:get(<<"shareable">>, Report),
        Identity = maps:get(<<"evidence_identity">>, Report),
        Build = maps:get(<<"build_identity">>, Report),
        Runtime = maps:get(<<"runtime">>, maps:get(<<"toolchain">>, Build)),
        Runtime = maps:get(<<"execution_environment">>, Report),
        Nonce = maps:get(<<"run_nonce">>, Report),
        true = examples_nonce_valid(Nonce),
        Directory = examples_run_directory(Nonce),
        Count = length(Expected),
        true = Count > 0 andalso Count =< 256,
        Count = maps:get(<<"count">>, Report),
        Count = maps:get(<<"completed_tests">>, Report),
        Scanned = length(examples_markdown_files()),
        Scanned = maps:get(<<"markdown_files_scanned">>, Report),
        true = examples_runner_valid(maps:get(<<"runner_sha256">>, Report), Directory),
        Compiler = maps:get(<<"compiler">>, Report),
        true = suite_exact_keys(Compiler, [stage, child_exit_status, process, timeout_milliseconds]),
        <<"gleam_no_beam">> = maps:get(<<"stage">>, Compiler),
        120000 = maps:get(<<"timeout_milliseconds">>, Compiler),
        true = examples_process_valid(Compiler, compiler),
        0 = maps:get(<<"output_bytes">>, maps:get(<<"process">>, Compiler)),
        BeamCompiler = maps:get(<<"beam_compiler">>, Report),
        true = suite_exact_keys(BeamCompiler, [stage, child_exit_status, process, child, timeout_milliseconds]),
        <<"beam_compile">> = maps:get(<<"stage">>, BeamCompiler),
        120000 = maps:get(<<"timeout_milliseconds">>, BeamCompiler),
        true = examples_process_valid(BeamCompiler, beam),
        true = examples_compile_child_valid(maps:get(<<"child">>, BeamCompiler), Nonce, Expected),
        Rows = maps:get(<<"examples">>, Report),
        true = is_list(Rows) andalso length(Rows) =:= Count,
        true = lists:all(fun({Row, Example}) -> examples_row_valid(Row, Example, Directory) end,
                          lists:zip(Rows, Expected)),
        true = lists:all(fun(Row) -> maps:get(<<"timeout_milliseconds">>, Row) =:= 30000 end, Rows),
        Compiled = maps:get(<<"modules">>, maps:get(<<"child">>, BeamCompiler)),
        Compiled = [maps:with([<<"module">>, <<"generated_sha256">>, <<"beam_sha256">>], R) || R <- Rows],
        ok
    catch _:_ -> error end.

examples_row_valid(Row, Example, Directory) ->
    true = suite_exact_keys(Row, [package, module, document, line, sha256,
        generated_sha256, beam_sha256, run_nonce, status, child_exit_status,
        process, child, completed_tests, timeout_milliseconds]),
    true = lists:all(fun({Key, Value}) -> maps:get(atom_to_binary(Key), Row) =:= Value end,
        maps:to_list(maps:remove(source, Example))),
    <<"Passed">> = maps:get(<<"status">>, Row),
    1 = maps:get(<<"completed_tests">>, Row),
    Name = maps:get(module, Example),
    Nonce = maps:get(<<"run_nonce">>, Row),
    true = examples_nonce_valid(Nonce),
    Timeout = maps:get(<<"timeout_milliseconds">>, Row),
    true = is_integer(Timeout) andalso Timeout > 0 andalso Timeout =< 30000,
    true = examples_process_valid(Row, beam),
    true = suite_child_valid(maps:get(<<"child">>, Row), [examples_unit(Name)], Nonce),
    Generated = examples_generated_path(Directory, Name),
    Beam = examples_beam_path(Directory, Name),
    Source = maps:get(source, Example),
    true = examples_read(examples_project_path(Directory, Name), 524289) =:= <<Source/binary, $\n>>,
    maps:get(<<"generated_sha256">>, Row) =:= examples_file_hash(Generated, 4194304) andalso
    maps:get(<<"beam_sha256">>, Row) =:= examples_file_hash(Beam, 4194304).

examples_process_valid(Proof, Kind) ->
    0 = maps:get(<<"child_exit_status">>, Proof),
    Process = maps:get(<<"process">>, Proof),
    true = suite_exact_keys(Process, runtime_matrix_process_keys()),
    Bytes = maps:get(<<"output_bytes">>, Process),
    true = is_integer(Bytes) andalso Bytes >= 0 andalso Bytes =< 8388608,
    Bytes = maps:get(<<"output_hashed_bytes">>, Process),
    8388608 = maps:get(<<"output_limit_bytes">>, Process),
    true = maps:get(<<"output_digest_complete">>, Process),
    false = maps:get(<<"output_limit_exceeded">>, Process),
    false = maps:get(<<"timed_out">>, Process),
    true = maps:get(<<"child_exit_observed">>, Process),
    true = runtime_matrix_process_valid(Process),
    Kind =:= compiler orelse Kind =:= beam.

examples_compile_child_valid(Child, Nonce, Expected) ->
    try
        true = suite_exact_keys(Child, [schema, nonce, status, modules]),
        1 = maps:get(<<"schema">>, Child),
        Nonce = maps:get(<<"nonce">>, Child),
        <<"Passed">> = maps:get(<<"status">>, Child),
        Rows = maps:get(<<"modules">>, Child),
        true = is_list(Rows) andalso length(Rows) =:= length(Expected),
        lists:all(fun({Row, E}) ->
            suite_exact_keys(Row, [module, generated_sha256, beam_sha256]) andalso
            maps:get(<<"module">>, Row) =:= maps:get(module, E) andalso
            examples_hash_valid(maps:get(<<"generated_sha256">>, Row)) andalso
            examples_hash_valid(maps:get(<<"beam_sha256">>, Row))
        end, lists:zip(Rows, Expected))
    catch _:_ -> false end.

examples_runner_valid(Hashes, Directory) ->
    true = suite_exact_keys(Hashes, [examples_child, qualification_eunit_listener]),
    lists:all(fun(Name) -> maps:get(list_to_binary(Name), Hashes) =:=
        examples_file_hash(filename:join([Directory, "runner", Name ++ ".beam"]), 4194304)
    end, ["examples_child", "qualification_eunit_listener"]).

examples_unit(Name) -> #{module => Name, function => <<"main">>, kind => <<"test">>}.
examples_nonce_valid(N) -> is_binary(N) andalso byte_size(N) =:= 32 andalso
    re:run(N, <<"^[0-9A-F]{32}$">>, [{capture, none}]) =:= match.
examples_hash_valid(H) -> is_binary(H) andalso byte_size(H) =:= 64 andalso
    re:run(H, <<"^[0-9A-F]{64}$">>, [{capture, none}]) =:= match.
examples_run_directory(Nonce) -> "build/examples/run-" ++ binary_to_list(Nonce).
examples_generated_path(Directory, Name) -> filename:join([Directory, "out", "_gleam_artefacts", binary_to_list(Name) ++ ".erl"]).
examples_project_path(Directory, Name) -> filename:join([Directory, "src", binary_to_list(Name) ++ ".gleam"]).
examples_beam_path(Directory, Name) -> filename:join([Directory, "out", "ebin", binary_to_list(Name) ++ ".beam"]).
examples_file_hash(Path, Limit) -> binary:encode_hex(crypto:hash(sha256, examples_read(Path, Limit))).
-endif.
