%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_RELEASE_EVIDENCE).
-define(HTTP_RELEASE_EVIDENCE, true).
-include("examples_evidence.hrl").
-include("release_sources.hrl").
-include("json_evidence.hrl").

release_directory(Nonce) -> "build/release-sim/run-" ++ binary_to_list(Nonce).
release_path(Path) -> unicode:characters_to_binary(examples_normalise(Path)).

release_tree(Root) ->
    examples_real_path(Root),
    {_, Paths} = release_walk(Root, "", 0, 16384, []),
    lists:sort(Paths).
release_walk(Root, Relative, Depth, Remaining, Acc) ->
    true = Depth =< 24 andalso Remaining > 0,
    Directory = case Relative of "" -> Root; _ -> filename:join(Root, Relative) end,
    {ok, Names} = file:list_dir(Directory),
    true = length(Names) =< Remaining,
    lists:foldl(fun(Name, {Left, Paths}) ->
        Part = case Relative of "" -> Name; _ -> filename:join(Relative, Name) end,
        Path = filename:join(Root, Part),
        {ok, Info} = file:read_link_info(Path),
        true = Left > 0,
        case Info#file_info.type of
            regular ->
                true = Info#file_info.size =< 16777216,
                {Left - 1, [examples_normalise(Part) | Paths]};
            directory -> release_walk(Root, Part, Depth + 1, Left - 1, Paths);
            _ -> error(release_non_regular_member)
        end
    end, {Remaining, Acc}, Names).

release_tree_inventory(Root) ->
    release_inventory([{Path, examples_read(filename:join(Root, Path), 16777216)} ||
        Path <- release_tree(Root)]).
release_inventory(Files) ->
    true = length(Files) =< 16384,
    true = lists:sum([byte_size(Bytes) || {_, Bytes} <- Files]) =< 268435456,
    [#{path => release_path(Path), bytes => byte_size(Bytes),
        sha256 => binary:encode_hex(crypto:hash(sha256, Bytes))} ||
        {Path, Bytes} <- lists:keysort(1, Files)].

release_generated_files(Out) ->
    Root = filename:join(Out, "_gleam_artefacts"),
    Paths = [P || P <- release_tree(Root), filename:extension(P) =:= ".erl"],
    true = length(Paths) > 0 andalso length(Paths) =< 1024,
    [begin
        Name = unicode:characters_to_binary(filename:basename(P, ".erl")),
        match = re:run(Name, <<"^[a-z][a-zA-Z0-9_@]*$">>, [{capture, none}]),
        Path = filename:join(Root, P),
        #{module => Name, path => release_path(Path),
          sha256 => examples_file_hash(Path, 16777216)}
    end || P <- Paths].

release_support_files(Out) ->
    Roots = [filename:join(Out, Part) || Part <- ["_gleam_artefacts", "include"]],
    Paths = lists:sort(lists:append([[filename:join(Root, P) || P <- release_tree(Root),
        filename:extension(P) =:= ".hrl"] || Root <- Roots, filelib:is_dir(Root)])),
    true = length(Paths) =< 2048,
    [#{path => release_path(P), sha256 => examples_file_hash(P, 16777216)} || P <- Paths].

release_compile_child_valid(Child, Nonce, Files) ->
    try
        true = suite_exact_keys(Child, [schema, nonce, status, modules,
            compiler_worker_heap_words, compiler_heap_includes_shared_binaries, compiler_workers_joined]),
        ok = release_compile_profile_valid(Child, Nonce, 134217728),
        <<"Passed">> = maps:get(<<"status">>, Child),
        Rows = maps:get(<<"modules">>, Child),
        true = is_list(Rows) andalso length(Rows) =:= length(Files),
        release_compile_rows_valid(Rows, Files)
    catch _:_ -> false end.

release_compile_profile_valid(Child, Nonce, HeapWords) ->
    2 = maps:get(<<"schema">>, Child), Nonce = maps:get(<<"nonce">>, Child),
    HeapWords = maps:get(<<"compiler_worker_heap_words">>, Child),
    true = maps:get(<<"compiler_heap_includes_shared_binaries">>, Child),
    true = maps:get(<<"compiler_workers_joined">>, Child), ok.

release_compile_rows_valid(Rows, Files) ->
    lists:all(fun({Row, File}) ->
            suite_exact_keys(Row, [module, generated_sha256, beam_sha256]) andalso
            maps:get(<<"module">>, Row) =:= maps:get(module, File) andalso
            maps:get(<<"generated_sha256">>, Row) =:= maps:get(sha256, File) andalso
            examples_hash_valid(maps:get(<<"beam_sha256">>, Row))
        end, lists:zip(Rows, Files)).

%% All common ownership/output rules remain identical. The sole profile
%% difference is the declared compiler-only default for OTP inliner workers.
release_compiler_process_valid(Proof) ->
    try
        Process = maps:get(<<"process">>, Proof),
        134217728 = maps:get(<<"vm_process_heap_words">>, Process),
        examples_process_valid(Proof#{<<"process">> =>
            Process#{<<"vm_process_heap_words">> => 33554432}}, beam)
    catch _:_ -> false end.

release_safe_compile_child(Child, Nonce, Files) ->
    release_safe_compile_child(Child, Nonce, Files, 134217728).
release_safe_compile_child(Child, Nonce, Files, HeapWords) ->
    case release_compile_child_valid(Child, Nonce, Files) of
        true -> Child;
        false ->
            try
                true = suite_exact_keys(Child, [schema, nonce, status, modules,
                    classification, exception_class, stack_depth, phase, failed_module,
                    error_count, warning_count, compiler_worker_heap_words,
                    compiler_heap_includes_shared_binaries, compiler_workers_joined]),
                ok = release_compile_profile_valid(Child, Nonce, HeapWords),
                <<"Failed">> = maps:get(<<"status">>, Child),
                Rows = maps:get(<<"modules">>, Child),
                true = is_list(Rows) andalso length(Rows) =< length(Files),
                true = release_compile_rows_valid(Rows, lists:sublist(Files, length(Rows))),
                Phase = maps:get(<<"phase">>, Child),
                true = lists:member(Phase, [<<"validation">>, <<"input_support">>, <<"input_source">>,
                    <<"compiler">>, <<"output_source">>, <<"write_beam">>, <<"output_support">>]),
                FailedModule = maps:get(<<"failed_module">>, Child),
                true = case Phase of
                    <<"validation">> -> FailedModule =:= <<"none">> andalso Rows =:= [];
                    <<"input_support">> -> FailedModule =:= <<"none">> andalso Rows =:= [];
                    <<"output_support">> -> FailedModule =:= <<"none">> andalso length(Rows) =:= length(Files);
                    _ -> length(Rows) < length(Files) andalso
                        FailedModule =:= maps:get(module, lists:nth(length(Rows) + 1, Files))
                end,
                lists:foreach(fun(Key) -> Count = maps:get(Key, Child),
                    true = is_integer(Count) andalso Count >= 0 andalso Count =< 65535
                end, [<<"error_count">>, <<"warning_count">>]),
                true = lists:member(maps:get(<<"classification">>, Child),
                    [<<"pattern_mismatch">>, <<"unexpected_variant">>, <<"assertion_failed">>,
                     <<"callback_failed">>, <<"invalid_argument">>, <<"resource_limit">>,
                     <<"deadline_exceeded">>, <<"validation_failed">>, <<"compiler_worker_exit">>,
                     <<"compiler_warnings">>, <<"compiler_errors">>, <<"compiler_result">>]),
                true = lists:member(maps:get(<<"exception_class">>, Child),
                    [<<"error">>, <<"exit">>, <<"throw">>]),
                Depth = maps:get(<<"stack_depth">>, Child),
                true = is_integer(Depth) andalso Depth >= 0 andalso Depth =< 16,
                Child
            catch _:_ -> #{invalid => true} end
    end.

%% Expected is reconstructed from current source by the caller. None of the
%% paths, package identities, module sets or allowed evidence keys come from
%% the report. Both archives and every executed BEAM are re-read here.
release_validate_report(Report, Identity, Builds, Expected) ->
    try
        true = suite_exact_keys(Report, [schema, status, shareable, version,
            run_nonce, archive_format, dependency_mode, artifacts, package_compilers,
            consumers, build_identity, runner_sha256, execution_environment,
            evidence_identity, dependency_library, sbom, provenance, ephemeral_signature]),
        2 = maps:get(<<"schema">>, Report), <<"Ready">> = maps:get(<<"status">>, Report),
        true = maps:get(<<"shareable">>, Report), <<"0.1.0">> = maps:get(<<"version">>, Report),
        <<"Hex v3">> = maps:get(<<"archive_format">>, Report),
        <<"exact archive registry">> = maps:get(<<"dependency_mode">>, Report),
        Identity = maps:get(<<"evidence_identity">>, Report),
        Builds = maps:get(<<"build_identity">>, Report),
        true = suite_exact_keys(Builds, [core, http3, http]),
        Runtime = maps:get(<<"execution_environment">>, Report),
        lists:foreach(fun(B) -> Runtime = maps:get(<<"runtime">>, maps:get(<<"toolchain">>, B)) end,
            maps:values(Builds)),
        Nonce = maps:get(<<"run_nonce">>, Report), true = examples_nonce_valid(Nonce),
        Directory = release_directory(Nonce),
        true = suite_exact_keys(maps:get(<<"runner_sha256">>, Report),
            [examples_child, qualification_eunit_listener, release_child]),
        maps:foreach(fun(Name, Digest) -> Digest = examples_file_hash(
            filename:join([Directory, "runner", binary_to_list(Name) ++ ".beam"]), 4194304)
        end, maps:get(<<"runner_sha256">>, Report)),
        [<<"quic_core">>, <<"http3">>, <<"http">>] = [maps:get(name, E) || E <- Expected],
        Artifacts = maps:get(<<"artifacts">>, Report),
        true = length(Artifacts) =:= 3,
        lists:foreach(fun({A, E}) -> release_archive_valid(A, E, Directory) end,
            lists:zip(Artifacts, Expected)),
        Dependencies = maps:get(<<"dependency_library">>, Report),
        [<<"gleam_stdlib">>, <<"gleam_erlang">>, <<"gleam_http">>] =
            [maps:get(<<"name">>, D) || D <- Dependencies],
        lists:foreach(fun(D) ->
            true = suite_exact_keys(D, [name, files]),
            Name = binary_to_list(maps:get(<<"name">>, D)),
            Files = release_json(release_tree_inventory(filename:join("build/dev/erlang", Name))),
            Files = maps:get(<<"files">>, D),
            Files = release_json(release_tree_inventory(filename:join([Directory, "lib", Name])))
        end, Dependencies),
        Compilers = maps:get(<<"package_compilers">>, Report),
        Consumers = maps:get(<<"consumers">>, Report),
        true = length(Compilers) =:= 3 andalso length(Consumers) =:= 3,
        lists:foreach(fun({C, E}) ->
            Name = maps:get(name, E),
            release_package_compiler_valid(C, Name, <<"package">>,
                filename:join([Directory, "lib", binary_to_list(Name)]), maps:get(modules, E)),
            release_archive_headers_valid(E, filename:join([Directory, "lib", binary_to_list(Name)]))
        end, lists:zip(Compilers, Expected)),
        lists:foreach(fun({C, E}) -> release_consumer_valid(C, E, Directory) end,
            lists:zip(Consumers, Expected)),
        Sbom = release_json(release_sbom(Artifacts)),
        Sbom = release_artifact_file_valid(maps:get(<<"sbom">>, Report),
            filename:join(Directory, "release-sim.cdx.json")),
        Signature = maps:get(<<"ephemeral_signature">>, Report),
        Provenance = release_json(release_provenance(Report)),
        Provenance = release_artifact_file_valid(maps:get(<<"provenance">>, Report),
            filename:join(Directory, "provenance.json")),
        release_signature_valid(Signature, Artifacts),
        ok
    catch _:_ -> error end.

release_archive_valid(A, Expected, Directory) ->
    true = suite_exact_keys(A, [sha256, bytes, files, source_inventory, path, name]),
    Name = maps:get(name, Expected), Name = maps:get(<<"name">>, A),
    Digest = maps:get(<<"sha256">>, A), true = examples_hash_valid(Digest),
    Paths = [filename:join([Directory, Pass, binary_to_list(Name) ++ "-0.1.0.tar"]) ||
        Pass <- ["pass-a", "pass-b"]],
    Last = release_path(lists:last(Paths)), Last = maps:get(<<"path">>, A),
    Files = release_json(maps:get(files, Expected)), Files = maps:get(<<"source_inventory">>, A),
    Count = length(Files), Count = maps:get(<<"files">>, A),
    lists:foreach(fun(Path) ->
        Bytes = examples_read(Path, 134217728),
        Size = byte_size(Bytes), Size = maps:get(<<"bytes">>, A),
        Digest = binary:encode_hex(crypto:hash(sha256, Bytes)),
        {ok, Outer} = erl_tar:extract({binary, Bytes}, [memory, {max_size, 134217728}]),
        ["CHECKSUM", "VERSION", "contents.tar.gz", "metadata.config"] = lists:sort([N || {N, _} <- Outer]),
        <<"3">> = proplists:get_value("VERSION", Outer),
        Metadata = maps:get(metadata, Expected), Metadata = proplists:get_value("metadata.config", Outer),
        Contents = proplists:get_value("contents.tar.gz", Outer),
        Checksum = binary:encode_hex(crypto:hash(sha256, [<<"3">>, Metadata, Contents])),
        Checksum = proplists:get_value("CHECKSUM", Outer),
        {ok, Inner} = erl_tar:extract({binary, Contents}, [compressed, memory, {max_size, 134217728}]),
        true = release_archive_metadata_valid(Bytes, Contents),
        Files = release_json(release_inventory(Inner))
    end, Paths),
    Registry = filename:join([Directory, "registry", binary_to_list(Name), "0.1.0"]),
    Files = release_json(release_tree_inventory(Registry)),
    ok.

release_archive_metadata_valid(Bytes, Contents) ->
    {ok, OuterTable} = erl_tar:table({binary, Bytes}, [verbose]),
    {ok, InnerTable} = erl_tar:table({binary, Contents}, [compressed, verbose]),
    lists:all(fun
        ({_, regular, _, 0, 8#100644, 0, 0}) -> true;
        (_) -> false
    end, OuterTable ++ InnerTable).

release_package_compiler_valid(C, Name, Kind, Out, ExpectedModules) ->
    true = suite_exact_keys(C, [name, kind, compiler, beam_compiler, generated, generated_support, status]),
    Name = maps:get(<<"name">>, C), Kind = maps:get(<<"kind">>, C),
    <<"Passed">> = maps:get(<<"status">>, C),
    Compiler = maps:get(<<"compiler">>, C),
    true = suite_exact_keys(Compiler, [child_exit_status, timeout_milliseconds, process]),
    120000 = maps:get(<<"timeout_milliseconds">>, Compiler),
    true = examples_process_valid(Compiler, compiler),
    0 = maps:get(<<"output_bytes">>, maps:get(<<"process">>, Compiler)),
    Files = release_generated_files(Out),
    ExpectedModules = lists:sort([maps:get(module, F) || F <- Files]),
    ExpectedModules = lists:sort([unicode:characters_to_binary(filename:basename(P, ".beam")) ||
        P <- release_tree(filename:join(Out, "ebin")), filename:extension(P) =:= ".beam"]),
    FilesJson = release_json(Files), FilesJson = maps:get(<<"generated">>, C),
    Supports = release_json(release_support_files(Out)),
    Supports = maps:get(<<"generated_support">>, C),
    BeamCompiler = maps:get(<<"beam_compiler">>, C),
    true = suite_exact_keys(BeamCompiler, [child_exit_status, timeout_milliseconds, process, child, run_nonce]),
    120000 = maps:get(<<"timeout_milliseconds">>, BeamCompiler),
    true = release_compiler_process_valid(BeamCompiler),
    Nonce = maps:get(<<"run_nonce">>, BeamCompiler), true = examples_nonce_valid(Nonce),
    Child = maps:get(<<"child">>, BeamCompiler),
    true = release_compile_child_valid(Child, Nonce, Files),
    Child = evidence_json_decode(examples_read(filename:join(Out, "beam-compiler.json"), 16777216)),
    lists:foreach(fun(Row) ->
        Digest = maps:get(<<"beam_sha256">>, Row),
        Digest = examples_file_hash(filename:join([Out, "ebin",
            binary_to_list(maps:get(<<"module">>, Row)) ++ ".beam"]), 16777216)
    end, maps:get(<<"modules">>, Child)),
    ok.

release_archive_headers_valid(Expected, Out) ->
    lists:foreach(fun(F) ->
        Path = binary_to_list(maps:get(path, F)),
        case filename:extension(Path) of
            ".hrl" ->
                "src/" ++ Relative = Path,
                Hash = maps:get(sha256, F),
                Hash = examples_file_hash(filename:join([Out, "_gleam_artefacts", Relative]), 16777216);
            _ -> ok
        end
    end, maps:get(files, Expected)), ok.

release_consumer_valid(C, Expected, Directory) ->
    true = suite_exact_keys(C, [name, dependency, requirement, compiler,
        source_sha256, manifest_sha256, execution, status]),
    Dependency = maps:get(name, Expected), Dependency = maps:get(<<"dependency">>, C),
    Name = <<"empty_", Dependency/binary, "_consumer">>, Name = maps:get(<<"name">>, C),
    <<"== 0.1.0">> = maps:get(<<"requirement">>, C), <<"Passed">> = maps:get(<<"status">>, C),
    Consumer = filename:join([Directory, "consumers", binary_to_list(Name)]),
    Source = maps:get(consumer_source, Expected), Manifest = maps:get(consumer_manifest, Expected),
    SourceHash = binary:encode_hex(crypto:hash(sha256, Source)), SourceHash = maps:get(<<"source_sha256">>, C),
    ManifestHash = binary:encode_hex(crypto:hash(sha256, Manifest)), ManifestHash = maps:get(<<"manifest_sha256">>, C),
    Module = <<Name/binary, "_main">>,
    Source = examples_read(filename:join([Consumer, "src", binary_to_list(Module) ++ ".gleam"]), 524288),
    Manifest = examples_read(filename:join(Consumer, "gleam.toml"), 524288),
    Out = filename:join(Consumer, "out"),
    release_package_compiler_valid(maps:get(<<"compiler">>, C), Name, <<"consumer">>, Out, [Module]),
    E = maps:get(<<"execution">>, C),
    true = suite_exact_keys(E, [module, run_nonce, timeout_milliseconds, child_exit_status,
        process, child, completed_tests, beam_sha256, status]),
    Module = maps:get(<<"module">>, E), <<"Passed">> = maps:get(<<"status">>, E),
    30000 = maps:get(<<"timeout_milliseconds">>, E), 1 = maps:get(<<"completed_tests">>, E),
    Nonce = maps:get(<<"run_nonce">>, E), true = examples_nonce_valid(Nonce),
    true = examples_process_valid(E, beam),
    true = suite_child_valid(maps:get(<<"child">>, E), [examples_unit(Module)], Nonce),
    Stored = evidence_json_decode(examples_read(filename:join(Out, "execution.json"), 16777216)),
    Stored = maps:get(<<"child">>, E),
    Digest = maps:get(<<"beam_sha256">>, E),
    Digest = examples_file_hash(filename:join([Out, "ebin", binary_to_list(Module) ++ ".beam"]), 16777216),
    ok.

release_artifact_file_valid(Proof, Path) ->
    true = suite_exact_keys(Proof, [path, sha256]),
    Name = release_path(Path), Name = maps:get(<<"path">>, Proof),
    Hash = examples_file_hash(Path, 16777216), Hash = maps:get(<<"sha256">>, Proof),
    evidence_json_decode(examples_read(Path, 16777216)).
release_signature_valid(S, Artifacts) ->
    true = suite_exact_keys(S, [algorithm, verified, public_key, signature, payload_sha256]),
    <<"Ed25519">> = maps:get(<<"algorithm">>, S), true = maps:get(<<"verified">>, S),
    Payload = iolist_to_binary([maps:get(<<"sha256">>, A) || A <- Artifacts]),
    Hash = binary:encode_hex(crypto:hash(sha256, Payload)), Hash = maps:get(<<"payload_sha256">>, S),
    Public = binary:decode_hex(maps:get(<<"public_key">>, S)),
    Signature = binary:decode_hex(maps:get(<<"signature">>, S)),
    true = byte_size(Public) =:= 32 andalso byte_size(Signature) =:= 64,
    true = crypto:verify(eddsa, none, Payload, Signature, [Public, ed25519]), ok.
release_json(Value) -> json:decode(iolist_to_binary(json:encode(Value))).
-endif.
