#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-include("evidence_identity.hrl").
-include("fresh_build_identity.hrl").
-include("process_runner.hrl").
-include("examples_evidence.hrl").
-include("release_evidence.hrl").
-include("release_archive_tests.hrl").
-compile(nowarn_unused_function).

-define(OUTPUT, "build/release-sim").
-define(VERSION, <<"0.1.0">>).
-define(MAX_ARCHIVE_BYTES, 128 * 1024 * 1024).

main(Arguments) ->
    Root = filename:dirname(filename:dirname(filename:absname(escript:script_name()))),
    ok = file:set_cwd(Root),
    try dispatch(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            Failure = diagnostic_failure_details(Class, Reason, Stacktrace),
            preserve_failure(Failure),
            io:format(standard_error, "release simulation failed: ~s~n", [json:encode(Failure)]),
            halt(1)
    end.

dispatch([]) -> run();
dispatch(["--self-test"]) -> self_test();
dispatch(["--self-test-archive-modes"]) -> archive_modes_self_test();
dispatch(["--self-test-archive-metadata"]) -> archive_metadata_self_test();
dispatch(["--verify"]) -> verify_report();
dispatch(_) -> erlang:error(release_sim_usage).

run() ->
    Identity = evidence_begin(filename:join(?OUTPUT, "report.json")),
    Nonce = hex(crypto:strong_rand_bytes(16)),
    Directory = release_directory(Nonce),
    put(release_directory, Directory),
    put(release_identity, Identity),
    make_output(Directory),
    Base = #{schema => 2, status => <<"Running">>, shareable => true,
        version => ?VERSION, run_nonce => Nonce, archive_format => <<"Hex v3">>,
        dependency_mode => <<"exact archive registry">>, evidence_identity => Identity,
        execution_environment => execution_runtime(), artifacts => [],
        package_compilers => [], consumers => []},
    checkpoint(Base),
    Names = ["core", "http3", "http"],
    fresh_with_verified_builds(Names, fun(Snapshots) ->
        run_locked(Identity, Base, Directory, Snapshots)
    end).

run_locked(Identity, Base, Directory, Snapshots) ->
    Builds = release_snapshot_builds(Snapshots),
    Runner = compile_runner(Directory),
    Started = Base#{build_identity => Builds, runner_sha256 => runner_hashes(Runner),
        execution_environment => maps:get(<<"runtime">>, maps:get(<<"toolchain">>,
            maps:get(<<"http">>, Builds)))},
    checkpoint(Started),
    Packages = release_packages(),
    First = [build_archive(Package, "pass-a") || Package <- Packages],
    Second = [build_archive(Package, "pass-b") || Package <- Packages],
    Artifacts = compare_passes(First, Second),
    checkpoint(Started#{artifacts => Artifacts}),
    Registry = filename:join(output(), "registry"),
    lists:foreach(fun(Artifact) -> install_archive(Artifact, Registry) end,
                  Artifacts),
    DependencyProof = prepare_library(),
    checkpoint((get(release_report))#{dependency_library => DependencyProof}),
    lists:foreach(fun(Package) ->
        Row = compile_registered_package(Package, Runner),
        State = get(release_report),
        checkpoint((maps:remove(active_compiler, State))#{package_compilers => maps:get(package_compilers, State) ++ [Row]}),
        ensure(maps:get(status, Row) =:= <<"Passed">>, archive_compilation_failed)
    end, Packages),
    lists:foreach(fun(Package) ->
        Row = compile_and_run_consumer(Package, Runner),
        State = get(release_report),
        checkpoint((maps:remove(active_compiler, State))#{consumers => maps:get(consumers, State) ++ [Row]}),
        ensure(maps:get(status, Row) =:= <<"Passed">>, consumer_failed)
    end, Packages),
    SbomPath = write_sbom(Packages, Artifacts),
    Signature = ephemeral_signature(Artifacts),
    ProvenancePath = write_provenance(get(release_report)),
    Report = (get(release_report))#{status => <<"Ready">>,
               sbom => artifact_file(SbomPath),
               provenance => artifact_file(ProvenancePath),
               ephemeral_signature => Signature},
    checkpoint(Report#{status => <<"Running">>}),
    FinalSnapshots = [fresh_verify_locked(maps:get(target, Snapshot))
                      || Snapshot <- Snapshots],
    Builds = release_snapshot_builds(FinalSnapshots),
    true = [maps:get(sha256, Snapshot) || Snapshot <- Snapshots] =:=
        [maps:get(sha256, Snapshot) || Snapshot <- FinalSnapshots],
    Expected = release_expected(),
    ok = release_validate_report(json_map(Report), Identity, Builds, Expected),
    release_report_self_tests(json_map(Report), Identity, Builds, Expected),
    Complete = evidence_complete(Report, Identity),
    write_json(filename:join(?OUTPUT, "report.json"),
               Complete),
    io:format("release simulation: 3 reproducible archives and empty consumers "
              "passed on OTP ~s~n", [erlang:system_info(otp_release)]),
    ok.

build_archive(Package, Pass) ->
    Name = maps:get(name, Package),
    Directory = filename:join(output(), Pass),
    Path = filename:join(Directory, binary_to_list(Name) ++ "-0.1.0.tar"),
    ContentPath = filename:join(Directory,
                                binary_to_list(Name) ++ "-contents.tar.gz"),
    ok = filelib:ensure_dir(Path),
    Files = release_package_files(Package),
    %% OTP 28 ignores the mode option for binary members and emits 100644.
    %% Name the same regular-file mode explicitly on OTP 29 and later.
    TarOptions = [compressed, {mtime, 0}, {atime, 0}, {ctime, 0},
                  {uid, 0}, {gid, 0}, {mode, 8#100644}],
    ok = erl_tar:create(ContentPath, Files, TarOptions),
    Contents = read(ContentPath),
    ok = file:delete(ContentPath),
    Metadata = release_metadata(Package, Files),
    Version = <<"3">>,
    Checksum = hex(crypto:hash(sha256, [Version, Metadata, Contents])),
    Outer = [{"VERSION", Version}, {"metadata.config", Metadata},
             {"contents.tar.gz", Contents}, {"CHECKSUM", Checksum}],
    ok = erl_tar:create(Path, Outer,
                        [{mtime, 0}, {atime, 0}, {ctime, 0},
                         {uid, 0}, {gid, 0}, {mode, 8#100644}]),
    Audit = audit_archive(Path, Package),
    Audit#{path => list_to_binary(Path), pass => list_to_binary(Pass),
           name => Name}.

compare_passes(First, Second) ->
    lists:map(fun(Left) ->
        Name = maps:get(name, Left),
        Right = hd([Item || Item <- Second, maps:get(name, Item) =:= Name]),
        LeftDigest = maps:get(sha256, Left),
        RightDigest = maps:get(sha256, Right),
        ensure(LeftDigest =:= RightDigest,
               {non_reproducible_archive, Name, LeftDigest, RightDigest}),
        maps:without([pass], Right)
    end, First).

audit_archive(Path, Package) ->
    Bytes = read(Path),
    ensure(byte_size(Bytes) =< ?MAX_ARCHIVE_BYTES,
           {archive_too_large, Path, byte_size(Bytes)}),
    {ok, Outer} = erl_tar:extract({binary, Bytes},
                                  [memory, {max_size, ?MAX_ARCHIVE_BYTES}]),
    Names = lists:sort([Name || {Name, _} <- Outer]),
    ensure(Names =:= ["CHECKSUM", "VERSION", "contents.tar.gz",
                      "metadata.config"], {invalid_hex_outer, Path, Names}),
    Version = member("VERSION", Outer),
    ensure(Version =:= <<"3">>, invalid_hex_version),
    Metadata = member("metadata.config", Outer),
    Contents = member("contents.tar.gz", Outer),
    ExpectedFiles = release_package_files(Package),
    ensure(Metadata =:= release_metadata(Package, ExpectedFiles), archive_metadata_changed),
    Stored = member("CHECKSUM", Outer),
    ensure(Stored =:= hex(crypto:hash(sha256,
                                     [Version, Metadata, Contents])),
           {invalid_archive_checksum, Path}),
    ensure(binary:match(Metadata, maps:get(name, Package)) =/= nomatch,
           {metadata_name_missing, Path}),
    ensure(binary:match(Metadata, <<"== 0.1.0">>) =/= nomatch orelse
           maps:get(name, Package) =:= <<"quic_core">>,
           {exact_dependency_missing, maps:get(name, Package)}),
    {ok, Inner} = erl_tar:extract({binary, Contents},
                                  [compressed, memory,
                                   {max_size, ?MAX_ARCHIVE_BYTES}]),
    ensure(release_archive_metadata_valid(Bytes, Contents), noncanonical_archive_metadata),
    InnerNames = [Name || {Name, _} <- Inner],
    ensure(length(InnerNames) =:= length(lists:usort(InnerNames)),
           {duplicate_archive_member, Path}),
    lists:foreach(fun release_audit_member/1, Inner),
    ensure(lists:keysort(1, Inner) =:= ExpectedFiles, archive_source_inventory_changed),
    #{sha256 => hex(crypto:hash(sha256, Bytes)),
      bytes => byte_size(Bytes), files => length(Inner),
      source_inventory => release_inventory(ExpectedFiles)}.

install_archive(Artifact, Registry) ->
    Path = binary_to_list(maps:get(path, Artifact)),
    Name = binary_to_list(maps:get(name, Artifact)),
    {ok, Outer} = erl_tar:extract({binary, read(Path)}, [memory, {max_size, ?MAX_ARCHIVE_BYTES}]),
    Contents = member("contents.tar.gz", Outer),
    {ok, Inner} = erl_tar:extract({binary, Contents}, [compressed, memory, {max_size, ?MAX_ARCHIVE_BYTES}]),
    Destination = filename:join([Registry, Name, "0.1.0"]),
    lists:foreach(fun({Relative, Bytes}) ->
        release_audit_member({Relative, Bytes}),
        Target = filename:join(Destination, Relative),
        ok = filelib:ensure_dir(Target),
        ok = file:write_file(Target, Bytes)
    end, Inner).

prepare_library() ->
    Library = filename:join(output(), "lib"),
    ok = filelib:ensure_dir(filename:join(Library, "placeholder")),
    lists:map(fun(Name) ->
        Source = filename:join("build/dev/erlang", Name),
        Destination = filename:join(Library, Name),
        ensure(filelib:is_dir(Source), {missing_precompiled_dependency, Name}),
        Files = release_tree(Source),
        lists:foreach(fun(Relative) ->
            Bytes = examples_read(filename:join(Source, Relative), 16777216),
            Target = filename:join(Destination, Relative),
            ok = filelib:ensure_dir(Target),
            ok = file:write_file(Target, Bytes, [exclusive])
        end, Files),
        Original = release_tree_inventory(Source),
        Original = release_tree_inventory(Destination),
        #{name => list_to_binary(Name), files => Original}
    end, ["gleam_stdlib", "gleam_erlang", "gleam_http"]).

compile_registered_package(Package, Runner) ->
    Name = binary_to_list(maps:get(name, Package)),
    Source = filename:join([output(), "registry", Name, "0.1.0"]),
    Out = filename:join([output(), "lib", Name]),
    ok = filelib:ensure_dir(filename:join(Out, "placeholder")),
    compile_package(Source, Out, Runner, maps:get(name, Package), package).

compile_and_run_consumer(Package, Runner) ->
    Dependency = maps:get(name, Package),
    Name = <<"empty_", Dependency/binary, "_consumer">>,
    Directory = filename:join([output(), "consumers", binary_to_list(Name)]),
    SourceDirectory = filename:join(Directory, "src"),
    ok = filelib:ensure_dir(filename:join(SourceDirectory, "placeholder")),
    Manifest = release_consumer_manifest(Name, Dependency),
    Module = <<Name/binary, "_main">>,
    Source = release_consumer_source(Dependency),
    ok = file:write_file(filename:join(Directory, "gleam.toml"), Manifest),
    ok = file:write_file(filename:join(SourceDirectory,
                                       binary_to_list(Module) ++ ".gleam"),
                         Source),
    Out = filename:join(Directory, "out"),
    ok = filelib:ensure_dir(filename:join(Out, "placeholder")),
    Compiler = compile_package(Directory, Out, Runner, Name, consumer),
    Base = #{name => Name, dependency => Dependency, requirement => <<"== 0.1.0">>,
      compiler => Compiler, source_sha256 => hex(crypto:hash(sha256, Source)),
      manifest_sha256 => hex(crypto:hash(sha256, Manifest))},
    case maps:get(status, Compiler) of
        <<"Passed">> ->
            Execution = execute_consumer(Module, Out, Runner, 30000),
            Base#{execution => Execution, status => maps:get(status, Execution)};
        _ -> Base#{status => <<"Failed">>}
    end.

compile_package(Source, Out, Runner, Name, Kind) ->
    Compiler = run_command(["compile-package", "--target", "erlang",
        "--package", Source, "--out", Out,
        "--lib", filename:join(output(), "lib"), "--no-beam"], 120000),
    Base = #{name => Name, kind => atom_to_binary(Kind), compiler => Compiler},
    compiler_checkpoint(Base),
    case proof_passed(Compiler, compiler) of
        false -> Base#{status => <<"Failed">>};
        true ->
            Files = release_generated_files(Out),
            Supports = release_support_files(Out),
            Nonce = hex(crypto:strong_rand_bytes(16)),
            Path = filename:absname(filename:join(Out, "beam-compiler.json")),
            Ebin = filename:absname(filename:join(Out, "ebin")),
            ok = filelib:ensure_dir(filename:join(Ebin, "placeholder")),
            Evaluation = lists:flatten(io_lib:format(
                "release_child:compile_modules(~0tp,~0tp,~0tp,~0tp,~0tp).",
                [Files, Supports, Ebin, Path, Nonce])),
            {Status, Output} = run_child_evaluation(filename:absname("."),
                runtime_paths(Runner, Ebin), Evaluation, 120000),
            Child = release_safe_compile_child(read_json(Path), Nonce, Files),
            BeamCompiler = #{child_exit_status => Status, timeout_milliseconds => 120000,
                process => (safe_process(Output, beam))#{vm_process_heap_words => 134217728},
                child => Child, run_nonce => Nonce},
            compiler_checkpoint(Base#{beam_compiler => BeamCompiler, generated => Files,
                generated_support => Supports}),
            Passed = release_compiler_process_valid(json_map(BeamCompiler)) andalso
                release_compile_child_valid(Child, Nonce, Files),
            Base#{beam_compiler => BeamCompiler, generated => Files, generated_support => Supports,
                status => case Passed of true -> <<"Passed">>; false -> <<"Failed">> end}
    end.

execute_consumer(Module, Out, Runner, Timeout) ->
    Nonce = hex(crypto:strong_rand_bytes(16)),
    Path = filename:absname(filename:join(Out, "execution.json")),
    Ebin = filename:absname(filename:join(Out, "ebin")),
    Beam = filename:join(Ebin, binary_to_list(Module) ++ ".beam"),
    Before = examples_file_hash(Beam, 16777216),
    Evaluation = lists:flatten(io_lib:format("examples_child:run_example(~0tp,~0tp,~0tp,~B).",
        [Module, Path, Nonce, Timeout])),
    {Status, Output} = run_child_evaluation(filename:absname("."), runtime_paths(Runner, Ebin),
        Evaluation, Timeout + 5000),
    Child = suite_safe_child(read_json(Path), [examples_unit(Module)], Nonce),
    Proof = #{module => Module, run_nonce => Nonce, timeout_milliseconds => Timeout,
        child_exit_status => Status, process => safe_process(Output, beam), child => Child,
        completed_tests => suite_completed_tests(Child), beam_sha256 => Before},
    Passed = proof_passed(Proof, beam) andalso
        suite_child_valid(Child, [examples_unit(Module)], Nonce) andalso
        Before =:= examples_file_hash(Beam, 16777216),
    Proof#{status => case Passed of true -> <<"Passed">>; false -> <<"Failed">> end}.

write_sbom(_Packages, Artifacts) ->
    Path = filename:join(output(), "release-sim.cdx.json"),
    write_json(Path, release_sbom(json_map(Artifacts))),
    Path.

ephemeral_signature(Artifacts) ->
    Payload = iolist_to_binary([maps:get(sha256, Artifact)
                                || Artifact <- Artifacts]),
    {Public, Private} = crypto:generate_key(eddsa, ed25519),
    Signature = crypto:sign(eddsa, none, Payload, [Private, ed25519]),
    ensure(crypto:verify(eddsa, none, Payload, Signature, [Public, ed25519]),
           ephemeral_signature_verification_failed),
    #{algorithm => <<"Ed25519">>, verified => true,
      public_key => hex(Public), signature => hex(Signature),
      payload_sha256 => hex(crypto:hash(sha256, Payload))}.

write_provenance(Report) ->
    Path = filename:join(output(), "provenance.json"),
    write_json(Path, release_provenance(json_map(Report))),
    Path.

runtime_paths(Runner, Ebin) ->
    [Runner, Ebin | [filename:absname(P) ||
        P <- filelib:wildcard(filename:join([output(), "lib", "*", "ebin"]))]].

run_command(Arguments, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    Executable = case os:find_executable("gleam") of
        false -> erlang:error(gleam_not_found);
        Path -> Path
    end,
    {Port, Identity} = open_owned_process(Executable, Arguments,
        filename:absname("."), [], Deadline),
    {Status, Output} = collect_eunit(Port, new_output(Identity), Deadline),
    #{child_exit_status => Status, timeout_milliseconds => Timeout,
        process => safe_process(Output, compiler)}.

safe_process(Output, _Kind) -> maps:without([tail, output_sha256], Output).

proof_passed(Proof, Kind) ->
    try examples_process_valid(json_map(Proof), Kind) andalso
        (Kind =/= compiler orelse maps:get(output_bytes, maps:get(process, Proof)) =:= 0)
    catch _:_ -> false end.

member(Name, Members) ->
    case lists:keyfind(Name, 1, Members) of
        {Name, Bytes} -> Bytes;
        false -> erlang:error({missing_archive_member, Name})
    end.

write_json(Path, Value) ->
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Value), <<"\n">>]).

output() -> get(release_directory).

make_output(Directory) ->
    examples_real_path("build"),
    case file:make_dir(?OUTPUT) of ok -> ok; {error, eexist} -> ok end,
    examples_real_path(?OUTPUT),
    ok = file:make_dir(Directory).

checkpoint(Report) ->
    put(release_report, Report),
    write_json(filename:join(?OUTPUT, "report.json"), Report).

compiler_checkpoint(Compiler) ->
    case get(release_report) of
        undefined -> ok;
        State -> checkpoint(State#{active_compiler => Compiler})
    end.

preserve_failure(Failure) ->
    case get(release_report) of
        undefined -> ok;
        State -> write_json(filename:join(?OUTPUT, "report.json"),
            State#{status => <<"Failed">>, failure => Failure})
    end.

current_builds() ->
    Names = ["core", "http3", "http"],
    Snapshots = fresh_with_verified_builds(Names,
        fun(Verified) -> Verified end),
    release_snapshot_builds(Snapshots).

release_snapshot_builds(Snapshots) ->
    maps:from_list([{list_to_binary(maps:get(target, Snapshot)),
        maps:get(report, Snapshot)} || Snapshot <- Snapshots]).

compile_runner(Directory) ->
    Runner = filename:absname(filename:join(Directory, "runner")),
    ok = filelib:ensure_dir(filename:join(Runner, "placeholder")),
    lists:foreach(fun(Name) ->
        {ok, Module, Beam, []} = compile:noenv_file("scripts/" ++ Name ++ ".erl",
            [binary, return_errors, return_warnings, {i, "scripts"}]),
        ok = file:write_file(filename:join(Runner, atom_to_list(Module) ++ ".beam"), Beam, [exclusive])
    end, ["qualification_eunit_listener", "examples_child", "release_child"]),
    Runner.

runner_hashes(Runner) -> maps:from_list([{list_to_binary(Name),
    examples_file_hash(filename:join(Runner, Name ++ ".beam"), 4194304)} ||
        Name <- ["qualification_eunit_listener", "examples_child", "release_child"]]).

artifact_file(Path) -> #{path => release_path(Path),
    sha256 => examples_file_hash(Path, ?MAX_ARCHIVE_BYTES)}.

verify_report() ->
    Identity = evidence_identity(),
    ok = release_validate_report(read_json(filename:join(?OUTPUT, "report.json")),
        Identity, current_builds(), release_expected()),
    io:format("release simulation evidence verified~n", []).

read_json(Path) ->
    try evidence_json_decode(examples_read(Path, 16777216)) catch _:_ -> #{invalid => true} end.
json_map(Value) -> json:decode(iolist_to_binary(json:encode(Value))).

self_test() ->
    Directory = release_directory(hex(crypto:strong_rand_bytes(16))),
    put(release_directory, Directory),
    make_output(Directory),
    Runner = compile_runner(Directory),
    ok = filelib:ensure_dir(filename:join([Directory, "lib", "placeholder"])),
    Fixtures = [{"pass", "nil"}, {"stall", "receive never -> nil end"},
        {"private", "Secret = <<\"release-private-marker\">>,io:put_chars(standard_error,Secret),erlang:error({badmatch,{Secret,self(),make_ref()}})"},
        {"flood", "B=binary:copy(<<\"release-private-marker\">>,65536),lists:foreach(fun(_)->io:put_chars(standard_error,B)end,lists:seq(1,16)),nil"},
        {"non_nil", "ok"}],
    Executions = [release_fixture(Directory, Runner, Name, Body) || {Name, Body} <- Fixtures],
    [Pass, Stall, Private, Flood, NonNil] = Executions,
    ensure(maps:get(status, Pass) =:= <<"Passed">>, real_consumer_main_not_executed),
    ensure(lists:all(fun(E) -> maps:get(status, E) =:= <<"Failed">> end,
        [Stall, Private, Flood, NonNil]), hostile_consumer_not_rejected),
    ensure(maps:get(child_exit_status, Flood) =:= 125, consumer_output_limit_missing),
    ensure(lists:all(fun(E) -> maps:get(child_exit_observed, maps:get(process, E)) end,
        Executions), consumer_child_not_joined),
    Encoded = iolist_to_binary(json:encode(Executions)),
    ensure(lists:all(fun(Marker) -> binary:match(Encoded, Marker) =:= nomatch end,
        [<<"release-private-marker">>, <<"output_sha256">>, <<"tail">>]), private_consumer_evidence),
    Project = filename:join(Directory, "compiler-fixture"),
    ok = filelib:ensure_dir(filename:join(Project, "src/placeholder")),
    ok = file:write_file(filename:join(Project, "gleam.toml"),
        <<"name = \"release_compiler_fixture\"\nversion = \"0.0.0\"\ntarget = \"erlang\"\n">>),
    ok = file:write_file(filename:join(Project, "src/release_compiler_fixture.gleam"),
        <<"@external(erlang, \"release_fixture_ffi\", \"value\")\nfn value() -> Int\n"
          "pub fn main() -> Nil { assert value() == 7 }">>),
    ok = file:write_file(filename:join(Project, "src/release_fixture_ffi.erl"),
        <<"-module(release_fixture_ffi).\n-export([value/0]).\n"
          "-include(\"release_fixture_support.hrl\").\n"
          "-ifdef(UNTRUSTED_RELEASE_ENV).\nvalue()->8.\n-else.\nvalue()->?FIXTURE_VALUE.\n-endif.\n">>),
    ok = file:write_file(filename:join(Project, "src/release_fixture_support.hrl"),
        <<"-define(FIXTURE_VALUE, 7).\n">>),
    Compiler = with_compiler_environment(fun() ->
        compile_package(Project, filename:join(Project, "out"), Runner,
            <<"release_compiler_fixture">>, consumer)
    end),
    ensure(maps:get(status, Compiler) =:= <<"Passed">>, real_no_beam_compiler_failed),
    compiler_evidence_self_tests(Compiler, filename:join(Project, "out")),
    CompilerExecution = execute_consumer(<<"release_compiler_fixture">>, filename:join(Project, "out"), Runner, 1000),
    ensure(maps:get(status, CompilerExecution) =:= <<"Passed">>, compiled_header_value_not_observed),
    CompilerFailures = compiler_failure_self_tests(Directory, Runner),
    Packages = release_packages(),
    First = [build_archive(P, "pass-a") || P <- Packages],
    Second = [build_archive(P, "pass-b") || P <- Packages],
    Archives = compare_passes(First, Second),
    canonical_archive_modes(Archives),
    lists:foreach(fun(A) -> install_archive(A, filename:join(Directory, "registry")) end, Archives),
    Expected = release_expected(),
    lists:foreach(fun({A, E}) ->
        ok = release_archive_valid(json_map(A), E, Directory),
        Paths = [maps:get(path, F) || F <- maps:get(source_inventory, A)],
        ensure(lists:all(fun(P) -> lists:member(P, Paths) end,
            [<<"LICENSES/MIT.txt">>, <<"LICENSES/Apache-2.0.txt">>]), archive_license_text_missing)
    end, lists:zip(Archives, Expected)),
    archive_evidence_self_tests(lists:last(Archives), lists:last(Expected), Directory),
    archive_metadata_rejection_tests(lists:last(Archives), lists:last(Expected), Directory),
    Http = lists:last(Archives),
    ensure(lists:any(fun(F) -> maps:get(path, F) =:= <<"src/http_brotli_tables.hrl">> end,
        maps:get(source_inventory, Http)), archive_omitted_brotli_tables),
    ensure(lists:any(fun(F) -> maps:get(path, F) =:= <<"LICENSES/LicenseRef-Brotli-MIT.txt">> end,
        maps:get(source_inventory, Http)), archive_omitted_brotli_license),
    ensure(release_validate_report(#{}, #{}, #{}, []) =:= error,
        empty_release_evidence_accepted),
    write_json(filename:join(Directory, "self-test.json"), #{schema => 1, status => <<"Passed">>,
        executions => Executions, compiler => Compiler, compiler_execution => CompilerExecution,
        compiler_failures => CompilerFailures, reproducible_archives => Archives}),
    io:format("release self-test: real compiler, 5 owned consumer outcomes and 3 reproducible archives passed~n", []).

archive_modes_self_test() ->
    Directory = release_directory(hex(crypto:strong_rand_bytes(16))),
    put(release_directory, Directory),
    make_output(Directory),
    Archives = [build_archive(Package, "mode-control") || Package <- release_packages()],
    canonical_archive_modes(Archives),
    write_json(filename:join(Directory, "mode-control.json"), #{schema => 1,
        execution_environment => execution_runtime(), archives => Archives}),
    io:format("canonical archive mode controls passed for 3 packages~n").

canonical_archive_modes(Archives) ->
    lists:foreach(fun(Artifact) ->
        Bytes = read(binary_to_list(maps:get(path, Artifact))),
        {ok, Outer} = erl_tar:extract({binary, Bytes}, [memory]),
        Contents = member("contents.tar.gz", Outer),
        ensure(release_archive_metadata_valid(Bytes, Contents), noncanonical_archive_metadata)
    end, Archives).

with_compiler_environment(Action) ->
    Before = os:getenv("ERL_COMPILER_OPTIONS"),
    try
        true = os:putenv("ERL_COMPILER_OPTIONS", "[{d,'UNTRUSTED_RELEASE_ENV'}]"),
        Action()
    after
        case Before of false -> os:unsetenv("ERL_COMPILER_OPTIONS"); Value -> os:putenv("ERL_COMPILER_OPTIONS", Value) end
    end.

compiler_failure_self_tests(Directory, Runner) ->
    Huge = iolist_to_binary(["-compile(nowarn_unused_function).\nmain()->nil.\n" |
        [io_lib:format("f~B()->~B.~n", [N, N]) || N <- lists:seq(1, 12000)]]),
    Cases = [{"private-compiler", <<"main()-> <<\"release-private-marker\">>, ().\n">>,
        134217728, <<"compiler_errors">>},
        {"warning-compiler", <<"main()->nil.\nunused()->\"release-private-marker\".\n">>,
        134217728, <<"compiler_warnings">>},
        {"bounded-compiler", Huge, 1048576, <<"resource_limit">>}],
    [begin
        Out = filename:join(Directory, Label),
        Source = filename:join(Out, "_gleam_artefacts"),
        Ebin = filename:absname(filename:join(Out, "ebin")),
        ok = filelib:ensure_dir(filename:join(Source, "placeholder")),
        ok = filelib:ensure_dir(filename:join(Ebin, "placeholder")),
        ok = file:write_file(filename:join(Source, "release_a_pass.erl"),
            <<"-module(release_a_pass).\n-export([main/0]).\nmain()->nil.\n">>),
        ok = file:write_file(filename:join(Source, "release_z_bad.erl"),
            [<<"-module(release_z_bad).\n-export([main/0]).\n">>, Body]),
        Files = release_generated_files(Out), Nonce = hex(crypto:strong_rand_bytes(16)),
        Path = filename:absname(filename:join(Out, "beam-compiler.json")),
        Eval = lists:flatten(io_lib:format("release_child:compile_modules(~0tp,[],~0tp,~0tp,~0tp,~B).",
            [Files, Ebin, Path, Nonce, HeapWords])),
        {Exit, Output} = run_child_evaluation(filename:absname("."), runtime_paths(Runner, Ebin), Eval, 30000),
        Child = release_safe_compile_child(read_json(Path), Nonce, Files, HeapWords),
        ensure(Exit =:= 1 andalso maps:get(child_exit_observed, Output), compiler_failure_not_joined),
        ensure(maps:get(<<"classification">>, Child) =:= Classification, compiler_failure_cause_lost),
        ensure(maps:get(<<"phase">>, Child) =:= <<"compiler">> andalso
            maps:get(<<"failed_module">>, Child) =:= <<"release_z_bad">>, compiler_failure_stage_lost),
        ensure(length(maps:get(<<"modules">>, Child)) =:= 1, compiler_partial_progress_lost),
        ensure(binary:match(iolist_to_binary(json:encode(Child)), <<"release-private-marker">>) =:= nomatch,
            private_compiler_term_retained),
        Bad = Child#{<<"failed_module">> => <<"release-private-marker">>},
        ensure(release_safe_compile_child(Bad, Nonce, Files, HeapWords) =:= #{invalid => true},
            forged_compiler_failure_module_accepted),
        #{child => Child, process => (safe_process(Output, beam))#{vm_process_heap_words => HeapWords},
            child_exit_status => Exit}
    end || {Label, Body, HeapWords, Classification} <- Cases].

%% Exercise the aggregate against a real successful execution, not a synthetic
%% Ready-shaped map. Tampering with a document also updates its file digest,
%% proving that semantic joins are checked after the ordinary digest check.
release_report_self_tests(Report, Identity, Builds, Expected) ->
    Check = fun(R) -> release_validate_report(R, Identity, Builds, Expected) end,
    ok = Check(Report),
    lists:foreach(fun(Key) ->
        ensure(Check(maps:remove(Key, Report)) =:= error, incomplete_release_report_accepted)
    end, maps:keys(Report)),
    ensure(Check(Report#{<<"private_marker">> => true}) =:= error, unknown_release_field_accepted),
    Mutations = [
        {[<<"artifacts">>, 1], fun(M) -> M#{<<"source_inventory">> => []} end},
        {[<<"package_compilers">>, 1, <<"beam_compiler">>, <<"child">>],
            fun(M) -> M#{<<"compiler_workers_joined">> => false} end},
        {[<<"consumers">>, 1, <<"execution">>], fun(M) -> M#{<<"completed_tests">> => 0} end},
        {[<<"consumers">>, 1, <<"execution">>, <<"child">>], fun(M) -> M#{<<"schema">> => 0} end},
        {[<<"dependency_library">>, 1], fun(M) -> M#{<<"files">> => []} end},
        {[<<"runner_sha256">>], fun(M) -> M#{<<"release_child">> => binary:copy(<<"0">>, 64)} end},
        {[], fun(M) -> M#{<<"evidence_identity">> => #{}} end},
        {[], fun(M) -> M#{<<"status">> => <<"Running">>} end}],
    lists:foreach(fun({Path, Change}) ->
        ensure(Check(mutate_map(Report, Path, Change)) =:= error, forged_release_report_accepted)
    end, Mutations),
    DocumentMutations = [
        {<<"sbom">>, fun(M) -> mutate_map(M, [<<"components">>, 1],
            fun(C) -> maps:remove(<<"bom-ref">>, C) end) end},
        {<<"sbom">>, fun(M) -> mutate_map(M, [<<"dependencies">>, 1],
            fun(D) -> D#{<<"dependsOn">> => [<<"absent-component">>]} end) end},
        {<<"provenance">>, fun(M) -> maps:remove(<<"predicate">>, M) end},
        {<<"provenance">>, fun(M) -> mutate_map(M, [<<"predicate">>, <<"runDetails">>, <<"builder">>],
            fun(B) -> B#{<<"id">> => <<"https://unproven-builder.invalid">>} end) end}],
    lists:foreach(fun({Key, Change}) ->
        Proof = maps:get(Key, Report), Path = binary_to_list(maps:get(<<"path">>, Proof)),
        Original = read(Path),
        try
            Bytes = iolist_to_binary(json:encode(Change(evidence_json_decode(Original)))),
            ok = file:write_file(Path, Bytes),
            Forged = Report#{Key => Proof#{<<"sha256">> => hex(crypto:hash(sha256, Bytes))}},
            ensure(Check(Forged) =:= error, forged_supply_chain_document_accepted)
        after ok = file:write_file(Path, Original) end
    end, DocumentMutations),
    ok = Check(Report),
    write_json(filename:join(output(), "validator-self-test.json"), #{schema => 1,
        status => <<"Passed">>, run_nonce => maps:get(<<"run_nonce">>, Report),
        positive_real_execution => true, missing_fields => map_size(Report),
        aggregate_mutations => length(Mutations) + 1,
        rebound_document_mutations => length(DocumentMutations)}).

compiler_evidence_self_tests(Compiler0, Out) ->
    Compiler = json_map(Compiler0),
    Check = fun(C) -> release_package_compiler_valid(C, <<"release_compiler_fixture">>,
        <<"consumer">>, Out, [<<"release_compiler_fixture">>, <<"release_fixture_ffi">>]) end,
    ok = Check(Compiler),
    Paths = [[], [<<"compiler">>], [<<"compiler">>, <<"process">>],
        [<<"beam_compiler">>], [<<"beam_compiler">>, <<"process">>],
        [<<"beam_compiler">>, <<"child">>]],
    lists:foreach(fun(Path) ->
        Bad = mutate_map(Compiler, Path, fun(M) -> M#{<<"private_marker">> => <<"release-private-marker">>} end),
        ensure(rejected(fun() -> Check(Bad) end), unknown_compiler_field_accepted)
    end, Paths),
    Mutations = [
        {[<<"compiler">>, <<"process">>], fun(M) -> M#{<<"output_bytes">> => 1} end},
        {[<<"compiler">>], fun(M) -> M#{<<"timeout_milliseconds">> => 0} end},
        {[<<"beam_compiler">>, <<"process">>], fun(M) -> M#{<<"child_exit_observed">> => false} end},
        {[<<"beam_compiler">>], fun(M) -> M#{<<"run_nonce">> => <<"00000000000000000000000000000000">>} end},
        {[<<"beam_compiler">>, <<"child">>], fun(M) -> M#{<<"modules">> => []} end},
        {[<<"beam_compiler">>, <<"child">>], fun(M) -> M#{<<"compiler_workers_joined">> => false} end},
        {[<<"beam_compiler">>, <<"child">>], fun(M) -> M#{<<"compiler_worker_heap_words">> => 0} end},
        {[<<"beam_compiler">>, <<"process">>], fun(M) -> M#{<<"vm_process_heap_words">> => 33554432} end},
        {[], fun(M) -> M#{<<"generated">> => []} end}],
    lists:foreach(fun({Path, Change}) ->
        ensure(rejected(fun() -> Check(mutate_map(Compiler, Path, Change)) end),
            forged_compiler_evidence_accepted)
    end, Mutations),
    Beam = filename:join([Out, "ebin", "release_compiler_fixture.beam"]),
    rewrite_rejected(Beam, <<"replaced-beam">>, fun() -> Check(Compiler) end),
    rewrite_rejected(filename:join([Out, "_gleam_artefacts", "release_fixture_support.hrl"]),
        <<"-define(FIXTURE_VALUE, 8).\n">>, fun() -> Check(Compiler) end),
    rewrite_rejected(filename:join(Out, "beam-compiler.json"), <<"{}">>, fun() -> Check(Compiler) end),
    Extra = filename:join([Out, "ebin", "unclaimed.beam"]),
    ok = file:write_file(Extra, <<"unclaimed">>, [exclusive]),
    try ensure(rejected(fun() -> Check(Compiler) end), unclaimed_beam_accepted)
    after ok = file:delete(Extra) end.

archive_evidence_self_tests(Artifact0, Expected, Directory) ->
    Artifact = json_map(Artifact0),
    Check = fun(A) -> release_archive_valid(A, Expected, Directory) end,
    lists:foreach(fun(Key) ->
        ensure(rejected(fun() -> Check(maps:remove(Key, Artifact)) end),
            missing_archive_field_accepted)
    end, maps:keys(Artifact)),
    ensure(rejected(fun() -> Check(Artifact#{<<"private_marker">> => true}) end),
        unknown_archive_field_accepted),
    Path = binary_to_list(maps:get(<<"path">>, Artifact)),
    rewrite_rejected(Path, <<"truncated-archive">>, fun() -> Check(Artifact) end),
    Registry = filename:join([Directory, "registry", "http", "0.1.0", "src", "http_brotli_tables.hrl"]),
    rewrite_rejected(Registry, <<"missing table content">>, fun() -> Check(Artifact) end),
    BadPaths = ["../escape", "/absolute", "test/fixture.gleam", "src/secret.pem"],
    lists:foreach(fun(P) -> ensure(rejected(fun() -> release_audit_member({P, <<>>}) end),
        forbidden_archive_path_accepted) end, BadPaths),
    ensure(rejected(fun() -> release_audit_member({"src/key.erl", <<"-----BEGIN PRIVATE KEY-----">>}) end),
        private_archive_material_accepted),
    BadJson = <<"{\"status\":\"Ready\",\"sta\\u0074us\":\"Failed\"}">>,
    ensure(rejected(fun() -> evidence_json_decode(BadJson) end), duplicate_evidence_key_accepted).

mutate_map(Map, [], Change) -> Change(Map);
mutate_map(List, [Index | Rest], Change) when is_list(List), is_integer(Index), Index > 0 ->
    [case N =:= Index of true -> mutate_map(Value, Rest, Change); false -> Value end ||
        {N, Value} <- lists:zip(lists:seq(1, length(List)), List)];
mutate_map(Map, [Key | Rest], Change) -> Map#{Key => mutate_map(maps:get(Key, Map), Rest, Change)}.
rejected(Action) -> try Action(), false catch _:_ -> true end.
rewrite_rejected(Path, Bytes, Check) ->
    Original = read(Path),
    try
        ok = file:write_file(Path, Bytes),
        ensure(rejected(Check), replaced_retained_artifact_accepted)
    after ok = file:write_file(Path, Original) end.

release_fixture(Directory, Runner, Name, Body) ->
    Module = list_to_binary("release_fixture_" ++ Name),
    Out = filename:join([Directory, "fixtures", Name]),
    Ebin = filename:join(Out, "ebin"),
    ok = filelib:ensure_dir(filename:join(Ebin, "placeholder")),
    Source = filename:join(Out, binary_to_list(Module) ++ ".erl"),
    ok = file:write_file(Source, ["-module(", Module,").\n-export([main/0]).\nmain()->", Body, ".\n"]),
    {ok, Atom, Beam, []} = compile:noenv_file(Source, [binary, return_errors, return_warnings]),
    true = Atom =:= binary_to_atom(Module),
    ok = file:write_file(filename:join(Ebin, binary_to_list(Module) ++ ".beam"), Beam, [exclusive]),
    execute_consumer(Module, Out, Runner, case Name of "flood" -> 5000; _ -> 200 end).

read(Path) -> examples_read(Path, ?MAX_ARCHIVE_BYTES).

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
