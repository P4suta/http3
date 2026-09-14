#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(OUTPUT, "build/release-sim").
-define(VERSION, <<"0.1.0">>).
-define(MAX_ARCHIVE_BYTES, 128 * 1024 * 1024).

main([]) ->
    try run() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "release simulation failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end;
main(_) -> erlang:error(release_sim_usage).

run() ->
    reset_output(),
    Packages = packages(),
    First = [build_archive(Package, "pass-a") || Package <- Packages],
    Second = [build_archive(Package, "pass-b") || Package <- Packages],
    Artifacts = compare_passes(First, Second),
    Registry = filename:join(?OUTPUT, "registry"),
    lists:foreach(fun(Artifact) -> install_archive(Artifact, Registry) end,
                  Artifacts),
    prepare_library(),
    lists:foreach(fun compile_registered_package/1, Packages),
    Consumers = [compile_and_run_consumer(Package) || Package <- Packages],
    SbomPath = write_sbom(Packages, Artifacts),
    Signature = ephemeral_signature(Artifacts),
    ProvenancePath = write_provenance(Artifacts, Consumers, Signature),
    Report = #{status => <<"Ready">>, version => ?VERSION,
               otp => list_to_binary(erlang:system_info(otp_release)),
               archive_format => <<"Hex v3">>,
               dependency_mode => <<"exact archive registry">>,
               artifacts => Artifacts, consumers => Consumers,
               sbom => list_to_binary(SbomPath),
               provenance => list_to_binary(ProvenancePath),
               ephemeral_signature => Signature},
    write_json(filename:join(?OUTPUT, "report.json"), Report),
    io:format("release simulation: 3 reproducible archives and empty consumers "
              "passed on OTP ~s~n", [erlang:system_info(otp_release)]),
    ok.

packages() ->
    [
        #{name => <<"quic_core">>, root => "packages/quic_core",
          dependencies => [
              {<<"gleam_erlang">>, <<">= 1.3.0 and < 2.0.0">>},
              {<<"gleam_stdlib">>, <<">= 1.0.0 and < 2.0.0">>}
          ]},
        #{name => <<"http3">>, root => "packages/http3",
          dependencies => [
              {<<"gleam_erlang">>, <<">= 1.3.0 and < 2.0.0">>},
              {<<"gleam_http">>, <<">= 4.3.0 and < 5.0.0">>},
              {<<"quic_core">>, <<"== 0.1.0">>},
              {<<"gleam_stdlib">>, <<">= 1.0.0 and < 2.0.0">>}
          ]},
        #{name => <<"http">>, root => ".",
          dependencies => [
              {<<"gleam_erlang">>, <<">= 1.3.0 and < 2.0.0">>},
              {<<"gleam_http">>, <<">= 4.3.0 and < 5.0.0">>},
              {<<"gleam_stdlib">>, <<">= 1.0.0 and < 2.0.0">>},
              {<<"http3">>, <<"== 0.1.0">>}
          ]}
    ].

build_archive(Package, Pass) ->
    Name = maps:get(name, Package),
    Directory = filename:join(?OUTPUT, Pass),
    Path = filename:join(Directory, binary_to_list(Name) ++ "-0.1.0.tar"),
    ContentPath = filename:join(Directory,
                                binary_to_list(Name) ++ "-contents.tar.gz"),
    ok = filelib:ensure_dir(Path),
    Files = package_files(Package),
    TarOptions = [compressed, {mtime, 0}, {atime, 0}, {ctime, 0},
                  {uid, 0}, {gid, 0}, {mode, 8#600}],
    ok = erl_tar:create(ContentPath, Files, TarOptions),
    Contents = read(ContentPath),
    ok = file:delete(ContentPath),
    Metadata = metadata(Package, Files),
    Version = <<"3">>,
    Checksum = hex(crypto:hash(sha256, [Version, Metadata, Contents])),
    Outer = [{"VERSION", Version}, {"metadata.config", Metadata},
             {"contents.tar.gz", Contents}, {"CHECKSUM", Checksum}],
    ok = erl_tar:create(Path, Outer,
                        [{mtime, 0}, {atime, 0}, {ctime, 0},
                         {uid, 0}, {gid, 0}, {mode, 8#600}]),
    Audit = audit_archive(Path, Package),
    Audit#{path => list_to_binary(Path), pass => list_to_binary(Pass),
           name => Name}.

package_files(Package) ->
    Root = maps:get(root, Package),
    Manifest = exact_manifest(Package),
    Static = [{"LICENSE", read(filename:join(Root, "LICENSE"))},
              {"README.md", read(filename:join(Root, "README.md"))},
              {"gleam.toml", Manifest}],
    SourcePaths = lists:sort(filelib:fold_files(
        filename:join(Root, "src"), ".*\\.(gleam|erl)$", true,
        fun(Path, Acc) -> [Path | Acc] end, [])),
    Source = [{relative_to(Root, Path), read(Path)} || Path <- SourcePaths],
    Files = lists:keysort(1, Static ++ Source),
    ensure(length(Files) =:= length(lists:ukeysort(1, Files)),
           {duplicate_archive_path, maps:get(name, Package)}),
    lists:foreach(fun audit_member/1, Files),
    Files.

exact_manifest(Package) ->
    Root = maps:get(root, Package),
    Original = read(filename:join(Root, "gleam.toml")),
    Name = maps:get(name, Package),
    Updated = case Name of
        <<"http3">> -> binary:replace(
            Original, <<"quic_core = { path = \"../quic_core\" }">>,
            <<"quic_core = \"== 0.1.0\"">>);
        <<"http">> -> binary:replace(
            Original, <<"http3 = { path = \"packages/http3\" }">>,
            <<"http3 = \"== 0.1.0\"">>);
        <<"quic_core">> -> Original
    end,
    ensure(binary:match(Updated, <<" = { path = ">>) =:= nomatch,
           {path_dependency_in_release_manifest, Name}),
    ensure(binary:match(Updated, <<"version = \"0.1.0\"">>) =/= nomatch,
           {unexpected_release_version, Name}),
    Updated.

metadata(Package, Files) ->
    Name = maps:get(name, Package),
    Description = toml_string(<<"description">>, exact_manifest(Package)),
    Requirements = [{Dependency,
                     [{<<"app">>, Dependency}, {<<"optional">>, false},
                      {<<"requirement">>, Requirement}]}
                    || {Dependency, Requirement} <-
                       maps:get(dependencies, Package)],
    Terms = [
        {<<"name">>, Name}, {<<"app">>, Name}, {<<"version">>, ?VERSION},
        {<<"description">>, Description},
        {<<"licenses">>, [<<"MIT">>, <<"Apache-2.0">>]},
        {<<"build_tools">>, [<<"gleam">>]}, {<<"links">>, []},
        {<<"requirements">>, Requirements},
        {<<"files">>, [unicode:characters_to_binary(Path)
                        || {Path, _} <- Files]}
    ],
    iolist_to_binary([io_lib:format("~0tp.~n", [Term]) || Term <- Terms]).

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
    Metadata = member("metadata.config", Outer),
    Contents = member("contents.tar.gz", Outer),
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
    InnerNames = [Name || {Name, _} <- Inner],
    ensure(length(InnerNames) =:= length(lists:usort(InnerNames)),
           {duplicate_archive_member, Path}),
    lists:foreach(fun audit_member/1, Inner),
    #{sha256 => hex(crypto:hash(sha256, Bytes)),
      bytes => byte_size(Bytes), files => length(Inner)}.

audit_member({Name, Contents}) ->
    Parts = filename:split(Name),
    Lower = string:lowercase(Name),
    Extension = string:lowercase(filename:extension(Name)),
    ensure(filename:pathtype(Name) =:= relative andalso
           not lists:member("..", Parts), {unsafe_archive_path, Name}),
    ensure(not lists:any(fun(Part) ->
        lists:member(string:lowercase(Part),
                     ["test", "tests", "build", "_build", ".git"])
    end, Parts), {unwanted_archive_path, Name}),
    ensure(string:find(Lower, "interop") =:= nomatch,
           {interop_in_archive, Name}),
    ensure(not lists:member(Extension, [".pem", ".key", ".p12", ".pfx"]),
           {credential_in_archive, Name}),
    Markers = [<<"-----BEGIN PRIVATE KEY-----">>,
               <<"-----BEGIN RSA PRIVATE KEY-----">>,
               <<"-----BEGIN EC PRIVATE KEY-----">>,
               <<"-----BEGIN OPENSSH PRIVATE KEY-----">>],
    ensure(not lists:any(fun(Marker) ->
        binary:match(Contents, Marker) =/= nomatch
    end, Markers), {private_key_material_in_archive, Name}).

install_archive(Artifact, Registry) ->
    Path = binary_to_list(maps:get(path, Artifact)),
    Name = binary_to_list(maps:get(name, Artifact)),
    {ok, Outer} = erl_tar:extract(Path, [memory]),
    Contents = member("contents.tar.gz", Outer),
    {ok, Inner} = erl_tar:extract({binary, Contents}, [compressed, memory]),
    Destination = filename:join([Registry, Name, "0.1.0"]),
    lists:foreach(fun({Relative, Bytes}) ->
        audit_member({Relative, Bytes}),
        Target = filename:join(Destination, Relative),
        ok = filelib:ensure_dir(Target),
        ok = file:write_file(Target, Bytes)
    end, Inner).

prepare_library() ->
    Library = filename:join(?OUTPUT, "lib"),
    ok = filelib:ensure_dir(filename:join(Library, "placeholder")),
    lists:foreach(fun(Name) ->
        Source = filename:join("build/dev/erlang", Name),
        Destination = filename:join(Library, Name),
        ensure(filelib:is_dir(Source), {missing_precompiled_dependency, Name}),
        copy_tree(Source, Destination)
    end, ["gleam_stdlib", "gleam_erlang", "gleam_http"]).

compile_registered_package(Package) ->
    Name = binary_to_list(maps:get(name, Package)),
    Source = filename:join([?OUTPUT, "registry", Name, "0.1.0"]),
    Out = filename:join([?OUTPUT, "lib", Name]),
    ok = filelib:ensure_dir(filename:join(Out, "placeholder")),
    Output = run_command(["compile-package", "--target", "erlang",
                          "--package", Source, "--out", Out,
                          "--lib", filename:join(?OUTPUT, "lib")]),
    ensure(binary:match(Output, <<"warning:">>) =:= nomatch,
           {archive_compile_warning, Name, Output}).

compile_and_run_consumer(Package) ->
    Dependency = maps:get(name, Package),
    Name = <<"empty_", Dependency/binary, "_consumer">>,
    Directory = filename:join([?OUTPUT, "consumers", binary_to_list(Name)]),
    SourceDirectory = filename:join(Directory, "src"),
    ok = filelib:ensure_dir(filename:join(SourceDirectory, "placeholder")),
    Manifest = consumer_manifest(Name, Dependency),
    Module = <<Name/binary, "_main">>,
    Source = consumer_source(Dependency),
    ok = file:write_file(filename:join(Directory, "gleam.toml"), Manifest),
    ok = file:write_file(filename:join(SourceDirectory,
                                       binary_to_list(Module) ++ ".gleam"),
                         Source),
    Out = filename:join(Directory, "out"),
    ok = filelib:ensure_dir(filename:join(Out, "placeholder")),
    Output = run_command(["compile-package", "--target", "erlang",
                          "--package", Directory, "--out", Out,
                          "--lib", filename:join(?OUTPUT, "lib")]),
    ensure(binary:match(Output, <<"warning:">>) =:= nomatch,
           {consumer_compile_warning, Name, Output}),
    add_runtime_paths(Out),
    Beam = filename:join([Out, "ebin", binary_to_list(Module) ++ ".beam"]),
    {module, Loaded} = code:load_abs(filename:rootname(filename:absname(Beam),
                                                       ".beam")),
    ensure(Loaded =:= binary_to_atom(Module), {wrong_consumer_module, Loaded}),
    ensure(apply(Loaded, main, []) =:= nil, {consumer_failed, Name}),
    #{name => Name, dependency => Dependency, requirement => <<"== 0.1.0">>,
      compiled_from_archive => true, executed => true}.

consumer_manifest(Name, Dependency) ->
    <<"name = \"", Name/binary, "\"\nversion = \"0.0.0\"\n",
      "target = \"erlang\"\n\n[dependencies]\n",
      Dependency/binary, " = \"== 0.1.0\"\n">>.

consumer_source(<<"quic_core">>) ->
    <<"import quic_core/config\nimport quic_core/failure\n\n",
      "pub fn main() -> Nil {\n",
      "  assert config.limit(config.default_limits(), failure.Queue) > 0\n}">>;
consumer_source(<<"http3">>) ->
    <<"import http3/client\n\npub fn main() -> Nil {\n",
      "  let _configuration = client.new()\n  Nil\n}">>;
consumer_source(<<"http">>) ->
    <<"import http/body\n\npub fn main() -> Nil {\n",
      "  assert body.is_replayable(body.empty())\n}">>.

write_sbom(Packages, Artifacts) ->
    Components = [#{type => <<"library">>, name => maps:get(name, Package),
                    version => ?VERSION,
                    hashes => [#{alg => <<"SHA-256">>,
                                 content => maps:get(sha256,
                                   hd([A || A <- Artifacts,
                                            maps:get(name, A) =:=
                                            maps:get(name, Package)]))}]}
                  || Package <- Packages],
    Dependencies = [#{ref => maps:get(name, Package), dependsOn =>
                      [Name || {Name, _} <- maps:get(dependencies, Package),
                               lists:member(Name,
                                  [<<"http3">>, <<"quic_core">>])]}
                    || Package <- Packages],
    Sbom = #{bomFormat => <<"CycloneDX">>, specVersion => <<"1.6">>,
             version => 1, components => Components,
             dependencies => Dependencies},
    Path = filename:join(?OUTPUT, "release-sim.cdx.json"),
    write_json(Path, Sbom),
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

write_provenance(Artifacts, Consumers, Signature) ->
    Path = filename:join(?OUTPUT, "provenance.json"),
    Provenance = #{predicateType =>
                       <<"https://slsa.dev/provenance/v1">>,
                   builder => #{id => <<"local-release-sim">>},
                   buildType => <<"unpublished-three-package-simulation">>,
                   source_sha256 => source_digest(),
                   subjects => [#{name => maps:get(name, Artifact),
                                   digest => #{sha256 =>
                                      maps:get(sha256, Artifact)}}
                                || Artifact <- Artifacts],
                   consumers => Consumers,
                   ephemeral_signature => Signature,
                   external_audit_attestation => false,
                   signed_commit => false},
    write_json(Path, Provenance),
    Path.

source_digest() ->
    Paths = lists:sort(lists:append([
        filelib:fold_files(filename:join(maps:get(root, Package), "src"),
                           ".*\\.(gleam|erl)$", true,
                           fun(Path, Acc) -> [Path | Acc] end, [])
        || Package <- packages()
    ])),
    hex(crypto:hash(sha256,
                    [[unicode:characters_to_binary(Path), 0, read(Path)]
                     || Path <- Paths])).

add_runtime_paths(ConsumerOut) ->
    Paths = [filename:join(ConsumerOut, "ebin") |
             filelib:wildcard(filename:join([?OUTPUT, "lib", "*", "ebin"]))],
    lists:foreach(fun(Path) -> true = code:add_patha(filename:absname(Path)) end,
                  Paths).

run_command(Arguments) ->
    Executable = case os:find_executable("gleam") of
        false -> erlang:error(gleam_not_found);
        Path -> Path
    end,
    Port = open_port({spawn_executable, Executable},
                     [binary, exit_status, use_stdio, stderr_to_stdout,
                      {args, Arguments}, {cd, filename:absname(".")}]),
    collect_command(Port, Arguments, []).

collect_command(Port, Arguments, Output) ->
    receive
        {Port, {data, Bytes}} -> collect_command(Port, Arguments,
                                                 [Bytes | Output]);
        {Port, {exit_status, 0}} ->
            iolist_to_binary(lists:reverse(Output));
        {Port, {exit_status, Status}} ->
            erlang:error({command_failed, Arguments, Status,
                          iolist_to_binary(lists:reverse(Output))})
    after 180000 ->
        port_close(Port),
        erlang:error({command_timeout, Arguments})
    end.

copy_tree(Source, Destination) ->
    ok = filelib:ensure_dir(filename:join(Destination, "placeholder")),
    {ok, Entries} = file:list_dir(Source),
    lists:foreach(fun(Entry) ->
        From = filename:join(Source, Entry),
        To = filename:join(Destination, Entry),
        case filelib:is_dir(From) of
            true -> copy_tree(From, To);
            false ->
                ok = filelib:ensure_dir(To),
                {ok, _} = file:copy(From, To)
        end
    end, Entries).

relative_to(".", Path) -> Path;
relative_to(Root, Path) ->
    RootParts = filename:split(filename:absname(Root)),
    PathParts = filename:split(filename:absname(Path)),
    filename:join(drop_prefix(RootParts, PathParts)).

drop_prefix([Part | Root], [Part | Path]) -> drop_prefix(Root, Path);
drop_prefix([], Path) -> Path;
drop_prefix(_, Path) -> Path.

toml_string(Key, Contents) ->
    Pattern = <<"(?m)^", Key/binary, "\\s*=\\s*\"([^\"]+)\"\\s*$">>,
    case re:run(Contents, Pattern, [{capture, [1], binary}]) of
        {match, [Value]} -> Value;
        nomatch -> erlang:error({missing_toml_value, Key})
    end.

member(Name, Members) ->
    case lists:keyfind(Name, 1, Members) of
        {Name, Bytes} -> Bytes;
        false -> erlang:error({missing_archive_member, Name})
    end.

write_json(Path, Value) ->
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Value), <<"\n">>]).

reset_output() ->
    Expected = filename:join(filename:absname("build"), "release-sim"),
    case filename:absname(?OUTPUT) of
        Expected ->
            _ = file:del_dir_r(Expected),
            ok = filelib:ensure_dir(filename:join(Expected, "placeholder"));
        Unsafe -> erlang:error({unsafe_release_output, Unsafe})
    end.

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
