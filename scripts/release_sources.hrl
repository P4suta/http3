%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_RELEASE_SOURCES).
-define(HTTP_RELEASE_SOURCES, true).

release_packages() ->
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


release_package_files(Package) ->
    Root = maps:get(root, Package),
    Manifest = release_exact_manifest(Package),
    Static = [{"LICENSE", release_source_read(filename:join(Root, "LICENSE"))},
              {"README.md", release_source_read(filename:join(Root, "README.md"))},
              {"gleam.toml", Manifest}],
    LicenseRoot = filename:join(Root, "LICENSES"),
    LicensePaths = release_tree(LicenseRoot),
    release_source_ensure(length(LicensePaths) =< 64, too_many_archive_licenses),
    release_source_ensure(lists:all(fun(Path) -> lists:member(Path, LicensePaths) end,
        ["MIT.txt", "Apache-2.0.txt"]), archive_license_text_missing),
    Licenses = [{"LICENSES/" ++ Path, examples_read(filename:join(LicenseRoot, Path), 1048576)} ||
        Path <- LicensePaths],
    SourceRoot = filename:join(Root, "src"),
    SourcePaths = [filename:join(SourceRoot, Path) || Path <- release_tree(SourceRoot),
        lists:member(filename:extension(Path), [".gleam", ".erl", ".hrl"])],
    release_source_ensure(length(SourcePaths) =< 1024, too_many_archive_sources),
    Source = [{release_relative_to(Root, Path), release_source_read(Path)} || Path <- SourcePaths],
    Files = lists:keysort(1, Static ++ Licenses ++ Source),
    release_source_ensure(lists:sum([byte_size(B) || {_, B} <- Files]) =< 134217728,
           archive_sources_too_large),
    release_source_ensure(length(Files) =:= length(lists:ukeysort(1, Files)),
           {duplicate_archive_path, maps:get(name, Package)}),
    lists:foreach(fun release_audit_member/1, Files),
    Files.

release_exact_manifest(Package) ->
    Root = maps:get(root, Package),
    Original = release_source_read(filename:join(Root, "gleam.toml")),
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
    release_source_ensure(binary:match(Updated, <<" = { path = ">>) =:= nomatch,
           {path_dependency_in_release_manifest, Name}),
    release_source_ensure(binary:match(Updated, <<"version = \"0.1.0\"">>) =/= nomatch,
           {unexpected_release_version, Name}),
    Updated.

release_metadata(Package, Files) ->
    Name = maps:get(name, Package),
    Description = release_toml_string(<<"description">>, release_exact_manifest(Package)),
    Requirements = [{Dependency,
                     [{<<"app">>, Dependency}, {<<"optional">>, false},
                      {<<"requirement">>, Requirement}]}
                    || {Dependency, Requirement} <-
                       maps:get(dependencies, Package)],
    Terms = [
        {<<"name">>, Name}, {<<"app">>, Name}, {<<"version">>, <<"0.1.0">>},
        {<<"description">>, Description},
        {<<"licenses">>, [<<"MIT">>, <<"Apache-2.0">>]},
        {<<"build_tools">>, [<<"gleam">>]}, {<<"links">>, []},
        {<<"requirements">>, Requirements},
        {<<"files">>, [unicode:characters_to_binary(Path)
                        || {Path, _} <- Files]}
    ],
    iolist_to_binary([io_lib:format("~0tp.~n", [Term]) || Term <- Terms]).


release_audit_member({Name, Contents}) ->
    Parts = filename:split(Name),
    Lower = string:lowercase(Name),
    Extension = string:lowercase(filename:extension(Name)),
    release_source_ensure(filename:pathtype(Name) =:= relative andalso
           Name =:= examples_normalise(Name) andalso
           not lists:member("..", Parts) andalso not lists:member(".", Parts),
           {unsafe_archive_path, Name}),
    release_source_ensure(not lists:any(fun(Part) ->
        lists:member(string:lowercase(Part),
                     ["test", "tests", "build", "_build", ".git"])
    end, Parts), {unwanted_archive_path, Name}),
    release_source_ensure(string:find(Lower, "interop") =:= nomatch,
           {interop_in_archive, Name}),
    release_source_ensure(not lists:member(Extension, [".pem", ".key", ".p12", ".pfx"]),
           {credential_in_archive, Name}),
    Markers = [<<"-----BEGIN PRIVATE KEY-----">>,
               <<"-----BEGIN RSA PRIVATE KEY-----">>,
               <<"-----BEGIN EC PRIVATE KEY-----">>,
               <<"-----BEGIN OPENSSH PRIVATE KEY-----">>],
    release_source_ensure(not lists:any(fun(Marker) ->
        binary:match(Contents, Marker) =/= nomatch
    end, Markers), {private_key_material_in_archive, Name}).


release_consumer_manifest(Name, Dependency) ->
    <<"name = \"", Name/binary, "\"\nversion = \"0.0.0\"\n",
      "target = \"erlang\"\n\n[dependencies]\n",
      Dependency/binary, " = \"== 0.1.0\"\n">>.

release_consumer_source(<<"quic_core">>) ->
    <<"import quic_core/config\nimport quic_core/failure\n\n",
      "pub fn main() -> Nil {\n",
      "  assert config.limit(config.default_limits(), failure.Queue) > 0\n}">>;
release_consumer_source(<<"http3">>) ->
    <<"import http3/client\n\npub fn main() -> Nil {\n",
      "  let _configuration = client.new()\n  Nil\n}">>;
release_consumer_source(<<"http">>) ->
    <<"import http/body\n\npub fn main() -> Nil {\n",
      "  assert body.is_replayable(body.empty())\n}">>.


release_relative_to(".", Path) ->
    case examples_normalise(Path) of "./" ++ Rest -> Rest; Normal -> Normal end;
release_relative_to(Root, Path) ->
    RootParts = filename:split(filename:absname(Root)),
    PathParts = filename:split(filename:absname(Path)),
    filename:join(release_drop_prefix(RootParts, PathParts)).

release_drop_prefix([Part | Root], [Part | Path]) -> release_drop_prefix(Root, Path);
release_drop_prefix([], Path) -> Path;
release_drop_prefix(_, Path) -> Path.

release_toml_string(Key, Contents) ->
    Pattern = <<"(?m)^", Key/binary, "\\s*=\\s*\"([^\"]+)\"\\s*$">>,
    case re:run(Contents, Pattern, [{capture, [1], binary}]) of
        {match, [Value]} -> Value;
        nomatch -> erlang:error({missing_toml_value, Key})
    end.


release_expected() -> [#{name => maps:get(name, P), modules => release_expected_modules(release_package_files(P)),
    files => release_inventory(release_package_files(P)), manifest => release_exact_manifest(P),
    metadata => release_metadata(P, release_package_files(P)),
    consumer_source => release_consumer_source(maps:get(name, P)),
    consumer_manifest => release_consumer_manifest(<<"empty_", (maps:get(name, P))/binary, "_consumer">>,
        maps:get(name, P))} || P <- release_packages()].

release_expected_modules(Files) ->
    lists:sort([case filename:extension(Path) of
        ".gleam" ->
            "src/" ++ ModulePath = examples_normalise(filename:rootname(Path, ".gleam")),
            binary:replace(unicode:characters_to_binary(ModulePath), <<"/">>, <<"@">>, [global]);
        ".erl" ->
            {match, [Module]} = re:run(Bytes, <<"(?m)^-module\\(([a-z][a-zA-Z0-9_@]*)\\)\\.">>,
                [{capture, [1], binary}]), Module
    end || {Path, Bytes} <- Files, lists:member(filename:extension(Path), [".gleam", ".erl"])]).

release_source_digest() ->
    binary:encode_hex(crypto:hash(sha256, [
        [maps:get(name, Package), 0,
         [[maps:get(path, File), 0, maps:get(sha256, File), 0] ||
            File <- release_inventory(release_package_files(Package))]] || Package <- release_packages()])).

release_sbom(Artifacts) ->
    Packages = release_packages(),
    External = release_external_packages(),
    Versions = maps:from_list([{maps:get(name, P), <<"0.1.0">>} || P <- Packages] ++
        [{maps:get(name, P), maps:get(version, P)} || P <- External]),
    Components = [(release_component(maps:get(name, P), <<"0.1.0">>))#{
        hashes => [#{alg => <<"SHA-256">>, content => maps:get(<<"sha256">>, A)}]} ||
        {P, A} <- lists:zip(Packages, Artifacts)] ++
        [release_component(maps:get(name, P), maps:get(version, P)) || P <- External],
    Dependencies = [#{ref => release_component_ref(maps:get(name, P), Versions), dependsOn =>
        lists:sort([release_component_ref(Name, Versions) || {Name, _} <- maps:get(dependencies, P)])} ||
        P <- Packages ++ External],
    #{bomFormat => <<"CycloneDX">>, specVersion => <<"1.6">>, version => 1,
        components => Components, dependencies => Dependencies}.

release_component(Name, Version) ->
    Ref = <<"pkg:hex/", Name/binary, "@", Version/binary>>,
    #{type => <<"library">>, 'bom-ref' => Ref, purl => Ref, name => Name, version => Version}.
release_component_ref(Name, Versions) -> maps:get('bom-ref', release_component(Name, maps:get(Name, Versions))).

release_external_packages() ->
    [begin
        App = examples_read(filename:join(["build/dev/erlang", binary_to_list(Name),
            "ebin", binary_to_list(Name) ++ ".app"]), 1048576),
        {match, [Version]} = re:run(App, <<"\\{vsn,\\s*\"([0-9][0-9A-Za-z.+-]{0,64})\"\\}">>, [{capture, [1], binary}]),
        {match, [Applications]} = re:run(App, <<"\\{applications,\\s*\\[([^]]*)\\]\\}">>, [{capture, [1], binary}]),
        Names = case string:trim(Applications) of <<>> -> []; Bytes ->
            [string:trim(N) || N <- binary:split(Bytes, <<",">>, [global])] end,
        Expected = case Name of <<"gleam_stdlib">> -> []; _ -> [<<"gleam_stdlib">>] end,
        Expected = lists:sort(Names),
        #{name => Name, version => Version, dependencies => [{N, <<>>} || N <- Expected]}
    end || Name <- [<<"gleam_stdlib">>, <<"gleam_erlang">>, <<"gleam_http">>]].

release_provenance(Report) ->
    Artifacts = maps:get(<<"artifacts">>, Report),
    Nonce = maps:get(<<"run_nonce">>, Report), Directory = release_directory(Nonce),
    Consumers = maps:get(<<"consumers">>, Report),
    Dependencies = maps:get(<<"dependency_library">>, Report),
    Identity = maps:get(<<"evidence_identity">>, Report),
    #{'_type' => <<"https://in-toto.io/Statement/v1">>,
        subject => [#{name => <<(maps:get(<<"name">>, A))/binary, "-0.1.0.tar">>,
            digest => #{sha256 => maps:get(<<"sha256">>, A)}} || A <- Artifacts],
        predicateType => <<"https://slsa.dev/provenance/v1">>,
        predicate => #{buildDefinition => #{
            buildType => <<"urn:http3:release-sim:archive-consumers:v1">>,
            externalParameters => #{}, internalParameters => #{},
            resolvedDependencies => [
                #{name => <<"archive-source-inventories">>, digest => #{sha256 => release_source_digest()}},
                #{name => <<"workspace-evidence-identity">>, digest => #{sha256 => release_inventory_digest(Identity)}} |
                [#{name => maps:get(<<"name">>, D), digest => #{sha256 =>
                    release_inventory_digest(maps:get(<<"files">>, D))}} || D <- Dependencies]]},
          runDetails => #{
            builder => #{id => <<"urn:http3:release-sim:local-untrusted:v1">>},
            metadata => #{invocationId => <<"release-sim:", Nonce/binary>>},
            byproducts => [#{name => maps:get(<<"name">>, C), digest => #{sha256 =>
                examples_file_hash(filename:join([Directory, "consumers",
                    binary_to_list(maps:get(<<"name">>, C)), "out", "execution.json"]), 16777216)}} || C <- Consumers]}}}.

release_inventory_digest(Value) ->
    binary:encode_hex(crypto:hash(sha256, json:encode(Value))).


release_source_read(Path) -> examples_read(Path, 134217728).
release_source_ensure(true, _) -> ok;
release_source_ensure(false, Reason) -> error(Reason).
-endif.
