#!/usr/bin/env escript

-define(MAX_OUTER_BYTES, 16 * 1024 * 1024).
-define(MAX_CONTENT_BYTES, 128 * 1024 * 1024).

main(Arguments) ->
    try run(Arguments) of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "gleam_quic package gate failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end.

run(["normalize", Input, Output]) ->
    normalize(Input, Output);
run(["normalize-export", Project, Output]) ->
    normalize(current_export_path(Project), Output);
run(["normalize-export", Project]) ->
    Path = current_export_path(Project),
    normalize(Path, Path);
run(["compare-export", Reference, Project]) ->
    compare(Reference, current_export_path(Project));
run(["compare", First, Second]) ->
    compare(First, Second);
run(_) ->
    erlang:error({usage,
                  "normalize INPUT OUTPUT | normalize-export PROJECT [OUTPUT] "
                  "| compare FIRST SECOND | compare-export REFERENCE PROJECT"}).

normalize(Input, Output) ->
    {Version, Metadata, Contents} = read_and_audit(Input),
    CanonicalMetadata = canonical_metadata(Metadata),
    Checksum = hex(crypto:hash(sha256,
                               [Version, CanonicalMetadata, Contents])),
    Files = [
        {"VERSION", Version},
        {"metadata.config", CanonicalMetadata},
        {"contents.tar.gz", Contents},
        {"CHECKSUM", Checksum}
    ],
    Options = [
        {mtime, 0},
        {atime, 0},
        {ctime, 0},
        {uid, 0},
        {gid, 0},
        {mode, 8#600}
    ],
    ok = erl_tar:create(Output, Files, Options),
    {_CanonicalVersion, CanonicalMetadata, Contents} = read_and_audit(Output),
    Digest = file_digest(Output),
    io:format("canonical gleam_quic Hex archive ~s  ~s~n", [Digest, Output]),
    ok.

compare(First, Second) ->
    FirstDigest = file_digest(First),
    SecondDigest = file_digest(Second),
    case FirstDigest =:= SecondDigest of
        true ->
            io:format("reproducible gleam_quic Hex archive ~s~n",
                      [FirstDigest]),
            ok;
        false ->
            erlang:error({non_reproducible_hex_archives,
                          {First, FirstDigest}, {Second, SecondDigest}})
    end.

current_export_path(Project) ->
    ConfigPath = filename:join(Project, "gleam.toml"),
    {ok, Config} = file:read_file(ConfigPath),
    Pattern = <<"(?m)^version[ \\t]*=[ \\t]*\"([0-9A-Za-z.+-]+)\"">>,
    {match, [Version]} = re:run(Config, Pattern, [{capture, [1], binary}]),
    filename:join([Project, "build",
                   "gleam_quic-" ++ binary_to_list(Version) ++ ".tar"]).

read_and_audit(Path) ->
    {ok, Outer} = erl_tar:extract(Path, [memory, {max_size, ?MAX_OUTER_BYTES}]),
    ExpectedOuter = ["CHECKSUM", "VERSION", "contents.tar.gz",
                     "metadata.config"],
    OuterNames = [Name || {Name, _Contents} <- Outer],
    ensure(lists:sort(OuterNames) =:= ExpectedOuter,
           {unexpected_outer_members, OuterNames}),
    ensure(length(OuterNames) =:= length(lists:usort(OuterNames)),
           duplicate_outer_member),
    Version = member("VERSION", Outer),
    Metadata = member("metadata.config", Outer),
    Contents = member("contents.tar.gz", Outer),
    StoredChecksum = member("CHECKSUM", Outer),
    ActualChecksum = hex(crypto:hash(sha256, [Version, Metadata, Contents])),
    ensure(StoredChecksum =:= ActualChecksum,
           {invalid_hex_checksum, StoredChecksum, ActualChecksum}),
    Terms = metadata_terms(Metadata),
    audit_metadata(Terms),
    audit_contents(Contents, Terms),
    {Version, Metadata, Contents}.

audit_metadata(Terms) ->
    Keys = [Key || {Key, _Value} <- Terms],
    ensure(length(Keys) =:= length(lists:usort(Keys)),
           duplicate_metadata_key),
    ensure(metadata_value(<<"name">>, Terms) =:= <<"gleam_quic">>,
           unexpected_package_name),
    ensure(metadata_value(<<"app">>, Terms) =:= <<"gleam_quic">>,
           unexpected_otp_app_name),
    ensure(is_binary(metadata_value(<<"version">>, Terms)),
           invalid_package_version),
    ok.

audit_contents(Compressed, MetadataTerms) ->
    {ok, Inner} = erl_tar:extract({binary, Compressed},
                                  [compressed, memory,
                                   {max_size, ?MAX_CONTENT_BYTES}]),
    Names = [Name || {Name, _Contents} <- Inner],
    ensure(length(Names) =:= length(lists:usort(Names)),
           duplicate_content_member),
    lists:foreach(fun audit_content_path/1, Names),
    lists:foreach(fun audit_private_key/1, Inner),
    Required = [
        "README.md",
        "gleam.toml",
        "src/gleam_quic.gleam",
        "src/gleam_quic/client.gleam",
        "src/gleam_quic/config.gleam",
        "src/gleam_quic/diagnostics.gleam",
        "src/gleam_quic/failure.gleam",
        "src/gleam_quic/server.gleam"
    ],
    lists:foreach(
        fun(Name) -> ensure(lists:member(Name, Names),
                            {missing_required_content, Name}) end,
        Required
    ),
    MetadataFiles = metadata_value(<<"files">>, MetadataTerms),
    DeclaredNames = [unicode:characters_to_list(Name, utf8)
                     || Name <- MetadataFiles],
    ensure(lists:sort(DeclaredNames) =:= lists:sort(Names),
           metadata_content_mismatch),
    ok.

audit_content_path(Name) ->
    Parts = filename:split(Name),
    LowerParts = [string:lowercase(Part) || Part <- Parts],
    Lower = string:lowercase(Name),
    LowerBase = string:lowercase(filename:basename(Name)),
    Extension = string:lowercase(filename:extension(Name)),
    ensure(filename:pathtype(Name) =:= relative andalso
           not lists:member("..", Parts),
           {unsafe_content_path, Name}),
    ensure(not lists:any(fun(Part) ->
        lists:member(Part, ["test", "tests"])
    end, LowerParts), {test_content_in_archive, Name}),
    ensure(not lists:any(fun(Part) ->
        lists:member(Part, ["build", "_build"])
    end, LowerParts), {build_content_in_archive, Name}),
    ensure(not lists:member(".git", LowerParts),
           {git_content_in_archive, Name}),
    ensure(string:find(Lower, "interop") =:= nomatch,
           {interop_content_in_archive, Name}),
    ensure(not lists:member(Extension,
                            [".key", ".pem", ".p12", ".pfx"]),
           {credential_file_in_archive, Name}),
    ensure(string:find(LowerBase, "http3") =:= nomatch andalso
           string:find(LowerBase, "qpack") =:= nomatch andalso
           not lists:member("http3", LowerParts) andalso
           not lists:member("qpack", LowerParts),
           {application_protocol_module_in_core_archive, Name}),
    ok.

audit_private_key({Name, Contents}) ->
    Begin = <<"-----BEGIN ">>,
    PrivateKey = <<"PRIVATE KEY-----">>,
    Markers = [
        <<Begin/binary, PrivateKey/binary>>,
        <<Begin/binary, "RSA ", PrivateKey/binary>>,
        <<Begin/binary, "EC ", PrivateKey/binary>>,
        <<Begin/binary, "OPENSSH ", PrivateKey/binary>>
    ],
    ensure(not lists:any(
        fun(Marker) -> binary:match(Contents, Marker) =/= nomatch end,
        Markers
    ), {private_key_material_in_archive, Name}).

canonical_metadata(Metadata) ->
    Terms = metadata_terms(Metadata),
    Normalized = [canonical_metadata_term(Term) || Term <- Terms],
    iolist_to_binary([io_lib:format("~0tp.~n", [Term])
                      || Term <- Normalized]).

canonical_metadata_term({<<"requirements">>, Requirements}) ->
    Canonical = [
        {Name, lists:keysort(1, Properties)}
        || {Name, Properties} <- Requirements
    ],
    {<<"requirements">>, lists:keysort(1, Canonical)};
canonical_metadata_term({<<"links">>, Links}) ->
    {<<"links">>, lists:sort(Links)};
canonical_metadata_term({<<"files">>, Files}) ->
    {<<"files">>, lists:sort(Files)};
canonical_metadata_term(Term) ->
    Term.

metadata_terms(Metadata) ->
    Characters = unicode:characters_to_list(Metadata, utf8),
    {ok, Tokens, _EndLocation} = erl_scan:string(Characters),
    parse_metadata_tokens(Tokens, [], []).

parse_metadata_tokens([], [], Terms) ->
    lists:reverse(Terms);
parse_metadata_tokens([], Current, _Terms) ->
    erlang:error({unterminated_metadata_term, lists:reverse(Current)});
parse_metadata_tokens([{dot, _Location} = Dot | Rest], Current, Terms) ->
    {ok, Term} = erl_parse:parse_term(lists:reverse([Dot | Current])),
    parse_metadata_tokens(Rest, [], [Term | Terms]);
parse_metadata_tokens([Token | Rest], Current, Terms) ->
    parse_metadata_tokens(Rest, [Token | Current], Terms).

metadata_value(Key, Terms) ->
    case lists:keyfind(Key, 1, Terms) of
        {Key, Value} -> Value;
        false -> erlang:error({missing_metadata_key, Key})
    end.

member(Name, Members) ->
    case lists:keyfind(Name, 1, Members) of
        {Name, Contents} -> Contents;
        false -> erlang:error({missing_archive_member, Name})
    end.

file_digest(Path) ->
    {ok, Contents} = file:read_file(Path),
    binary_to_list(hex(crypto:hash(sha256, Contents))).

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte])
                      || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
