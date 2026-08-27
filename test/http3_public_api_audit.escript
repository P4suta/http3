#!/usr/bin/env escript

main(["print", Path]) ->
    io:put_chars(canonical_snapshot(Path));
main(["update", RootPath, CorePath, RootSnapshotPath, CoreSnapshotPath]) ->
    Root = read(RootPath),
    Core = read(CorePath),
    audit_root(Root),
    audit_core(Core),
    ok = file:write_file(RootSnapshotPath, canonical_snapshot(Root)),
    ok = file:write_file(CoreSnapshotPath, canonical_snapshot(Core)),
    io:format("updated audited http3 and gleam_quic API snapshots~n");
main(["boundary", "--write-allowlist" | Rest]) ->
    {Directories, AllowlistPath} = split_boundary_arguments(Rest),
    Entries = forbidden_imports(Directories),
    Pairs = allowlist_pairs(Entries),
    ok = file:write_file(AllowlistPath, allowlist_document(Pairs)),
    io:format(
        "wrote ~b boundary allowlist entries to ~s~n",
        [length(Pairs), AllowlistPath]
    );
main(["boundary" | Rest]) ->
    {Directories, AllowlistPath} = split_boundary_arguments(Rest),
    Entries = forbidden_imports(Directories),
    Allowed = read_allowlist(AllowlistPath),
    Present = allowlist_pairs(Entries),
    Violations = [
        Entry
     || Entry = {File, _Line, Module} <- Entries,
        not lists:member({File, Module}, Allowed)
    ],
    Stale = [Pair || Pair <- Allowed, not lists:member(Pair, Present)],
    report_boundary(Violations, Stale, AllowlistPath);
main([RootPath, CorePath, RootSnapshotPath, CoreSnapshotPath]) ->
    Root = read(RootPath),
    Core = read(CorePath),
    audit_root(Root),
    audit_core(Core),
    compare_snapshot("http3", canonical_snapshot(Root), read(RootSnapshotPath)),
    compare_snapshot(
        "gleam_quic",
        canonical_snapshot(Core),
        read(CoreSnapshotPath)
    ),
    io:format("public API boundaries and canonical snapshots ok~n");
main(_) ->
    erlang:error(public_api_audit_usage).

audit_root(Interface) ->
    Forbidden = [
        <<"\"client_connection\":{" >>,
        <<"\"client_stream\":{" >>,
        <<"\"server_stream\":{" >>,
        <<"\"ticket_handle\":{" >>,
        <<"ConnectionHandle">>,
        <<"StreamHandle">>,
        <<"RequestHandle">>,
        <<"ResumptionTicketHandle">>,
        <<"http3/internal/">>,
        <<"Bbr">>,
        <<"BackendFailure">>
    ],
    Required = [
        <<"\"connection_transport\":{" >>,
        <<"\"stream_transport\":{" >>,
        <<"\"request_transport\":{" >>,
        <<"\"capabilities\":{" >>,
        <<"\"resumption_ticket\":{" >>,
        <<"\"Limits\":{" >>,
        <<"\"Deadlines\":{" >>,
        <<"\"Failure\":{" >>
    ],
    assert_absent(Interface, Forbidden),
    assert_present(Interface, Required).

audit_core(Interface) ->
    Decoded = json:decode(Interface),
    Modules = maps:get(<<"modules">>, Decoded),
    Expected = public_core_modules(),
    case lists:sort(maps:keys(Modules)) of
        Expected -> ok;
        Actual -> erlang:error({unexpected_gleam_quic_public_modules, Actual})
    end,
    assert_absent(Interface, [
        <<"gleam_quic/http3">>,
        <<"gleam_quic/frame">>,
        <<"gleam_quic/packet">>,
        <<"gleam_quic/transport_parameter">>,
        <<"gleam_quic/varint">>,
        <<"gleam_quic/version">>,
        <<"\"Http3\"">>,
        <<"\"RequestBody\"">>,
        <<"\"ResponseBody\"">>,
        <<"\"Frame\"">>,
        <<"\"QpackTable\"">>,
        <<"\"QpackBlockedStreams\"">>,
        <<"\"name\":\"Pid\"">>,
        <<"\"name\":\"Subject\"">>,
        <<"\"name\":\"Reference\"">>,
        <<"\"name\":\"Dynamic\"">>,
        <<"\"name\":\"SigningKey\"">>,
        <<"\"name\":\"TrustStore\"">>,
        <<"\"name\":\"ServerCredential\"">>,
        <<"\"name\":\"ClientCredential\"">>,
        <<"\"name\":\"VerifiedPeer\"">>,
        <<"\"name\":\"ClientTicket\"">>,
        <<"\"name\":\"TrafficSecret\"">>,
        <<"Bbr">>,
        <<"BackendFailure">>
    ]),
    assert_present(Interface, [
        <<"\"gleam_quic/client\":{" >>,
        <<"\"gleam_quic/config\":{" >>,
        <<"\"gleam_quic/diagnostics\":{" >>,
        <<"\"gleam_quic/server\":{" >>,
        <<"\"Client\":{" >>,
        <<"\"Listener\":{" >>,
        <<"\"Deadlines\":{" >>,
        <<"\"Limits\":{" >>,
        <<"\"ConnectionInfo\":{" >>,
        <<"\"CipherSuite\":{" >>,
        <<"\"OperationalKeys\":{" >>,
        <<"\"ClientAuthentication\":{" >>,
        <<"\"ClientCertificateAuthorities\":{" >>,
        <<"\"ClientIdentity\":{" >>,
        <<"\"Failure\":{" >>
    ]).

public_core_modules() ->
    [
        <<"gleam_quic">>,
        <<"gleam_quic/client">>,
        <<"gleam_quic/config">>,
        <<"gleam_quic/diagnostics">>,
        <<"gleam_quic/failure">>,
        <<"gleam_quic/server">>
    ].

canonical_snapshot(Path) when is_list(Path) ->
    canonical_snapshot(read(Path));
canonical_snapshot(Interface) when is_binary(Interface) ->
    Decoded = json:decode(Interface),
    Package = maps:get(<<"name">>, Decoded),
    Modules = maps:get(<<"modules">>, Decoded),
    Lines = maps:fold(
        fun(Module, Definition, Acc) ->
            module_lines(Package, Module, Definition, Acc)
        end,
        [],
        Modules
    ),
    iolist_to_binary(lists:join(<<"\n">>, lists:sort(Lines)) ++ [<<"\n">>]).

module_lines(Package, Module, Definition, Acc) ->
    Header = iolist_to_binary([<<"module ">>, Package, <<" ">>, Module]),
    Categories = [
        {<<"alias">>, <<"type-aliases">>},
        {<<"type">>, <<"types">>},
        {<<"constant">>, <<"constants">>},
        {<<"function">>, <<"functions">>}
    ],
    lists:foldl(
        fun({Kind, Key}, Lines) ->
            Entries = maps:get(Key, Definition, #{}),
            maps:fold(
                fun(Name, Value, EntryLines) ->
                    [snapshot_line(Kind, Module, Name, Value) | EntryLines]
                end,
                Lines,
                Entries
            )
        end,
        [Header | Acc],
        Categories
    ).

snapshot_line(Kind, Module, Name, Value) ->
    Semantic = strip_metadata(Value),
    iolist_to_binary([
        Kind,
        <<" ">>,
        Module,
        <<"/">>,
        Name,
        <<" ">>,
        io_lib:format("~0p", [Semantic])
    ]).

strip_metadata(Value) when is_map(Value) ->
    maps:map(
        fun(_Key, Child) -> strip_metadata(Child) end,
        maps:without(
            [<<"documentation">>, <<"deprecation">>, <<"implementations">>],
            Value
        )
    );
strip_metadata(Value) when is_list(Value) ->
    lists:map(fun strip_metadata/1, Value);
strip_metadata(Value) ->
    Value.

compare_snapshot(Name, Actual, Expected) ->
    ActualLines = snapshot_lines(Actual),
    ExpectedLines = snapshot_lines(Expected),
    case ActualLines =:= ExpectedLines of
        true -> io:format("~s API snapshot ok~n", [Name]);
        false ->
            erlang:error({public_api_snapshot_changed, Name,
                          first_difference(ActualLines, ExpectedLines, 1)})
    end.

snapshot_lines(Snapshot) ->
    drop_trailing_empty(binary:split(Snapshot, <<"\n">>, [global])).

drop_trailing_empty(Lines) ->
    lists:reverse(drop_leading_empty(lists:reverse(Lines))).

drop_leading_empty([<<>> | Rest]) -> drop_leading_empty(Rest);
drop_leading_empty(Lines) -> Lines.

first_difference([Line | Rest], [Line | ExpectedRest], Number) ->
    first_difference(Rest, ExpectedRest, Number + 1);
first_difference([Actual | _], [Expected | _], Number) ->
    {line, Number, expected, Expected, actual, Actual};
first_difference([], [Expected | _], Number) ->
    {line, Number, expected, Expected, actual, end_of_file};
first_difference([Actual | _], [], Number) ->
    {line, Number, expected, end_of_file, actual, Actual};
first_difference([], [], _Number) ->
    unknown.

read(Path) ->
    case file:read_file(Path) of
        {ok, Contents} -> Contents;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

assert_absent(_Interface, []) ->
    ok;
assert_absent(Interface, [Pattern | Rest]) ->
    case binary:match(Interface, Pattern) of
        nomatch -> assert_absent(Interface, Rest);
        _ -> erlang:error({public_api_leaks_internal_value, Pattern})
    end.

assert_present(_Interface, []) ->
    ok;
assert_present(Interface, [Pattern | Rest]) ->
    case binary:match(Interface, Pattern) of
        nomatch -> erlang:error({public_api_missing_expected_value, Pattern});
        _ -> assert_present(Interface, Rest)
    end.

split_boundary_arguments(Arguments) ->
    case lists:reverse(Arguments) of
        [AllowlistPath | ReversedDirectories] when ReversedDirectories =/= [] ->
            {lists:reverse(ReversedDirectories), AllowlistPath};
        _ ->
            erlang:error(public_api_audit_usage)
    end.

forbidden_imports(Directories) ->
    Files = lists:sort(lists:flatmap(fun gleam_files/1, Directories)),
    lists:flatmap(fun file_forbidden_imports/1, Files).

gleam_files(Directory) ->
    case file:list_dir(Directory) of
        {error, Reason} ->
            erlang:error({cannot_read, Directory, Reason});
        {ok, Names} ->
            lists:flatmap(
                fun(Name) ->
                    Path = filename:join(Directory, Name),
                    case filelib:is_dir(Path) of
                        true -> gleam_files(Path);
                        false -> gleam_file(Path)
                    end
                end,
                lists:sort(Names)
            )
    end.

gleam_file(Path) ->
    case filename:extension(Path) of
        ".gleam" -> [Path];
        _ -> []
    end.

file_forbidden_imports(Path) ->
    Lines = binary:split(read(Path), <<"\n">>, [global]),
    {Entries, _} = lists:foldl(
        fun(Line, {Acc, Number}) ->
            {line_forbidden_import(Path, Number, Line) ++ Acc, Number + 1}
        end,
        {[], 1},
        Lines
    ),
    lists:reverse(Entries).

line_forbidden_import(Path, Number, Line) ->
    case imported_core_module(binary_to_list(Line)) of
        none -> [];
        {ok, Module} ->
            case is_public_core_module(Module) of
                true -> [];
                false -> [{Path, Number, Module}]
            end
    end.

imported_core_module("import gleam_quic" ++ Rest) ->
    case Rest of
        [] -> {ok, "gleam_quic"};
        [Separator | _] when
            Separator =:= $/; Separator =:= $.; Separator =:= $\s;
            Separator =:= $\t; Separator =:= $\r
        ->
            {ok, "gleam_quic" ++ module_characters(Rest)};
        _ ->
            none
    end;
imported_core_module(_Line) ->
    none.

module_characters([Character | Rest]) ->
    case is_module_character(Character) of
        true -> [Character | module_characters(Rest)];
        false -> []
    end;
module_characters([]) ->
    [].

is_module_character(Character) ->
    (Character >= $a andalso Character =< $z) orelse
        (Character >= $0 andalso Character =< $9) orelse
        Character =:= $_ orelse
        Character =:= $/.

is_public_core_module(Module) ->
    lists:member(list_to_binary(Module), public_core_modules()).

allowlist_pairs(Entries) ->
    lists:usort([{File, Module} || {File, _Number, Module} <- Entries]).

allowlist_document(Pairs) ->
    Header = [
        <<"# Root imports of package-private gleam_quic modules that predate\n">>,
        <<"# the three-layer boundary gate. Every line is a `path|module` pair.\n">>,
        <<"# This file may only shrink: delete a line once the import is gone.\n">>,
        <<"# Never add a line and never regenerate it with --write-allowlist.\n">>
    ],
    Lines = [
        [File, <<"|">>, Module, <<"\n">>]
     || {File, Module} <- Pairs
    ],
    iolist_to_binary([Header, Lines]).

read_allowlist(Path) ->
    case file:read_file(Path) of
        {error, enoent} ->
            [];
        {error, Reason} ->
            erlang:error({cannot_read, Path, Reason});
        {ok, Contents} ->
            Lines = binary:split(Contents, <<"\n">>, [global]),
            lists:usort(lists:flatmap(fun allowlist_entry/1, Lines))
    end.

allowlist_entry(<<"#", _/binary>>) ->
    [];
allowlist_entry(<<>>) ->
    [];
allowlist_entry(Line) ->
    case binary:split(Line, <<"|">>) of
        [File, Module] -> [{binary_to_list(File), binary_to_list(Module)}];
        _ -> erlang:error({malformed_boundary_allowlist_line, Line})
    end.

report_boundary([], [], AllowlistPath) ->
    io:format(
        "three-layer boundary ok (allowlist ~s)~n",
        [AllowlistPath]
    );
report_boundary(Violations, Stale, AllowlistPath) ->
    lists:foreach(
        fun({File, Number, Module}) ->
            io:format(
                standard_error,
                "~s:~b: forbidden import ~s~n",
                [File, Number, Module]
            )
        end,
        Violations
    ),
    lists:foreach(
        fun({File, Module}) ->
            io:format(
                standard_error,
                "~s: stale allowlist entry ~s|~s~n",
                [AllowlistPath, File, Module]
            )
        end,
        Stale
    ),
    io:format(
        standard_error,
        "boundary audit failed: ~b forbidden imports, ~b stale allowlist entries~n",
        [length(Violations), length(Stale)]
    ),
    halt(1).
