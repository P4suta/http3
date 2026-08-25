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
    Expected = [
        <<"gleam_quic">>,
        <<"gleam_quic/client">>,
        <<"gleam_quic/config">>,
        <<"gleam_quic/diagnostics">>,
        <<"gleam_quic/failure">>,
        <<"gleam_quic/server">>
    ],
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
