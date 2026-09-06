#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

main(["print", Path]) ->
    io:put_chars(canonical_snapshot(Path));
main(["update", HttpPath, Http3Path, CorePath,
      HttpSnapshotPath, Http3SnapshotPath, CoreSnapshotPath]) ->
    Http = read(HttpPath),
    Http3 = read(Http3Path),
    Core = read(CorePath),
    audit_http(Http),
    audit_http3(Http3),
    audit_core(Core),
    ok = file:write_file(HttpSnapshotPath, canonical_snapshot(Http)),
    ok = file:write_file(Http3SnapshotPath, canonical_snapshot(Http3)),
    ok = file:write_file(CoreSnapshotPath, canonical_snapshot(Core)),
    io:format("updated audited http, http3, and quic_core API snapshots~n");
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
main([HttpPath, Http3Path, CorePath,
      HttpSnapshotPath, Http3SnapshotPath, CoreSnapshotPath]) ->
    Http = read(HttpPath),
    Http3 = read(Http3Path),
    Core = read(CorePath),
    audit_http(Http),
    audit_http3(Http3),
    audit_core(Core),
    compare_snapshot("http", canonical_snapshot(Http), read(HttpSnapshotPath)),
    compare_snapshot(
        "http3",
        canonical_snapshot(Http3),
        read(Http3SnapshotPath)
    ),
    compare_snapshot(
        "quic_core",
        canonical_snapshot(Core),
        read(CoreSnapshotPath)
    ),
    io:format("public API boundaries and canonical snapshots ok~n");
main(_) ->
    erlang:error(public_api_audit_usage).

audit_http(Interface) ->
    assert_absent(Interface, [
        <<"http/internal/">>,
        <<"http3/internal/">>,
        <<"quic_core/internal/">>,
        <<"CancelHandle">>,
        <<"\"Lifecycle\":{" >>,
        <<"Registration">>,
        <<"\"name\":\"Socket\"">>,
        <<"FileSource">>,
        <<"KeyToken">>,
        <<"ControllerHandle">>,
        <<"LeaseHandle">>,
        <<"TunnelGuard">>,
        <<"replay_factory">>,
        <<"\"name\":\"Pid\"">>,
        <<"\"name\":\"Subject\"">>,
        <<"\"name\":\"Reference\"">>,
        <<"\"name\":\"Dynamic\"">>,
        <<"\"udp_proxy_http3_request\":{" >>
    ] ++ production_ffi_modules()),
    assert_present(Interface, [
        <<"\"http\":{" >>,
        <<"\"http/body\":{" >>,
        <<"\"http/bhttp\":{" >>,
        <<"\"http/client\":{" >>,
        <<"\"http/client_store\":{" >>,
        <<"\"http/compression\":{" >>,
        <<"\"http/context\":{" >>,
        <<"\"http/diagnostics\":{" >>,
        <<"\"request_id\":{" >>,
        <<"\"request_id_value\":{" >>,
        <<"\"RequestId\":{" >>,
        <<"\"Observation\":{" >>,
        <<"\"http/digest\":{" >>,
        <<"\"http/error\":{" >>,
        <<"\"http/masque\":{" >>,
        <<"\"start_udp_proxy_listener\":{" >>,
        <<"\"udp_proxy_listener_port\":{" >>,
        <<"\"accept_udp_proxy_request\":{" >>,
        <<"\"udp_proxy_prepared_request\":{" >>,
        <<"\"validate_http3_udp_proxy_request\":{" >>,
        <<"\"establish_system_udp_proxy_request\":{" >>,
        <<"\"system_udp_proxy_transport\":{" >>,
        <<"\"system_udp_proxy_session\":{" >>,
        <<"\"udp_proxy_listener_snapshot\":{" >>,
        <<"\"drain_udp_proxy_listener\":{" >>,
        <<"\"stop_udp_proxy_listener\":{" >>,
        <<"\"UdpProxyListener\":{" >>,
        <<"\"UdpProxyRequest\":{" >>,
        <<"\"UdpProxyListenerSnapshot\":{" >>,
        <<"\"UdpProxyListenerFailure\":{" >>,
        <<"\"UdpProxyRequestAccept\":{" >>,
        <<"\"SystemUdpProxy\":{" >>,
        <<"\"SystemUdpProxyEstablishment\":{" >>,
        <<"\"context_udp_request_stream_resource\":{" >>,
        <<"\"http3_udp_request_stream_resource\":{" >>,
        <<"\"establish_system_udp_proxy\":{" >>,
        <<"\"forward_system_udp_datagram\":{" >>,
        <<"\"receive_system_udp_datagram\":{" >>,
        <<"\"wait_system_udp_event\":{" >>,
        <<"\"system_udp_socket_snapshot\":{" >>,
        <<"\"bind_supervised_system_udp_proxy_stream\":{" >>,
        <<"\"bind_supervised_system_udp_proxy_stream_with_idle\":{" >>,
        <<"\"bind_supervised_system_udp_proxy_context\":{" >>,
        <<"\"bind_supervised_system_udp_proxy_context_with_idle\":{" >>,
        <<"\"udp_proxy_idle_timeout_disabled\":{" >>,
        <<"\"udp_proxy_idle_timeout\":{" >>,
        <<"\"udp_proxy_idle_timeout_milliseconds\":{" >>,
        <<"\"udp_proxy_idle_snapshot\":{" >>,
        <<"\"UdpProxyIdlePolicy\":{" >>,
        <<"\"UdpProxyIdleState\":{" >>,
        <<"\"UdpProxyIdleSnapshot\":{" >>,
        <<"\"SystemUdpSocketSnapshot\":{" >>,
        <<"\"SystemUdpSessionInactive\"" >>,
        <<"\"http/middleware\":{" >>,
        <<"\"http/ohttp\":{" >>,
        <<"\"http/resource\":{" >>,
        <<"\"http/server\":{" >>,
        <<"\"http/signature\":{" >>,
        <<"\"http/status\":{" >>,
        <<"\"http/structured_fields\":{" >>,
        <<"\"http/websocket\":{" >>,
        <<"\"fetch\":{" >>,
        <<"\"exchange\":{" >>,
        <<"\"open_tunnel\":{" >>,
        <<"\"tunnel_response\":{" >>,
        <<"\"tunnel_connection\":{" >>,
        <<"\"send_tunnel\":{" >>,
        <<"\"read_tunnel\":{" >>,
        <<"\"close_tunnel\":{" >>,
        <<"\"drain\":{" >>,
        <<"\"close\":{" >>,
        <<"\"selected_protocol\":{" >>,
        <<"\"pool_limits\":{" >>,
        <<"\"pooling_enabled\":{" >>,
        <<"\"without_pooling\":{" >>,
        <<"\"with_pool_limits\":{" >>,
        <<"\"with_body_limits\":{" >>,
        <<"\"handle\":{" >>,
        <<"\"reload_handler\":{" >>,
        <<"\"remaining_milliseconds\":{" >>,
        <<"\"with_middlewares\":{" >>,
        <<"\"with_diagnostics\":{" >>,
        <<"\"http1_defaults\":{" >>,
        <<"\"allow_http1_cleartext\":{" >>,
        <<"\"with_http1_idle_timeout\":{" >>,
        <<"\"with_http1_timeouts\":{" >>,
        <<"\"with_http1_connection_limits\":{" >>,
        <<"\"with_http1_limits\":{" >>,
        <<"\"listen_http1\":{" >>,
        <<"\"listen_http1_tls\":{" >>,
        <<"\"listener_endpoint\":{" >>,
        <<"\"drain_listener\":{" >>,
        <<"\"stop_listener\":{" >>,
        <<"\"resize\":{" >>,
        <<"\"snapshot\":{" >>,
        <<"\"supports_http3\":{" >>,
        <<"\"module\":\"gleam/http/request\"">>,
        <<"\"module\":\"gleam/http/response\"">>,
        <<"\"read_all\":{" >>,
        <<"\"replay\":{" >>,
        <<"\"from_bytes_with_trailers\":{" >>,
        <<"\"Body\":{" >>,
        <<"\"Client\":{" >>,
        <<"\"Config\":{" >>,
        <<"\"Exchange\":{" >>,
        <<"\"Tunnel\":{" >>,
        <<"\"TunnelHandshake\":{" >>,
        <<"\"TunnelRead\":{" >>,
        <<"\"PoolLimits\":{" >>,
        <<"\"Context\":{" >>,
        <<"\"Key\":{" >>,
        <<"\"Reporter\":{" >>,
        <<"\"Middleware\":{" >>,
        <<"\"Controller\":{" >>,
        <<"\"Lease\":{" >>,
        <<"\"Server\":{" >>,
        <<"\"Http1Config\":{" >>,
        <<"\"Listener\":{" >>,
        <<"\"Handler\":{" >>,
        <<"\"Error\":{" >>,
        <<"\"ErrorKind\":{" >>
    ]).

audit_http3(Interface) ->
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
        <<"\"cancel\":{" >>,
        <<"\"Cancellation\":{" >>,
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
        Actual -> erlang:error({unexpected_quic_core_public_modules, Actual})
    end,
    assert_absent(Interface, [
        <<"quic_core/http3">>,
        <<"quic_core/frame">>,
        <<"quic_core/packet">>,
        <<"quic_core/transport_parameter">>,
        <<"quic_core/varint">>,
        <<"quic_core/version">>,
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
        <<"\"quic_core/client\":{" >>,
        <<"\"quic_core/config\":{" >>,
        <<"\"quic_core/diagnostics\":{" >>,
        <<"\"quic_core/server\":{" >>,
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
        <<"quic_core">>,
        <<"quic_core/client">>,
        <<"quic_core/config">>,
        <<"quic_core/diagnostics">>,
        <<"quic_core/failure">>,
        <<"quic_core/server">>
    ].

production_ffi_modules() ->
    Manifest = json:decode(read("qualification.json")),
    Inventory = maps:get(<<"ffi_inventory">>, Manifest),
    1 = maps:get(<<"schema">>, Inventory),
    Sources = maps:get(<<"sources">>, Inventory),
    true = Sources =/= [],
    true = Sources =:= lists:usort(Sources),
    [
        list_to_binary(filename:basename(binary_to_list(Source), ".erl"))
     || Source <- Sources
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

imported_core_module("import quic_core" ++ Rest) ->
    case Rest of
        [] -> {ok, "quic_core"};
        [Separator | _] when
            Separator =:= $/; Separator =:= $.; Separator =:= $\s;
            Separator =:= $\t; Separator =:= $\r
        ->
            {ok, "quic_core" ++ module_characters(Rest)};
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
        <<"# Root imports of package-private quic_core modules that predate\n">>,
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
