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
    assert_no_internal_symbol_references(Directories),
    Pairs = allowlist_pairs(Entries),
    ok = file:write_file(AllowlistPath, allowlist_document(Pairs)),
    io:format(
        "wrote ~b boundary allowlist entries to ~s~n",
        [length(Pairs), AllowlistPath]
    );
main(["boundary" | Rest]) ->
    {Directories, AllowlistPath} = split_boundary_arguments(Rest),
    Entries = forbidden_imports(Directories),
    InternalReferences = forbidden_internal_symbol_references(Directories),
    Allowed = read_allowlist(AllowlistPath),
    Present = allowlist_pairs(Entries),
    Violations = [
        Entry
     || Entry = {File, _Line, Module} <- Entries,
        not lists:member({File, Module}, Allowed)
    ],
    Stale = [Pair || Pair <- Allowed, not lists:member(Pair, Present)],
    report_boundary(Violations, InternalReferences, Stale, AllowlistPath);
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
        <<"\"connection_reusable\":{" >>,
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
        <<"\"close_completion_allowance_milliseconds\":{" >>,
        <<"\"close_operation_allowance_milliseconds\":{" >>,
        <<"\"close_with_code_until\":{" >>,
        <<"\"stop_completion_allowance_milliseconds\":{" >>,
        <<"\"stop_until\":{" >>,
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

%% Resolve every qualified use and selectively imported symbol from a public
%% quic_core module back to the current Gleam source. This source-only check runs
%% before an allowlist can bless a private module import; the compiler-interface
%% audit remains the authority for opaque representation leaks.
forbidden_internal_symbol_references(Directories) ->
    internal_symbol_scanner_self_test(),
    assert_repository_root(),
    assert_opaque_adapter_contracts(),
    Files = lists:sort(lists:flatmap(fun gleam_files/1, Directories)),
    References = lists:flatmap(fun file_core_symbol_references/1, Files),
    lists:usort(lists:flatmap(fun forbidden_core_reference/1, References)).

assert_no_internal_symbol_references(Directories) ->
    case forbidden_internal_symbol_references(Directories) of
        [] -> ok;
        References ->
            lists:foreach(fun report_internal_symbol_reference/1, References),
            erlang:error({package_internal_symbol_references, length(References)})
    end.

assert_repository_root() ->
    Required = [
        "scripts/public_api_audit.escript",
        "packages/quic_core/src/quic_core.gleam",
        "packages/quic_core/src/quic_core/client.gleam",
        "packages/quic_core/src/quic_core/server.gleam"
    ],
    case [Path || Path <- Required, not filelib:is_regular(Path)] of
        [] -> ok;
        Missing -> erlang:error({public_api_audit_repository_root_required, Missing})
    end.

assert_opaque_adapter_contracts() ->
    Contracts = [
        {<<"quic_core/client">>, <<"DiagnosticBudget">>},
        {<<"quic_core/client">>, <<"DiagnosticReservation">>},
        {<<"quic_core/server">>, <<"CompletionFeedOwner">>}
    ],
    lists:foreach(
        fun({Module, Symbol}) ->
            Path = core_module_source(Module),
            case opaque_declaration_visibility(read(Path), Symbol) of
                {public_opaque, _Line} -> ok;
                Other -> erlang:error({unsafe_adapter_capability, Path, Symbol, Other})
            end
        end,
        Contracts
    ).

file_core_symbol_references(Path) ->
    [
        {Path, Line, Module, Symbol}
     || {Line, Module, Symbol} <- source_core_symbol_references(read(Path))
    ].

source_core_symbol_references(Source) ->
    Lines = binary:split(Source, <<"\n">>, [global]),
    CodeLines = scrub_gleam_lines(Lines),
    {Aliases, SelectiveReferences} = source_core_imports(CodeLines),
    {Reversed, _} = lists:foldl(
        fun(Code, {Acc, Line}) ->
            Found = lists:flatmap(
                fun({Module, Alias}) ->
                    [
                        {Line, Module, Symbol}
                     || Symbol <- line_alias_symbols(Code, Alias)
                    ]
                end,
                Aliases
            ),
            {Found ++ Acc, Line + 1}
        end,
        {[], 1},
        CodeLines
    ),
    lists:usort(SelectiveReferences ++ Reversed).

source_core_imports(Lines) ->
    source_core_imports(Lines, 1, none, [], []).

source_core_imports([], _Line, none, Aliases, References) ->
    {lists:usort(Aliases), lists:usort(References)};
source_core_imports([], _Line, {collecting, Start, _Declaration},
                    _Aliases, _References) ->
    erlang:error({unterminated_selective_import, Start});
source_core_imports([Raw | Rest], Line, none, Aliases, References) ->
    Trimmed = trim_binary(Raw),
    case Trimmed of
        <<"import ", _/binary>> ->
            case selective_import_continues(Trimmed) of
                true ->
                    source_core_imports(
                        Rest, Line + 1, {collecting, Line, Trimmed},
                        Aliases, References);
                false ->
                    {NewAliases, NewReferences} = parse_core_import(Trimmed, Line),
                    source_core_imports(
                        Rest, Line + 1, none,
                        NewAliases ++ Aliases, NewReferences ++ References)
            end;
        _ ->
            source_core_imports(Rest, Line + 1, none, Aliases, References)
    end;
source_core_imports([Raw | Rest], Line,
                    {collecting, Start, Declaration}, Aliases, References) ->
    Joined = <<Declaration/binary, 32, (trim_binary(Raw))/binary>>,
    case binary:match(Joined, <<"}">>) of
        nomatch ->
            source_core_imports(
                Rest, Line + 1, {collecting, Start, Joined},
                Aliases, References);
        _ ->
            {NewAliases, NewReferences} = parse_core_import(Joined, Start),
            source_core_imports(
                Rest, Line + 1, none,
                NewAliases ++ Aliases, NewReferences ++ References)
    end.

selective_import_continues(Declaration) ->
    binary:match(Declaration, <<".{">>) =/= nomatch andalso
        binary:match(Declaration, <<"}">>) =:= nomatch.

parse_core_import(Declaration, Line) ->
    case binary_to_list(Declaration) of
        "import " ++ Rest ->
            Module = module_characters(Rest),
            ModuleBinary = list_to_binary(Module),
            case lists:member(ModuleBinary, public_core_modules()) of
                true ->
                    Tail = lists:nthtail(length(Module), Rest),
                    Alias = module_import_alias(Tail, ModuleBinary),
                    References = [
                        {Line, ModuleBinary, Symbol}
                     || Symbol <- selective_import_symbols(Tail)
                    ],
                    {[{ModuleBinary, Alias}], References};
                false -> {[], []}
            end;
        _ -> {[], []}
    end.

module_import_alias(" as " ++ Rest, _Module) ->
    list_to_binary(take_alias_identifier(Rest));
module_import_alias(_Tail, Module) ->
    lists:last(binary:split(Module, <<"/">>, [global])).

selective_import_symbols(".{" ++ Rest) ->
    Content = take_until_closing_brace(Rest),
    lists:flatmap(fun selective_import_symbol/1,
        string:split(Content, ",", all));
selective_import_symbols(_) -> [].

take_until_closing_brace([$} | _]) -> [];
take_until_closing_brace([Character | Rest]) ->
    [Character | take_until_closing_brace(Rest)];
take_until_closing_brace([]) -> [].

selective_import_symbol(Item) ->
    Trimmed = string:trim(Item),
    WithoutType = case Trimmed of
        "type " ++ Rest -> Rest;
        _ -> Trimmed
    end,
    case take_alias_identifier(WithoutType) of
        [] -> [];
        Symbol -> [list_to_binary(Symbol)]
    end.

take_alias_identifier([Character | Rest]) when
    (Character >= $a andalso Character =< $z) orelse
        (Character >= $A andalso Character =< $Z) orelse
        (Character >= $0 andalso Character =< $9) orelse
        Character =:= $_
->
    [Character | take_alias_identifier(Rest)];
take_alias_identifier(_) -> [].

scrub_gleam_lines(Lines) ->
    {Reversed, _} = lists:foldl(
        fun(Line, {Acc, State}) ->
            {Code, NextState} = scrub_gleam_line(Line, State, <<>>),
            {[Code | Acc], NextState}
        end,
        {[], code},
        Lines
    ),
    lists:reverse(Reversed).

scrub_gleam_line(<<>>, State, Acc) -> {Acc, State};
scrub_gleam_line(<<$/, $/, _/binary>>, code, Acc) -> {Acc, code};
scrub_gleam_line(<<$", Rest/binary>>, code, Acc) ->
    scrub_gleam_line(Rest, string, <<Acc/binary, 32>>);
scrub_gleam_line(<<$\\, _Escaped, Rest/binary>>, string, Acc) ->
    scrub_gleam_line(Rest, string, Acc);
scrub_gleam_line(<<$", Rest/binary>>, string, Acc) ->
    scrub_gleam_line(Rest, code, <<Acc/binary, 32>>);
scrub_gleam_line(<<_Character, Rest/binary>>, string, Acc) ->
    scrub_gleam_line(Rest, string, Acc);
scrub_gleam_line(<<Character, Rest/binary>>, code, Acc) ->
    scrub_gleam_line(Rest, code, <<Acc/binary, Character>>).

line_alias_symbols(Line, Alias) ->
    Pattern = <<Alias/binary, $.>>,
    lists:flatmap(
        fun({Position, Length}) ->
            case alias_prefix_boundary(Line, Position) of
                false -> [];
                true ->
                    Start = Position + Length,
                    Rest = binary:part(Line, Start, byte_size(Line) - Start),
                    case take_identifier(Rest, <<>>) of
                        <<>> -> [];
                        Symbol -> [Symbol]
                    end
            end
        end,
        binary:matches(Line, Pattern)
    ).

alias_prefix_boundary(_Line, 0) -> true;
alias_prefix_boundary(Line, Position) ->
    not identifier_character(binary:at(Line, Position - 1)).

identifier_character(Character) ->
    (Character >= $a andalso Character =< $z) orelse
        (Character >= $A andalso Character =< $Z) orelse
        (Character >= $0 andalso Character =< $9) orelse
        Character =:= $_.

forbidden_core_reference({File, Line, Module, Symbol}) ->
    Path = core_module_source(Module),
    case source_symbol_visibility(read(Path), Symbol) of
        {public, _DeclarationLine} -> [];
        {Reason, DeclarationLine} ->
            [{File, Line, Module, Symbol,
                {Reason, Path, DeclarationLine}}]
    end.

core_module_source(Module) ->
    "packages/quic_core/src/" ++ binary_to_list(Module) ++ ".gleam".

source_symbol_visibility(Source, Symbol) ->
    case declaration_visibility(Source, Symbol) of
        {missing, 0} -> constructor_visibility(Source, Symbol);
        Visibility -> Visibility
    end.

declaration_visibility(Source, Symbol) ->
    declaration_visibility(binary:split(Source, <<"\n">>, [global]),
        Symbol, false, 1).

declaration_visibility([], _Symbol, _PendingInternal, _Line) ->
    {missing, 0};
declaration_visibility([Raw | Rest], Symbol, PendingInternal, Line) ->
    Trimmed = trim_binary(Raw),
    case Trimmed of
        <<"@internal">> ->
            declaration_visibility(Rest, Symbol, true, Line + 1);
        _ ->
            case public_declaration_symbol(Trimmed) of
                {ok, Symbol} when PendingInternal -> {internal, Line};
                {ok, Symbol} -> {public, Line};
                {ok, _Other} ->
                    declaration_visibility(Rest, Symbol, false, Line + 1);
                none ->
                    KeepPending = PendingInternal andalso
                        declaration_spacing_or_attribute(Trimmed),
                    declaration_visibility(Rest, Symbol, KeepPending, Line + 1)
            end
    end.

public_declaration_symbol(<<"pub opaque type ", Rest/binary>>) ->
    declaration_identifier(Rest);
public_declaration_symbol(<<"pub type ", Rest/binary>>) ->
    declaration_identifier(Rest);
public_declaration_symbol(<<"pub fn ", Rest/binary>>) ->
    declaration_identifier(Rest);
public_declaration_symbol(<<"pub const ", Rest/binary>>) ->
    declaration_identifier(Rest);
public_declaration_symbol(_) -> none.

opaque_declaration_visibility(Source, Symbol) ->
    opaque_declaration_visibility(
        binary:split(Source, <<"\n">>, [global]), Symbol, false, 1).

opaque_declaration_visibility([], _Symbol, _PendingInternal, _Line) ->
    {missing, 0};
opaque_declaration_visibility([Raw | Rest], Symbol, PendingInternal, Line) ->
    Trimmed = trim_binary(Raw),
    case Trimmed of
        <<"@internal">> ->
            opaque_declaration_visibility(Rest, Symbol, true, Line + 1);
        <<"pub opaque type ", Declaration/binary>> ->
            case declaration_identifier(Declaration) of
                {ok, Symbol} when PendingInternal -> {internal_opaque, Line};
                {ok, Symbol} -> {public_opaque, Line};
                _ -> opaque_declaration_visibility(Rest, Symbol, false, Line + 1)
            end;
        _ ->
            case public_declaration_symbol(Trimmed) of
                {ok, Symbol} -> {wrong_public_kind, Line};
                {ok, _Other} ->
                    opaque_declaration_visibility(Rest, Symbol, false, Line + 1);
                none ->
                    KeepPending = PendingInternal andalso
                        declaration_spacing_or_attribute(Trimmed),
                    opaque_declaration_visibility(
                        Rest, Symbol, KeepPending, Line + 1)
            end
    end.

constructor_visibility(Source, Symbol) ->
    constructor_visibility(
        binary:split(Source, <<"\n">>, [global]),
        Symbol, false, outside, 1).

constructor_visibility([], _Symbol, _PendingInternal, _State, _Line) ->
    {missing, 0};
constructor_visibility([Raw | Rest], Symbol, PendingInternal, outside, Line) ->
    Trimmed = trim_binary(Raw),
    case Trimmed of
        <<"@internal">> ->
            constructor_visibility(Rest, Symbol, true, outside, Line + 1);
        _ ->
            case public_sum_type_line(Trimmed) of
                true ->
                    Visibility = case PendingInternal of
                        true -> internal;
                        false -> public
                    end,
                    constructor_visibility(
                        Rest, Symbol, false, {sum_type, Visibility, 0}, Line + 1);
                false ->
                    KeepPending = PendingInternal andalso
                        declaration_spacing_or_attribute(Trimmed),
                    constructor_visibility(
                        Rest, Symbol, KeepPending, outside, Line + 1)
            end
    end;
constructor_visibility([Raw | Rest], Symbol, _PendingInternal,
                       {sum_type, Visibility, Depth}, Line) ->
    Trimmed = trim_binary(Raw),
    case {Depth, Trimmed} of
        {0, <<"}", _/binary>>} ->
            constructor_visibility(Rest, Symbol, false, outside, Line + 1);
        _ ->
            case {Depth, constructor_identifier(Trimmed)} of
                {0, {ok, Symbol}} -> {Visibility, Line};
                _ ->
                    NextDepth = Depth + parenthesis_delta(Trimmed),
                    constructor_visibility(
                        Rest, Symbol, false,
                        {sum_type, Visibility, NextDepth}, Line + 1)
            end
    end.

public_sum_type_line(<<"pub type ", _/binary>> = Line) ->
    binary:match(Line, <<"{">>) =/= nomatch;
public_sum_type_line(_) -> false.

constructor_identifier(Line) ->
    Identifier = take_identifier(Line, <<>>),
    case Identifier of
        <<First, _/binary>> when First >= $A, First =< $Z ->
            Rest = binary:part(
                Line, byte_size(Identifier), byte_size(Line) - byte_size(Identifier)),
            case trim_binary(Rest) of
                <<>> -> {ok, Identifier};
                <<"(", _/binary>> -> {ok, Identifier};
                _ -> none
            end;
        _ -> none
    end.

parenthesis_delta(Line) ->
    count_character(Line, $() - count_character(Line, $)).

count_character(Line, Character) ->
    count_character(Line, Character, 0).

count_character(<<>>, _Character, Count) -> Count;
count_character(<<Character, Rest/binary>>, Character, Count) ->
    count_character(Rest, Character, Count + 1);
count_character(<<_Other, Rest/binary>>, Character, Count) ->
    count_character(Rest, Character, Count).

internal_symbol_scanner_self_test() ->
    {public, 1} = source_symbol_visibility(
        <<"pub fn visible() -> Nil { Nil }\n">>, <<"visible">>),
    {internal, 2} = source_symbol_visibility(
        <<"@internal\npub fn hidden() -> Nil { Nil }\n">>, <<"hidden">>),
    {public, 1} = source_symbol_visibility(
        <<"pub type PublicAlias = Int\n">>, <<"PublicAlias">>),
    {internal, 2} = source_symbol_visibility(
        <<"@internal\npub type HiddenAlias = Int\n">>, <<"HiddenAlias">>),
    {public, 2} = source_symbol_visibility(
        <<"pub type Result {\n  Visible\n}\n">>, <<"Visible">>),
    {internal, 3} = source_symbol_visibility(
        <<"@internal\npub type Result {\n  Hidden\n}\n">>, <<"Hidden">>),
    {missing, 0} = source_symbol_visibility(
        <<"pub fn visible() -> Nil { Nil }\n">>, <<"absent">>),
    {public_opaque, 1} = opaque_declaration_visibility(
        <<"pub opaque type Capability { Capability(owner: Pid) }\n">>,
        <<"Capability">>),
    {wrong_public_kind, 1} = opaque_declaration_visibility(
        <<"pub type Capability { Capability(owner: Pid) }\n">>,
        <<"Capability">>),
    Fixture = <<
        "import quic_core/client as core_client\n",
        "const text = \"core_client.string_value\n",
        "import quic_core/server as decoy\n",
        "decoy.hidden_value\"\n",
        "// core_client.comment_value\n",
        "pub fn probe() { core_client.live_value() }\n",
        "import quic_core/server.{type CompletionFeedOwner as Owner,\n",
        "  completion_feed_owner as capture}\n",
        "pub fn second() { server.live_server_value() }\n"
    >>,
    [
        {6, <<"quic_core/client">>, <<"live_value">>},
        {7, <<"quic_core/server">>, <<"CompletionFeedOwner">>},
        {7, <<"quic_core/server">>, <<"completion_feed_owner">>},
        {9, <<"quic_core/server">>, <<"live_server_value">>}
    ] = source_core_symbol_references(Fixture),
    ok.

declaration_identifier(Source) ->
    case take_identifier(Source, <<>>) of
        <<>> -> none;
        Identifier -> {ok, Identifier}
    end.

take_identifier(<<Character, Rest/binary>>, Acc) when
    (Character >= $a andalso Character =< $z) orelse
        (Character >= $A andalso Character =< $Z) orelse
        (Character >= $0 andalso Character =< $9) orelse
        Character =:= $_
->
    take_identifier(Rest, <<Acc/binary, Character>>);
take_identifier(_, Acc) -> Acc.

declaration_spacing_or_attribute(<<>>) -> true;
declaration_spacing_or_attribute(<<"@", _/binary>>) -> true;
declaration_spacing_or_attribute(_) -> false.

trim_binary(Line) -> list_to_binary(string:trim(binary_to_list(Line))).

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

report_boundary([], [], [], AllowlistPath) ->
    io:format(
        "three-layer boundary ok (allowlist ~s, public adapter seams verified)~n",
        [AllowlistPath]
    );
report_boundary(Violations, InternalReferences, Stale, AllowlistPath) ->
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
    lists:foreach(fun report_internal_symbol_reference/1, InternalReferences),
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
        "boundary audit failed: ~b forbidden imports, ~b internal adapter references, ~b stale allowlist entries~n",
        [length(Violations), length(InternalReferences), length(Stale)]
    ),
    halt(1).

report_internal_symbol_reference({File, Number, Module, Symbol, Reason}) ->
    io:format(
        standard_error,
        "~s:~b: cross-package reference ~s.~s resolves to ~p~n",
        [File, Number, Module, Symbol, Reason]
    ).
