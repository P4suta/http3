#!/usr/bin/env escript

main([]) ->
    Xref = start_xref(http3_ffi_xref),
    Modules = [
        "build/dev/erlang/http3/ebin/http3_internal_transport_ffi.beam",
        "build/dev/erlang/http3/ebin/http3_process_label_ffi.beam",
        "build/dev/erlang/gleam_quic/ebin/gleam_quic_crypto_ffi.beam",
        "build/dev/erlang/gleam_quic/ebin/gleam_quic_process_label_ffi.beam",
        "build/dev/erlang/gleam_quic/ebin/gleam_quic_tls_ffi.beam",
        "build/dev/erlang/gleam_quic/ebin/gleam_quic_udp_ffi.beam",
        "build/dev/erlang/gleam_quic/ebin/gleam_quic_qlog_ffi.beam"
    ],
    lists:foreach(
        fun(Path) ->
            {ok, _} = xref:add_module(Xref, Path)
        end,
        Modules
    ),
    Result = xref:analyze(Xref, undefined_function_calls),
    xref:stop(Xref),
    case Result of
        {ok, []} ->
            io:format("production Erlang FFI xref ok~n");
        {ok, Calls} ->
            io:format(standard_error, "undefined FFI calls: ~p~n", [Calls]),
            halt(1);
        Error ->
            io:format(standard_error, "xref failed: ~p~n", [Error]),
            halt(1)
    end;
main(["boundary", AllowlistPath]) ->
    Xref = start_xref(http3_boundary_xref),
    {ok, _} = xref:add_directory(Xref, "build/dev/erlang/http3/ebin"),
    Result = xref:q(Xref, "XC"),
    xref:stop(Xref),
    case Result of
        {ok, Calls} ->
            Allowed = boundary_allowlist(AllowlistPath),
            Edges = boundary_edges(Calls, Allowed),
            report_boundary_edges(Edges);
        Error ->
            io:format(standard_error, "xref failed: ~p~n", [Error]),
            halt(1)
    end;
main(_) ->
    erlang:error(http3_ffi_xref_usage).

start_xref(Name) ->
    ok = code:add_paths(filelib:wildcard("build/dev/erlang/*/ebin")),
    {ok, Xref} = xref:start(Name),
    ok = xref:set_default(Xref, [{verbose, false}, {warnings, false}]),
    ok = xref:set_library_path(Xref, code:get_path()),
    Xref.

boundary_edges(Calls, Allowed) ->
    lists:usort([
        {From, To}
     || {{From, _, _}, {To, _, _}} <- Calls,
        is_root_module(From),
        is_private_core_module(To),
        not lists:member(root_module_source(From), Allowed)
    ]).

is_root_module(Module) ->
    Name = atom_to_list(Module),
    Name =:= "http3" orelse lists:prefix("http3@", Name).

is_private_core_module(Module) ->
    Name = atom_to_list(Module),
    lists:prefix("gleam_quic@internal@", Name) orelse
        lists:member(Name, [
            "gleam_quic@frame",
            "gleam_quic@packet",
            "gleam_quic@packet_number",
            "gleam_quic@stream_id",
            "gleam_quic@transport_parameter",
            "gleam_quic@varint",
            "gleam_quic@version"
        ]).

root_module_source(Module) ->
    Segments = string:split(atom_to_list(Module), "@", all),
    "src/" ++ lists:flatten(lists:join("/", Segments)) ++ ".gleam".

boundary_allowlist(Path) ->
    case file:read_file(Path) of
        {error, enoent} ->
            [];
        {error, Reason} ->
            erlang:error({cannot_read, Path, Reason});
        {ok, Contents} ->
            Lines = binary:split(Contents, <<"\n">>, [global]),
            lists:usort(lists:flatmap(fun allowlisted_source/1, Lines))
    end.

allowlisted_source(<<"#", _/binary>>) ->
    [];
allowlisted_source(<<>>) ->
    [];
allowlisted_source(Line) ->
    case binary:split(Line, <<"|">>) of
        [File, _Module] -> [binary_to_list(File)];
        _ -> erlang:error({malformed_boundary_allowlist_line, Line})
    end.

report_boundary_edges([]) ->
    io:format("root to core-internal call boundary ok~n");
report_boundary_edges(Edges) ->
    lists:foreach(
        fun({From, To}) ->
            io:format(
                standard_error,
                "~s calls package-private ~s~n",
                [From, To]
            )
        end,
        Edges
    ),
    io:format(
        standard_error,
        "boundary xref failed: ~b forbidden call edges from ~b root modules~n",
        [length(Edges), length(lists:usort([From || {From, _} <- Edges]))]
    ),
    halt(1).
