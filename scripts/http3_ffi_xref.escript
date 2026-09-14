#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

main([]) ->
    Xref = start_xref(http3_ffi_xref),
    Modules = production_ffi_beams(),
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

production_ffi_beams() ->
    {ok, Encoded} = file:read_file("qualification.json"),
    Manifest = json:decode(Encoded),
    Inventory = maps:get(<<"ffi_inventory">>, Manifest),
    1 = maps:get(<<"schema">>, Inventory),
    Sources = maps:get(<<"sources">>, Inventory),
    true = Sources =/= [],
    true = Sources =:= lists:usort(Sources),
    [production_ffi_beam(Source) || Source <- Sources].

production_ffi_beam(Source) when is_binary(Source) ->
    Path = binary_to_list(Source),
    Module = filename:basename(Path, ".erl") ++ ".beam",
    BuildRoot = case {
        lists:prefix("packages/http3/src/", Path),
        lists:prefix("packages/quic_core/src/", Path),
        lists:prefix("src/", Path)
    } of
        {true, _, _} -> "build/dev/erlang/http3/ebin";
        {_, true, _} ->
            "build/dev/erlang/quic_core/ebin";
        {_, _, true} -> "build/dev/erlang/http/ebin";
        _ -> erlang:error({unsupported_production_ffi_source, Source})
    end,
    filename:join(BuildRoot, Module);
production_ffi_beam(Source) ->
    erlang:error({invalid_production_ffi_source, Source}).

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
    Name =:= "http3" orelse
        lists:prefix("http3@", Name) orelse
        is_root_ffi_module(Name).

%% Root Erlang FFI modules (`http3_internal_transport_ffi`,
%% `http3_process_label_ffi`, and any other `http3_*_ffi`) are root callers too:
%% an FFI shim reaches the same package-private core modules that the Gleam
%% import gate rejects, and it carries no `@` separator to be caught above.
is_root_ffi_module(Name) ->
    lists:prefix("http3_", Name) andalso lists:suffix("_ffi", Name).

is_private_core_module(Module) ->
    Name = atom_to_list(Module),
    lists:prefix("quic_core@internal@", Name) orelse
        lists:member(Name, [
            "quic_core@frame",
            "quic_core@packet",
            "quic_core@packet_number",
            "quic_core@stream_id",
            "quic_core@transport_parameter",
            "quic_core@varint",
            "quic_core@version"
        ]).

root_module_source(Module) ->
    Segments = string:split(atom_to_list(Module), "@", all),
    "packages/http3/src/" ++
        lists:flatten(lists:join("/", Segments)) ++ ".gleam".

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
