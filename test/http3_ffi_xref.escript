#!/usr/bin/env escript

main([]) ->
    Paths = filelib:wildcard("build/dev/erlang/*/ebin"),
    ok = code:add_paths(Paths),
    {ok, Xref} = xref:start(http3_ffi_xref),
    ok = xref:set_default(Xref, [{verbose, false}, {warnings, false}]),
    ok = xref:set_library_path(Xref, code:get_path()),
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
main(_) ->
    erlang:error(http3_ffi_xref_usage).
