#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("diagnostic_failure.hrl").
main(Arguments) ->
    try
        {ok, performance_host, Bytes, []} = compile:file("scripts/performance_host.erl",
            [binary, deterministic, return_errors, return_warnings]),
        {module, performance_host} = code:load_binary(performance_host, "performance_host.beam", Bytes),
        case Arguments of
            ["--self-test"] -> performance_host:self_test();
            ["capture", Label, Path] when Label =:= "start"; Label =:= "end" ->
                Snapshot = performance_host:capture(list_to_binary(Label)),
                ok = filelib:ensure_dir(Path),
                ok = file:write_file(Path, [json:encode(Snapshot), $\n]);
            _ -> halt(2)
        end
    catch Class:Reason:Stack ->
        io:format(standard_error, "host snapshot failed: ~s~n",
            [json:encode(diagnostic_failure_details(Class, Reason, Stack))]), halt(1)
    end.
