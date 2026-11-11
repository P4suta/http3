%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_multiplexing_controls).
-export([run/0]).
-compile(nowarn_unused_function).
-include("process_runner.hrl").

-spec run() -> boolean().
run() ->
    Root = filename:absname("."),
    Paths = filelib:wildcard(filename:join([Root, "build", "dev", "erlang", "*", "ebin"])),
    Evaluation =
        "{ok,_}=application:ensure_all_started(http),"
        "case http3_client_adapter_test:observe_http3_multiplexing() of "
        "multiplexed->halt(0);"
        "{unexpected_finite_phase,Phase}->"
        "io:format(\"multiplexing_phase=~B~n\","
        "[http3_client_adapter_test:multiplexing_phase_code(Phase)]),halt(1);"
        "_->halt(1) end.",
    try run_child_evaluation(Root, Paths, Evaluation, 30000) of
        {Status, Output} ->
            process_status_verified(Status, 0, Output) andalso
                maps:get(output_bytes, Output) =:= 0
    catch _:_ -> false
    end.
