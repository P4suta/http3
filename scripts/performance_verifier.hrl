%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PERFORMANCE_VERIFIER_HRL).
-define(HTTP_PERFORMANCE_VERIFIER_HRL, true).
performance_load_auditor() ->
    case compile:file("scripts/performance_audit.erl",
        [binary, deterministic, return_errors, return_warnings, {i, "scripts"}]) of
        {ok, performance_audit, Bytes, []} ->
            {module, performance_audit} = code:load_binary(performance_audit, "current-performance-auditor", Bytes),
            ok;
        _ -> erlang:error(performance_auditor_compile_failed)
    end.
-endif.
