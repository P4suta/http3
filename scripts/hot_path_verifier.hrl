%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_HOT_PATH_VERIFIER_HRL).
-define(HTTP_HOT_PATH_VERIFIER_HRL, true).
hpp_load_auditor() ->
    case compile:file("scripts/hot_path_profile.erl",
        [binary, deterministic, return_errors, return_warnings, {i, "scripts"}]) of
        {ok, hot_path_profile, Bytes, []} ->
            {module, hot_path_profile} = code:load_binary(hot_path_profile, "current-hot-path-auditor", Bytes),
            ok;
        _ -> erlang:error(hot_path_auditor_compile_failed)
    end.
-endif.
