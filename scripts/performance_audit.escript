#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("diagnostic_failure.hrl").
-include("performance_verifier.hrl").
main(Arguments) ->
    Root = filename:dirname(filename:dirname(filename:absname(escript:script_name()))),
    ok = file:set_cwd(Root),
    try
        performance_load_auditor(),
        performance_audit:main(Arguments)
    catch Class:Reason:Stack ->
        io:format(standard_error, "performance audit failed: ~s~n",
            [json:encode(diagnostic_failure_details(Class, Reason, Stack))]),
        halt(1)
    end.
