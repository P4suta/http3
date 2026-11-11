#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("diagnostic_failure.hrl").
-include("hot_path_verifier.hrl").
main(Arguments) ->
    Root=filename:dirname(filename:dirname(filename:absname(escript:script_name()))),
    ok=file:set_cwd(Root),
    try
        hpp_load_auditor(), hot_path_profile:main(Arguments)
    catch Class:Reason:Stack ->
        io:format(standard_error,"hot-path audit failed: ~s~n",[json:encode(diagnostic_failure_details(Class,Reason,Stack))]),
        halt(1)
    end.
