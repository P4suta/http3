%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(performance_comparison_capture).
-export([run/3]).
-include("execution_identity.hrl").

run(Path,Nonce,Image)->
    Started=erlang:monotonic_time(millisecond),
    {ok,Capture}=performance_comparison_host:capture(Image),
    true=performance_comparison_host:validate_capture(Capture),
    Child=#{schema=>1,nonce=>Nonce,capture=>Capture,runtime=>execution_runtime(),
        elapsed_ms=>erlang:monotonic_time(millisecond)-Started},
    ok=file:write_file(Path,json:encode(Child),[exclusive]),
    halt(0).
