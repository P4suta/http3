%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(quic_core_process_ffi).

-export([spawn_monitor/1]).

-spec spawn_monitor(fun(() -> term())) -> {pid(), reference()}.
spawn_monitor(Fun) when is_function(Fun, 0) ->
    erlang:spawn_monitor(Fun).
