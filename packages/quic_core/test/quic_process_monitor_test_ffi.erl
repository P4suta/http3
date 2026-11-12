%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(quic_process_monitor_test_ffi).

-export([atomic_monitor_contract/0]).

atomic_monitor_contract() ->
    Parent = self(),
    Ref = make_ref(),
    {Worker, Monitor} = quic_core_process_ffi:spawn_monitor(fun() ->
        {monitored_by, Watchers} = process_info(self(), monitored_by),
        {links, Links} = process_info(self(), links),
        Parent ! {Ref, lists:member(Parent, Watchers),
                  not lists:member(Parent, Links)}
    end),
    Observation = receive
        {Ref, Monitored, NotLinked} -> {Monitored, NotLinked}
    after 1000 -> {false, false}
    end,
    Down = receive
        {'DOWN', Monitor, process, Worker, _} -> true
    after 1000 -> false
    end,
    {Observation, Down}.
