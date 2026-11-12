#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-mode(compile).

%% The isolated VM substitutes only the public event/drain boundary. The real
%% peer runs still compile these fixtures against the native package modules.
main([]) ->
    load_stub('http3@client', [
        "-export([next_event/1]).",
        "next_event(_) -> [Event | Rest] = get(events), put(events, Rest), Event."
    ]),
    load_stub('http3@server', [
        "-export([graceful_stop/1]).",
        "graceful_stop(_) -> get(drain_result)."
    ]),
    Modules = [http3_quicgo_interop, http3_phase4_interop],
    lists:foreach(fun(Module) ->
        Path = filename:join(["packages/http3/test/interop", atom_to_list(Module) ++ ".erl"]),
        {ok, Module, Binary} = compile:file(Path, [binary, export_all, return_errors]),
        {module, Module} = code:load_binary(Module, "isolated-interoperability-fixture", Binary)
    end, Modules),
    Cases = lists:append([body_cases(Module) || Module <- Modules]) ++ [
        {drained_is_complete, fun() ->
            put(drain_result, {ok, drained}),
            ok = http3_quicgo_interop:finish_listener(unused)
        end},
        {forced_is_incomplete, fun() ->
            put(drain_result, {ok, forced}),
            true = rejected(fun() -> http3_quicgo_interop:finish_listener(unused) end)
        end},
        {failed_drain_is_incomplete, fun() ->
            put(drain_result, {error, private_failure_marker}),
            true = rejected(fun() -> http3_quicgo_interop:finish_listener(unused) end)
        end}
    ],
    Results = [#{test => atom_to_binary(Name), passed => not rejected(Check)}
               || {Name, Check} <- Cases],
    io:format("~s~n", [json:encode(#{tests => Results})]),
    case lists:all(fun(#{passed := Passed}) -> Passed end, Results) of
        true -> ok;
        false -> halt(1)
    end;
main(_) -> halt(2).

body_cases(Module) -> [
    {bounded_body_is_accepted, fun() ->
        Body = binary:copy(<<1>>, 131072),
        put(events, [{ok, {response, 200, []}}, {ok, {data, Body}}, {ok, 'end'}]),
        {200, [], Body} = Module:collect(unused)
    end},
    {oversized_chunk_is_refused, fun() ->
        put(events, [{ok, {data, binary:copy(<<1>>, 131073)}}, {ok, 'end'}]),
        true = rejected(fun() -> Module:collect(unused) end)
    end},
    {accumulated_body_is_bounded, fun() ->
        Chunk = {ok, {data, binary:copy(<<1>>, 65536)}},
        put(events, [Chunk, Chunk, Chunk, {ok, 'end'}]),
        true = rejected(fun() -> Module:collect(unused) end)
    end},
    {empty_events_cannot_extend_work_forever, fun() ->
        put(events, lists:duplicate(5000, {ok, {data, <<>>}}) ++ [{ok, 'end'}]),
        true = rejected(fun() -> Module:collect(unused) end)
    end}
].

load_stub(Module, Texts) ->
    Forms = [parse_form("-module('" ++ atom_to_list(Module) ++ "').") |
             [parse_form(Text) || Text <- Texts]],
    {ok, Module, Binary} = compile:forms(Forms, [binary, return_errors]),
    {module, Module} = code:load_binary(Module, "isolated-public-boundary-stub", Binary).

parse_form(Text) ->
    {ok, Tokens, _} = erl_scan:string(Text),
    {ok, Form} = erl_parse:parse_form(Tokens),
    Form.

rejected(Check) ->
    try Check(), false catch _:_ -> true end.
