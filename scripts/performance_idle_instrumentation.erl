%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(performance_idle_instrumentation).
-export([prepare/1, self_test/1]).

%% The original receive expression is retained byte-for-byte in its abstract
%% form, including callback evaluation and timeout semantics. Only its local
%% function name changes. A wrapper emits a finite classification; no selector,
%% callback, delivered message, or return payload enters an observer mailbox.
prepare(Original) when is_binary(Original) ->
    try
        {ok, {gleam_erlang_ffi, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
            beam_lib:chunks(Original, [abstract_code]),
        [Select] = [F || F = {function, _, select, 2, _} <- Forms],
        [] = [F || F = {function, _, idle_observed_select, 2, _} <- Forms],
        true = normalized(Select) =:= normalized(expected_select()),
        Replacement = wrapper(),
        NewForms = lists:append([case F of
            {function, Line, select, 2, Clauses} ->
                [Replacement, {function, Line, idle_observed_select, 2, Clauses}];
            _ -> [F]
        end || F <- Forms]),
        {ok, gleam_erlang_ffi, Instrumented, []} = compile:forms(NewForms,
            [binary, debug_info, deterministic, return_errors, return_warnings]),
        {ok, Instrumented, #{
            schema => 1,
            method => <<"verified_select_ast_scalar_wrapper">>,
            original_beam_sha256 => digest(Original),
            instrumented_beam_sha256 => digest(Instrumented),
            select_ast_sha256 => digest(term_to_binary(normalized(Select), [deterministic])),
            receive_expression_unchanged => true,
            payloads_observed => false,
            added_timers => 0}}
    catch _:_ -> {error, unsupported_select_implementation} end;
prepare(_) -> {error, invalid_beam}.

expected_select() ->
    parse("select({selector, Handlers}, Timeout) -> "
        "AnythingHandler = maps:get(anything, Handlers, undefined), "
        "receive "
        "{'DOWN', Ref, _, _, _} = Message when is_map_key(Ref, Handlers) -> "
        "Fn = maps:get(Ref, Handlers), {ok, Fn(cast_down_message(Message))}; "
        "Msg when is_map_key({element(1, Msg), tuple_size(Msg)}, Handlers) -> "
        "Fn = maps:get({element(1, Msg), tuple_size(Msg)}, Handlers), {ok, Fn(Msg)}; "
        "Msg when AnythingHandler =/= undefined -> {ok, AnythingHandler(Msg)} "
        "after Timeout -> {error, nil} end.").

wrapper() ->
    parse("select(Selector, Timeout) -> "
        "http3_idle_wakeup_ffi:observe_enter(Timeout), "
        "Result = idle_observed_select(Selector, Timeout), "
        "case Result of "
        "{error, nil} -> http3_idle_wakeup_ffi:observe_leave(Timeout, timeout); "
        "{ok, _} -> http3_idle_wakeup_ffi:observe_leave(Timeout, message) "
        "end, Result.").

parse(Source) ->
    {ok, Tokens, _} = erl_scan:string(Source),
    {ok, Form} = erl_parse:parse_form(Tokens),
    Form.

normalized(Form) -> erl_parse:map_anno(fun(_) -> 0 end, Form).
digest(Bytes) -> binary:encode_hex(crypto:hash(sha256, Bytes)).

self_test(Original) ->
    {ok, Instrumented, Metadata} = prepare(Original),
    false = maps:get(payloads_observed, Metadata),
    0 = maps:get(added_timers, Metadata),
    {error, invalid_beam} = prepare(invalid),
    {error, unsupported_select_implementation} = prepare(<<0, 1, 2>>),
    %% Changing even the timeout-result branch invalidates the exact semantic
    %% contract rather than silently measuring a new dependency implementation.
    {ok, {gleam_erlang_ffi, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
        beam_lib:chunks(Original, [abstract_code]),
    Modified = [case F of
        {function, _, select, 2, _} -> parse("select(_, _) -> {error, changed}.");
        _ -> F
    end || F <- Forms],
    {ok, gleam_erlang_ffi, Changed, _} = compile:forms(Modified,
        [binary, debug_info, deterministic, return_errors, return_warnings]),
    {error, unsupported_select_implementation} = prepare(Changed),
    %% Execute the same real receive/callback controls before and after the
    %% rewrite. Results stay in the workload actor; its observer sees only the
    %% fixed event vocabulary, including when messages contain private bytes.
    {module, gleam_erlang_ffi} = code:load_binary(gleam_erlang_ffi, "original", Original),
    ok = behavior_controls(false),
    _ = code:purge(gleam_erlang_ffi),
    {module, gleam_erlang_ffi} = code:load_binary(gleam_erlang_ffi, "instrumented", Instrumented),
    try
        ok = http3_idle_wakeup_ffi:self_test(),
        ok = behavior_controls(true)
    after
        _ = code:purge(gleam_erlang_ffi),
        {module, gleam_erlang_ffi} = code:load_binary(gleam_erlang_ffi, "original", Original)
    end,
    ok.

behavior_controls(Observed) ->
    Parent = self(),
    {Actor, Monitor} = spawn_monitor(fun() ->
        receive run -> ok end,
        try
            Private = <<"idle-private-marker">>,
            {error, nil} = gleam_erlang_ffi:select({selector, #{}}, 0),
            self() ! {payload, Private},
            {ok, Private} = gleam_erlang_ffi:select({selector,
                #{{payload, 2} => fun({payload, Bytes}) ->
                    put(callback_calls, 1 + case get(callback_calls) of
                        undefined -> 0; Count -> Count end), Bytes end}}, 1000),
            1 = get(callback_calls),
            self() ! {private, Private},
            {ok, {private, Private}} = gleam_erlang_ffi:select(
                {selector, #{anything => fun(X) -> X end}}, 1000),
            self() ! {private, Private},
            {private, Private} = gleam_erlang_ffi:select(
                {selector, #{anything => fun(X) -> X end}}),
            Ref = make_ref(),
            Down = {'DOWN', Ref, process, self(), normal}, self() ! Down,
            Expected = gleam_erlang_ffi:cast_down_message(Down),
            {ok, Expected} = gleam_erlang_ffi:select(
                {selector, #{Ref => fun(X) -> X end}}, 1000),
            %% The wrapper does not catch, transform, or repeat callback errors.
            self() ! {private, Private},
            true = try gleam_erlang_ffi:select({selector,
                #{anything => fun(_) -> erlang:error({private, Private}) end}}, 1000) of
                    _ -> false
                catch error:{private, Private} -> true end,
            Parent ! {control, true}
        catch _:_ -> Parent ! {control, false} end,
        receive stop -> ok end
    end),
    Handle = http3_idle_observer:open(#{Actor => <<"http3.client">>}, Parent),
    try
        Actor ! run,
        receive {control, true} -> ok;
                {control, false} -> erlang:error(changed_select_behavior)
        after 3000 -> erlang:error(missing_behavior_control) end,
        true = http3_idle_observer:pause(Handle),
        Events = collect_events([]),
        ExpectedCount = case Observed of true -> 11; false -> 0 end,
        ExpectedCount = length(Events),
        true = lists:all(fun({idle_scalar, Pid, Operation, Class}) ->
            Pid =:= Actor andalso lists:member(Operation, [enter, timeout, message])
                andalso lists:member(Class, [zero, second, unbounded])
        end, Events),
        nomatch = binary:match(term_to_binary(Events), <<"idle-private-marker">>),
        #{events_sent := ExpectedCount, events_dropped := 0, invalid_events := 0}
            = http3_idle_observer:snapshot(Handle),
        ok
    after
        true = http3_idle_observer:close(Handle),
        Actor ! stop,
        receive {'DOWN', Monitor, process, Actor, normal} -> ok
        after 3000 -> exit(Actor, kill),
            receive {'DOWN', Monitor, process, Actor, _} -> ok end
        end
    end.

collect_events(Acc) ->
    receive {idle_scalar, _, _, _} = Event -> collect_events([Event | Acc])
    after 0 -> lists:reverse(Acc)
    end.
