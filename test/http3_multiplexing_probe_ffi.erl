%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http3_multiplexing_probe_ffi).

-export([
    fixture_role_count/0,
    fixture_roles_clear/0,
    registry_census_controls/0,
    with_unrelated_fixture/1,
    isolated_fixture_contract/0,
    is_request_reaper/1,
    same_connection/2
]).

-spec same_connection(term(), term()) -> boolean().
same_connection(First, Second) ->
    'http3@server':same_connection(First, Second).

-spec with_unrelated_fixture(fun(() -> boolean())) -> boolean().
with_unrelated_fixture(Contract) ->
    Root = self(), Tag = make_ref(),
    {Fixture, Monitor} = spawn_monitor(fun() ->
        ok = proc_lib:set_label(<<"http.client_connection_candidate">>),
        Root ! {Tag, ready},
        receive stop -> ok end
    end),
    try
        receive {Tag, ready} -> Contract()
            after 1000 -> error(fixture_start_timeout) end
    after
        exit(Fixture, kill),
        receive {'DOWN', Monitor, process, Fixture, _} -> ok
            after 1000 -> error(fixture_stop_timeout) end
    end.

-spec isolated_fixture_contract() -> boolean().
isolated_fixture_contract() ->
    {ok, http3_multiplexing_controls, Beam, []} = compile:file(
        "scripts/http3_multiplexing_controls.erl",
        [binary, return_errors, return_warnings, {i, "scripts"}]),
    {module, http3_multiplexing_controls} = code:load_binary(
        http3_multiplexing_controls, "scripts/http3_multiplexing_controls.erl", Beam),
    http3_multiplexing_controls:run().

-spec is_request_reaper(pid()) -> boolean().
is_request_reaper(Pid) when is_pid(Pid) ->
    process_info(Pid, label) =:= {label, <<"http.http3_request_reaper">>};
is_request_reaper(_Pid) -> false.

-spec fixture_roles_clear() -> boolean().
fixture_roles_clear() ->
    Deadline = erlang:monotonic_time(millisecond) + 2000,
    await_fixture_roles_clear(Deadline).

-spec fixture_role_count() -> non_neg_integer().
fixture_role_count() ->
    length([ok || Pid <- processes(), has_fixture_role(Pid)]).

-spec await_fixture_roles_clear(integer()) -> boolean().
await_fixture_roles_clear(Deadline) ->
    case fixture_role_count() of
        0 -> true;
        _ ->
            Remaining = Deadline - erlang:monotonic_time(millisecond),
            case Remaining =< 0 of
                true -> false;
                false ->
                    receive after min(10, Remaining) -> ok end,
                    await_fixture_roles_clear(Deadline)
            end
    end.

-spec has_fixture_role(pid()) -> boolean().
has_fixture_role(Pid) ->
    case process_info(Pid, label) of
        {label, <<"http.body_recovery_registry">>} ->
            process_info(Pid, monitors) =/= {monitors, []};
        {label, Label} when is_binary(Label) -> fixture_label(Label);
        _ -> false
    end.

-spec registry_census_controls() -> boolean().
registry_census_controls() ->
    Root = self(), Tag = make_ref(),
    {Registry, Monitor} = spawn_monitor(fun() ->
        ok = proc_lib:set_label(<<"http.body_recovery_registry">>),
        Root ! {Tag, idle},
        receive monitor_root ->
            _ = monitor(process, Root),
            Root ! {Tag, active},
            receive stop -> ok end
        end
    end),
    try
        receive {Tag, idle} -> ok after 1000 -> error(registry_start_timeout) end,
        Idle = has_fixture_role(Registry),
        Registry ! monitor_root,
        receive {Tag, active} -> ok after 1000 -> error(registry_monitor_timeout) end,
        Idle =:= false andalso has_fixture_role(Registry)
    after
        exit(Registry, kill),
        receive {'DOWN', Monitor, process, Registry, _} -> ok
            after 1000 -> error(registry_stop_timeout) end
    end.

-spec fixture_label(binary()) -> boolean().
fixture_label(<<"http.", _/binary>>) -> true;
fixture_label(<<"http3.", _/binary>>) -> true;
fixture_label(<<"quic_core.", _/binary>>) -> true;
fixture_label(_) -> false.
