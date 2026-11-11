%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_server_contract_test_ffi).

-export([
    cancel_primitive_failures_are_closed/0,
    claim_once/1,
    new_once/0,
    resource_primitive_failures_are_typed/0
]).

-spec resource_primitive_failures_are_typed() -> boolean().
resource_primitive_failures_are_typed() ->
    Unavailable = http_server_ffi:new_resource_controller_with_factory(
        2, 64, fun() -> erlang:error(system_limit) end
    ),
    Invalid = http_server_ffi:new_resource_controller_with_factory(
        2, 64, fun() -> invalid_primitive end
    ),
    Controller = http_server_ffi:new_resource_controller(2, 64),
    LeaseFailure = http_server_ffi:resource_acquire_with_lease_factory(
        Controller, 32, fun() -> erlang:error(system_limit) end
    ),
    InvalidLeaseFailure = http_server_ffi:resource_acquire_with_lease_factory(
        Controller, 32, fun() -> invalid_primitive end
    ),
    AfterFailure = http_server_ffi:resource_snapshot(Controller),
    Recovered = http_server_ffi:resource_acquire(Controller, 32),
    case Recovered of
        {ok, Lease} ->
            nil = http_server_ffi:resource_release(Controller, Lease);
        {error, _Code} ->
            ok
    end,
    Final = http_server_ffi:resource_snapshot(Controller),
    UnavailableClosed =
        http_server_ffi:resource_acquire(Unavailable, 1) =:= {error, 3}
        andalso http_server_ffi:resource_snapshot(Unavailable) =:= {0, 0}
        andalso http_server_ffi:resource_stop(Unavailable) =:= nil,
    InvalidClosed =
        http_server_ffi:resource_acquire(Invalid, 1) =:= {error, 3}
        andalso http_server_ffi:resource_snapshot(Invalid) =:= {0, 0},
    UnavailableClosed andalso InvalidClosed
        andalso LeaseFailure =:= {error, 2}
        andalso InvalidLeaseFailure =:= {error, 2}
        andalso AfterFailure =:= {0, 0}
        andalso element(1, Recovered) =:= ok
        andalso Final =:= {0, 0}.

-spec cancel_primitive_failures_are_closed() -> boolean().
cancel_primitive_failures_are_closed() ->
    CheckedFailure =
        http_server_ffi:new_cancel_handle_checked_with_factories(
            fun() -> erlang:error(system_limit) end,
            fun(Work) -> spawn(Work) end
        ),
    StateFailure = http_server_ffi:new_cancel_handle_with_factories(
        fun() -> erlang:error(system_limit) end,
        fun(Work) -> spawn(Work) end
    ),
    SpawnFailure = http_server_ffi:new_cancel_handle_with_factories(
        fun() -> atomics:new(6, [{signed, false}]) end,
        fun(_Work) -> erlang:error(system_limit) end
    ),
    InvalidState = http_server_ffi:new_cancel_handle_with_factories(
        fun() -> invalid_primitive end,
        fun(Work) -> spawn(Work) end
    ),
    CheckedFailure =:= {error, nil} andalso lists:all(
        fun(Handle) ->
            http_server_ffi:is_cancelled(Handle) =:= true andalso
            http_server_ffi:mark_cancelled(Handle) =:= false andalso
            http_server_ffi:cancel_handle_snapshot(Handle) =:=
                {1, 1, 0, 0, 0, 0}
        end,
        [StateFailure, SpawnFailure, InvalidState]
    ).

-spec new_once() -> atomics:atomics_ref().
new_once() ->
    atomics:new(1, [{signed, false}]).

-spec claim_once(atomics:atomics_ref()) -> boolean().
claim_once(Once) ->
    try atomics:compare_exchange(Once, 1, 0, 1) of
        ok -> true;
        _ -> false
    catch
        _:_ -> false
    end.
