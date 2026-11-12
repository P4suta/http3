%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_client_lifecycle_close_test).
-export([
    confirmed_graceful_idle_resource_owner_join/0,
    confirmed_idle_resource_owner_join/0,
    concurrent_idle_resource_owner_join/0,
    timed_out_graceful_idle_resource_owner_join/0,
    unconfirmed_idle_resource_owner_join/0
]).

-define(TEST_DEADLINE_MILLISECONDS, 1000).

confirmed_graceful_idle_resource_owner_join() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 3000),
    Parent = self(),
    Tag = make_ref(),
    ResourceOwner = spawn(fun() -> graceful_idle(Parent, Tag) end),
    ResourceMonitor = monitor(process, ResourceOwner),
    CloseHandle = http_client_ffi:new_http3_close_handle(
        {subject, ResourceOwner, Tag}
    ),
    {ok, Registration} = http_client_ffi:reserve_resource(
        Lifecycle, <<"origin">>
    ),
    {ok, nil} = http_client_ffi:attach_http3_resource(
        Registration, ResourceOwner, CloseHandle
    ),
    true = http_client_ffi:checkin_resource(
        Registration, <<"h3|origin|443">>, pooled_connection
    ),
    Result = http_client_ffi:close_before(
        Lifecycle,
        erlang:monotonic_time(millisecond) + ?TEST_DEADLINE_MILLISECONDS,
        true
    ),
    CloseHandled = receive
        {Tag, close_handled} -> true
    after ?TEST_DEADLINE_MILLISECONDS ->
        false
    end,
    OwnerJoined = await_down(
        ResourceOwner, ResourceMonitor, ?TEST_DEADLINE_MILLISECONDS
    ),
    Repeated = http_client_ffi:close_before(
        Lifecycle,
        erlang:monotonic_time(millisecond) + ?TEST_DEADLINE_MILLISECONDS,
        true
    ),
    {Result, CloseHandled, OwnerJoined, Repeated}.

timed_out_graceful_idle_resource_owner_join() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 3000),
    Parent = self(),
    Tag = make_ref(),
    ResourceOwner = spawn(fun() -> stalled_graceful_idle(Parent, Tag) end),
    ResourceMonitor = monitor(process, ResourceOwner),
    CloseHandle = http_client_ffi:new_http3_close_handle(
        {subject, ResourceOwner, Tag}
    ),
    {ok, Registration} = http_client_ffi:reserve_resource(
        Lifecycle, <<"origin">>
    ),
    {ok, nil} = http_client_ffi:attach_http3_resource(
        Registration, ResourceOwner, CloseHandle
    ),
    true = http_client_ffi:checkin_resource(
        Registration, <<"h3|origin|443">>, pooled_connection
    ),
    Result = http_client_ffi:close_before(
        Lifecycle,
        erlang:monotonic_time(millisecond) + 100,
        true
    ),
    CloseHandled = receive
        {Tag, close_handled} -> true
    after ?TEST_DEADLINE_MILLISECONDS ->
        false
    end,
    OwnerJoined = await_down(
        ResourceOwner, ResourceMonitor, ?TEST_DEADLINE_MILLISECONDS
    ),
    Repeated = await_close(Lifecycle, ?TEST_DEADLINE_MILLISECONDS),
    {Result, CloseHandled, OwnerJoined, Repeated}.

confirmed_idle_resource_owner_join() ->
    Lifecycle = http_client_ffi:new_lifecycle(2, 2, 3000),
    {FirstOwner, FirstMonitor} = pooled_idle_resource(
        Lifecycle, <<"first-origin">>, <<"h3|first-origin|443">>
    ),
    {SecondOwner, SecondMonitor} = pooled_idle_resource(
        Lifecycle, <<"second-origin">>, <<"h3|second-origin|443">>
    ),
    Result = http_client_ffi:close_before(
        Lifecycle,
        erlang:monotonic_time(millisecond) + ?TEST_DEADLINE_MILLISECONDS,
        true
    ),
    OwnersJoined = await_down(
        FirstOwner, FirstMonitor, ?TEST_DEADLINE_MILLISECONDS
    ) andalso await_down(
        SecondOwner, SecondMonitor, ?TEST_DEADLINE_MILLISECONDS
    ),
    Repeated = http_client_ffi:close_before(
        Lifecycle,
        erlang:monotonic_time(millisecond) + ?TEST_DEADLINE_MILLISECONDS,
        true
    ),
    {Result, OwnersJoined, Repeated}.

concurrent_idle_resource_owner_join() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 3000),
    {ResourceOwner, ResourceMonitor} = pooled_idle_resource(
        Lifecycle, <<"origin">>, <<"h3|origin|443">>
    ),
    Parent = self(),
    Start = make_ref(),
    FirstTag = make_ref(),
    SecondTag = make_ref(),
    First = spawn_close(Parent, Start, FirstTag, Lifecycle),
    Second = spawn_close(Parent, Start, SecondTag, Lifecycle),
    First ! Start,
    Second ! Start,
    FirstResult = receive_result(FirstTag),
    SecondResult = receive_result(SecondTag),
    OwnerJoined = await_down(
        ResourceOwner, ResourceMonitor, ?TEST_DEADLINE_MILLISECONDS
    ),
    Repeated = http_client_ffi:close_before(
        Lifecycle,
        erlang:monotonic_time(millisecond) + ?TEST_DEADLINE_MILLISECONDS,
        true
    ),
    {FirstResult, SecondResult, OwnerJoined, Repeated}.

unconfirmed_idle_resource_owner_join() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 3000),
    {ResourceOwner, ResourceMonitor} = pooled_idle_resource(
        Lifecycle, <<"origin">>, <<"h3|origin|443">>
    ),
    First = http_client_ffi:close_before(
        Lifecycle,
        erlang:monotonic_time(millisecond) + ?TEST_DEADLINE_MILLISECONDS,
        false
    ),
    OwnerJoined = await_down(
        ResourceOwner, ResourceMonitor, ?TEST_DEADLINE_MILLISECONDS
    ),
    Second = await_close(Lifecycle, ?TEST_DEADLINE_MILLISECONDS),
    Third = http_client_ffi:close_before(
        Lifecycle,
        erlang:monotonic_time(millisecond) + ?TEST_DEADLINE_MILLISECONDS,
        true
    ),
    {First, OwnerJoined, Second, Third}.

pooled_idle_resource(Lifecycle, Origin, Key) ->
    ResourceOwner = spawn(fun idle/0),
    ResourceMonitor = monitor(process, ResourceOwner),
    {ok, Registration} = http_client_ffi:reserve_resource(
        Lifecycle, Origin
    ),
    {ok, nil} = http_client_ffi:attach_resource(
        Registration, ResourceOwner
    ),
    true = http_client_ffi:checkin_resource(
        Registration, Key, pooled_connection
    ),
    {ResourceOwner, ResourceMonitor}.

spawn_close(Parent, Start, Tag, Lifecycle) ->
    spawn(fun() ->
        receive Start -> ok end,
        Result = http_client_ffi:close_before(
            Lifecycle,
            erlang:monotonic_time(millisecond)
                + ?TEST_DEADLINE_MILLISECONDS,
            true
        ),
        Parent ! {Tag, Result}
    end).

receive_result(Tag) ->
    receive
        {Tag, Result} -> Result
    after ?TEST_DEADLINE_MILLISECONDS ->
        {error, timeout}
    end.

await_close(Lifecycle, Remaining) when Remaining > 0 ->
    case http_client_ffi:close_before(
        Lifecycle,
        erlang:monotonic_time(millisecond) + 10,
        true
    ) of
        {error, _} ->
            receive after 1 -> await_close(Lifecycle, Remaining - 1) end;
        Result -> Result
    end;
await_close(_Lifecycle, 0) ->
    {error, timeout}.

await_down(ResourceOwner, ResourceMonitor, Timeout) ->
    receive
        {'DOWN', ResourceMonitor, process, ResourceOwner, _Reason} -> true
    after Timeout ->
        false
    end.

idle() ->
    receive
        stop -> ok
    end.

graceful_idle(Parent, Tag) ->
    receive
        {Tag, {close, Deadline}} when is_integer(Deadline) ->
            Parent ! {Tag, close_handled},
            ok
    end.

stalled_graceful_idle(Parent, Tag) ->
    receive
        {Tag, {close, Deadline}} when is_integer(Deadline) ->
            Parent ! {Tag, close_handled},
            idle()
    end.
