%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_model_runtime).
-export([run/3]).

run(pool, Seed, Steps) -> pool(Seed, Steps);
run(cancellation, Seed, Steps) -> cancellation(Seed, Steps);
run(drain, Seed, _Steps) -> drain(Seed).

next(Seed) -> ((Seed + 1) * 48271) rem 2147483647.
check(true, _Step, _Code) -> ok;
check(false, Step, Code) -> throw({model_failure, Step, Code}).
deadline() -> erlang:monotonic_time(millisecond) + 1000.

pool(Seed, Steps) ->
    Lifecycle = http_client_ffi:new_lifecycle(4, 2, 60000),
    Owner = http_client_ffi:lifecycle_owner(Lifecycle),
    Monitor = monitor(process, Owner),
    try
        {Count, Entries} = pool_steps(Seed, Steps, 1, Lifecycle, #{}),
        1 = http_client_ffi:drain(Lifecycle),
        %% A FIFO message barrier makes idle-owner cleanup observable without
        %% guessing a scheduler delay. Active leases remain until close.
        check(http_client_ffi:reserve_resource(Lifecycle, <<"a">>) =:= {error, 1}, Count, 401),
        check(http_client_ffi:checkout_resource(Lifecycle, <<"a">>) =:= {error, 1}, Count, 402),
        nil = http_client_ffi:close(Lifecycle),
        await_down(Monitor, Owner, deadline(), Count, 403),
        lists:foreach(fun({_Id, {_Origin, _Lease, Pid, M, _State}}) ->
            await_down(M, Pid, deadline(), Count, 404)
        end, maps:to_list(Entries)),
        {Count + 3, {maps:size(Entries), http_client_ffi:state(Lifecycle)}}
    after
        http_client_ffi:close(Lifecycle),
        demonitor(Monitor, [flush])
    end.

pool_steps(_Seed, 0, Step, _Lifecycle, Entries) -> {Step - 1, Entries};
pool_steps(Seed, Remaining, Step, Lifecycle, Entries) ->
    Id = (Seed div 5) rem 8,
    Origin = case (Seed div 40) rem 2 of 0 -> <<"a">>; 1 -> <<"b">> end,
    Operation = Seed rem 5,
    Updated = case {Operation, maps:find(Id, Entries)} of
        {0, error} ->
            SameOrigin = length([ok || {O, _, _, _, _} <- maps:values(Entries), O =:= Origin]),
            Admitted = maps:size(Entries) < 4 andalso SameOrigin < 2,
            case http_client_ffi:reserve_resource(Lifecycle, Origin) of
                {ok, Lease} ->
                    check(Admitted, Step, 405),
                    {Pid, M} = spawn_monitor(fun idle/0),
                    {ok, nil} = http_client_ffi:attach_resource(Lease, Pid),
                    maps:put(Id, {Origin, Lease, Pid, M, active}, Entries);
                {error, 2} -> check(not Admitted, Step, 406), Entries;
                _ -> throw({model_failure, Step, 407})
            end;
        {1, {ok, {O, Lease, Pid, M, active}}} ->
            %% Unique cache keys remove an implementation-specific LIFO/FIFO
            %% choice from the oracle while still exercising reuse ownership.
            Key = <<O/binary, Id>>,
            check(http_client_ffi:checkin_resource(Lease, Key, Id), Step, 408),
            maps:put(Id, {O, Lease, Pid, M, idle}, Entries);
        {2, {ok, {O, Lease, Pid, M, Status}}} ->
            Expected = case Status of idle -> {ok, Id}; active -> {error, 0} end,
            check(http_client_ffi:checkout_resource(Lifecycle, <<O/binary, Id>>) =:= Expected,
                  Step, 409),
            maps:put(Id, {O, Lease, Pid, M, active}, Entries);
        {3, {ok, {_O, Lease, Pid, M, _}}} ->
            nil = http_client_ffi:cancel_resource(Lease),
            await_down(M, Pid, deadline(), Step, 410),
            %% Duplicate cancellation cannot free an unrelated live lease.
            nil = http_client_ffi:cancel_resource(Lease),
            maps:remove(Id, Entries);
        {4, _} ->
            check(http_client_ffi:state(Lifecycle) =:= 0, Step, 411),
            Entries;
        _ -> Entries
    end,
    check(maps:size(Updated) =< 4, Step, 412),
    pool_steps(next(Seed), Remaining - 1, Step + 1, Lifecycle, Updated).

idle() -> receive stop -> ok end.
await_down(Monitor, Pid, Deadline, Step, Code) ->
    receive {'DOWN', Monitor, process, Pid, _} -> ok
    after max(0, Deadline - erlang:monotonic_time(millisecond)) ->
        throw({model_failure, Step, Code})
    end.

cancellation(Seed, Steps) ->
    Handle = http_server_ffi:new_cancel_handle(),
    {http_cancel_handle, _, Broker} = Handle,
    Monitor = monitor(process, Broker),
    AnchorTag = make_ref(),
    Anchor = http_server_ffi:subscribe_cancel_handle(Handle, {subject, self(), AnchorTag}),
    try
        {Count, Cancelled, Notifications, Entries} =
            cancel_steps(Seed, Steps, 1, Handle, false, 0, #{}),
        _ = http_server_ffi:mark_cancelled(Handle),
        case Cancelled of
            false ->
                expect_notice(AnchorTag, Count),
                lists:foreach(fun({_Id, {Tag, _, active}}) -> expect_notice(Tag, Count);
                                 (_) -> ok end, maps:to_list(Entries));
            true -> ok
        end,
        await_down(Monitor, Broker, deadline(), Count, 501),
        lists:foreach(fun({_Id, {_Tag, Subscription, _}}) ->
            http_server_ffi:unsubscribe_cancel_handle(Subscription)
        end, maps:to_list(Entries)),
        nil = http_server_ffi:unsubscribe_cancel_handle(Anchor),
        {1, 1, 0, Actual, _, _} = http_server_ffi:cancel_handle_snapshot(Handle),
        Expected = case Cancelled of
            true -> Notifications;
            false -> Notifications + 1 + length([ok || {_, _, active} <- maps:values(Entries)])
        end,
        check(Actual =:= Expected, Count, 502),
        {Count + 1, {Actual, maps:size(Entries)}}
    after
        http_server_ffi:mark_cancelled(Handle),
        demonitor(Monitor, [flush])
    end.

cancel_steps(_Seed, 0, Step, _Handle, Cancelled, Notifications, Entries) ->
    {Step - 1, Cancelled, Notifications, Entries};
cancel_steps(Seed, Remaining, Step, Handle, Cancelled, Notifications, Entries) ->
    Id = (Seed div 4) rem 4,
    {C, N, Updated} = case {Seed rem 4, maps:find(Id, Entries)} of
        {0, error} ->
            Tag = make_ref(),
            Subscription = http_server_ffi:subscribe_cancel_handle(Handle, {subject, self(), Tag}),
            Status = case Cancelled of
                false -> active;
                true -> expect_notice(Tag, Step), notified
            end,
            {Cancelled, Notifications + bool(Cancelled), maps:put(Id, {Tag, Subscription, Status}, Entries)};
        {1, {ok, {_Tag, Subscription, _}}} ->
            nil = http_server_ffi:unsubscribe_cancel_handle(Subscription),
            nil = http_server_ffi:unsubscribe_cancel_handle(Subscription),
            {Cancelled, Notifications, maps:remove(Id, Entries)};
        {2, _} ->
            First = http_server_ffi:mark_cancelled(Handle),
            check(First =:= not Cancelled, Step, 503),
            Added = case Cancelled of
                true -> 0;
                false -> 1 + length([ok || {_, _, active} <- maps:values(Entries)])
            end,
            %% The cancellation broker may schedule after this caller. Its
            %% fixed scalar snapshot is the synchronization barrier.
            await_notifications(Handle, Notifications + Added, deadline(), Step),
            case Cancelled of
                true -> ok;
                false ->
                    %% Anchor notice is included in the count; drain all
                    %% cancellation-only messages owned by this case.
                    receive_notices(Added, Step)
            end,
            Marked = maps:map(fun(_, {T, S, _}) -> {T, S, notified} end, Entries),
            {true, Notifications + Added, Marked};
        _ -> {Cancelled, Notifications, Entries}
    end,
    check(http_server_ffi:is_cancelled(Handle) =:= C, Step, 504),
    cancel_steps(next(Seed), Remaining - 1, Step + 1, Handle, C, N, Updated).

bool(true) -> 1;
bool(false) -> 0.
expect_notice(Tag, Step) ->
    receive {Tag, nil} -> ok after 1000 -> throw({model_failure, Step, 505}) end,
    receive {Tag, nil} -> throw({model_failure, Step, 506}) after 0 -> ok end.
receive_notices(0, _) -> ok;
receive_notices(N, Step) ->
    receive {Tag, nil} when is_reference(Tag) -> receive_notices(N - 1, Step)
    after 1000 -> throw({model_failure, Step, 507}) end.
await_notifications(Handle, Expected, Deadline, Step) ->
    case http_server_ffi:cancel_handle_snapshot(Handle) of
        {1, 1, 0, Expected, _, _} -> ok;
        _ ->
            check(erlang:monotonic_time(millisecond) < Deadline, Step, 508),
            receive after 1 -> await_notifications(Handle, Expected, Deadline, Step) end
    end.

drain(Seed) ->
    Capacity = 1 + Seed rem 3,
    {ok, Limits} = 'http@resource':limits(Capacity, 4096),
    {ok, Config0} = 'http@server':with_resource_limits('http@server':defaults(), Limits, 128),
    {ok, Config} = 'http@server':with_drain_timeout(Config0, 1000),
    Releases = atomics:new(1, [{signed, false}]),
    Handler = fun(_, _) ->
        Pull = 'http@body':pull(fun(_) -> {ok, {pull_end, []}} end),
        {ok, Body} = 'http@body':from_pull(Pull, none, none,
            fun() -> atomics:add(Releases, 1, 1), nil end),
        {ok, 'gleam@http@response':set_body('gleam@http@response':new(200), Body)}
    end,
    {ok, Server} = 'http@server':start(Config, Handler),
    try
        Bodies = [admit(Server, Index) || Index <- lists:seq(1, Capacity)],
        {Rejected, RejectedContext} = attempt(Server),
        check(is_error(Rejected), 1, 601),
        'http@context':cancel(RejectedContext),
        Parent = self(), Tag = make_ref(),
        {Drainer, Monitor} = spawn_monitor(fun() -> Parent ! {Tag, 'http@server':drain(Server)} end),
        await_draining(Server, deadline()),
        {AfterDrain, AfterContext} = attempt(Server),
        check(is_error(AfterDrain), 2, 602),
        'http@context':cancel(AfterContext),
        Order = case Seed rem 2 of 0 -> Bodies; 1 -> lists:reverse(Bodies) end,
        lists:foldl(fun({Body, Context}, Released) ->
            %% The independent admitted-work ledger is nonempty here.
            receive {Tag, _} -> throw({model_failure, Released + 3, 603}) after 0 -> ok end,
            case (Seed + Released) rem 2 of
                0 -> 'http@body':cancel(Body);
                1 ->
                    check(is_ok('http@body':read_all(Body, 256)), Released + 3, 604),
                    %% EOF alone does not certify delivery. Model the adapter's
                    %% successful final write before disposing its body.
                    receive {Tag, _} -> throw({model_failure, Released + 3, 613}) after 0 -> ok end,
                    'http@body':transfer_finished(Body, {ok, nil}),
                    'http@body':cancel(Body)
            end,
            case 'http@body':await_release(Body, 1000) of
                {released, {ok, nil}} -> ok;
                {released, {error, Failure}} ->
                    throw({model_failure, Released + 3, 605, 'http@error':kind(Failure)});
                release_pending -> throw({model_failure, Released + 3, 605, pending})
            end,
            'http@body':cancel(Body),
            'http@context':cancel(Context),
            case atomics:get(Releases, 1) of
                Actual when Actual =:= Released + 1 -> ok;
                Actual -> throw({model_failure, Released + 3, 606, Released + 1, Actual})
            end,
            Released + 1
        end, 0, Order),
        receive {Tag, Result} -> check(Result =:= {ok, nil}, Capacity + 3, 607)
        after 1000 -> throw({model_failure, Capacity + 3, 608}) end,
        await_down(Monitor, Drainer, deadline(), Capacity + 3, 609),
        {ok, nil} = 'http@server':stop(Server),
        check('http@server':state(Server) =:= stopped, Capacity + 4, 610),
        {Capacity + 4, {Capacity, atomics:get(Releases, 1)}}
    after 'http@server':stop(Server) end.

admit(Server, Step) ->
    {Result, Context} = attempt(Server),
    case Result of
        {ok, {response, 200, _, Body}} -> {Body, Context};
        _ -> throw({model_failure, Step, 611})
    end.
attempt(Server) ->
    {ok, Context} = 'http@context':new(http1,
        {endpoint, <<"127.0.0.1">>, 50000}, {endpoint, <<"127.0.0.1">>, 8080},
        5000, cleartext_identity, early_data_disabled),
    Request = 'gleam@http@request':set_body('gleam@http@request':new(), 'http@body':empty()),
    {'http@server':handle(Server, Request, Context), Context}.
await_draining(Server, Deadline) ->
    case 'http@server':state(Server) of
        draining -> ok;
        _ ->
            check(erlang:monotonic_time(millisecond) < Deadline, 2, 612),
            receive after 1 -> await_draining(Server, Deadline) end
    end.
is_ok({ok, _}) -> true;
is_ok(_) -> false.
is_error({error, _}) -> true;
is_error(_) -> false.
