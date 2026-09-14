%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_client_ffi).

-export([
    checkin_socket/3,
    checkin_http2/5,
    call_https_resolver/4,
    call_policy_adapter/2,
    cancel_race/1,
    claim_connection_close/1,
    checkout_socket/2,
    checkout_http2/2,
    close/1,
    close_http2_pool/1,
    close_policy_store/1,
    drain/1,
    drain_http2_pool/1,
    is_closed/1,
    mark_connection_released/1,
    new_connection_guard/0,
    new_http2_pool/3,
    new_lifecycle/3,
    new_policy_store/2,
    new_race_cancellation/0,
    policy_store_get/3,
    policy_store_list/2,
    policy_store_put/6,
    register_socket/3,
    race_cancelled/1,
    state/1,
    unregister_socket/1
]).

-define(OWNER_TIMEOUT, 10000).
-type lifecycle() :: #{state := atomics:atomics_ref(), owner := pid()}.
-type registration() :: {http_client_registration, pid(), reference()}.
-type registered_socket() :: {reference(), binary(), term()}.
-type pooled_socket() :: {binary(), reference(), term(), integer()}.
-type pool_limits() :: {pos_integer(), pos_integer(), pos_integer()}.
-type http2_pool() :: #{state := atomics:atomics_ref(), owner := pid()}.
-type cleanup() :: fun(() -> term()).
-type http2_session() :: {binary(), term(), term(), cleanup(), integer()}.
-type policy_store() :: #{state := atomics:atomics_ref(), owner := pid()}.
-type policy_item() :: {binary(), binary(), term(), integer(), pos_integer()}.

-spec call_policy_adapter(fun(), pos_integer()) ->
    {ok, term()} | {error, integer()}.
call_policy_adapter(Run, TimeoutMilliseconds)
    when is_function(Run, 0), TimeoutMilliseconds > 0,
         TimeoutMilliseconds =< 2147483647 ->
    Parent = self(),
    Reference = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Outcome = try Run() of
            {ok, Value} -> {ok, Value};
            _ -> {error, 1}
        catch
            _Class:_Reason -> {error, 1}
        end,
        Parent ! {Reference, Outcome}
    end),
    receive
        {Reference, Outcome} ->
            erlang:demonitor(Monitor, [flush]),
            Outcome;
        {'DOWN', Monitor, process, Worker, _Reason} ->
            {error, 1}
    after TimeoutMilliseconds ->
        exit(Worker, kill),
        erlang:demonitor(Monitor, [flush]),
        {error, 2}
    end;
call_policy_adapter(_Run, _TimeoutMilliseconds) ->
    {error, 1}.

-spec call_https_resolver(fun(), binary(), integer(), pos_integer()) ->
    {ok, [term()]} | {error, integer()}.
call_https_resolver(Resolver, Host, Port, TimeoutMilliseconds)
    when is_function(Resolver, 3), is_binary(Host),
         Port > 0, Port =< 65535,
         TimeoutMilliseconds > 0, TimeoutMilliseconds =< 2147483647 ->
    Parent = self(),
    Reference = make_ref(),
    {Worker, Monitor} = spawn_monitor(fun() ->
        Outcome = try Resolver(Host, Port, TimeoutMilliseconds) of
            {ok, Records} when is_list(Records) -> {ok, Records};
            _ -> {error, 1}
        catch
            _Class:_Reason -> {error, 1}
        end,
        Parent ! {Reference, Outcome}
    end),
    receive
        {Reference, Outcome} ->
            erlang:demonitor(Monitor, [flush]),
            Outcome;
        {'DOWN', Monitor, process, Worker, _Reason} ->
            {error, 1}
    after TimeoutMilliseconds ->
        exit(Worker, kill),
        erlang:demonitor(Monitor, [flush]),
        {error, 2}
    end;
call_https_resolver(_Resolver, _Host, _Port, _TimeoutMilliseconds) ->
    {error, 1}.

-spec new_policy_store(integer(), integer()) -> policy_store().
new_policy_store(MaximumEntries, MaximumBytes)
    when MaximumEntries > 0, MaximumEntries =< 65536,
         MaximumBytes > 0, MaximumBytes =< 67108864 ->
    State = atomics:new(1, [{signed, false}]),
    Owner = spawn(fun() ->
        policy_store_loop(State, [], MaximumEntries, MaximumBytes)
    end),
    #{state => State, owner => Owner};
new_policy_store(_MaximumEntries, _MaximumBytes) ->
    new_policy_store(1, 1).

-spec policy_store_put(
    policy_store(), binary(), binary(), term(), integer(), integer()
) -> boolean().
policy_store_put(
    #{state := State, owner := Owner},
    Partition,
    Key,
    Value,
    ExpiresAt,
    RetainedBytes
) when is_binary(Partition), is_binary(Key),
       is_integer(ExpiresAt), RetainedBytes > 0 ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            Owner ! {
                policy_put,
                self(),
                Reference,
                Partition,
                Key,
                Value,
                ExpiresAt,
                RetainedBytes
            },
            receive
                {Reference, Stored} when is_boolean(Stored) -> Stored
            after ?OWNER_TIMEOUT ->
                false
            end;
        _ -> false
    end;
policy_store_put(_Store, _Partition, _Key, _Value, _ExpiresAt, _Bytes) ->
    false.

-spec policy_store_list(policy_store(), binary()) -> [term()].
policy_store_list(#{state := State, owner := Owner}, Partition)
    when is_binary(Partition) ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            Owner ! {policy_list, self(), Reference, Partition},
            receive
                {Reference, Values} when is_list(Values) -> Values
            after ?OWNER_TIMEOUT ->
                []
            end;
        _ -> []
    end;
policy_store_list(_Store, _Partition) ->
    [].

-spec policy_store_get(policy_store(), binary(), binary()) ->
    {ok, term()} | {error, integer()}.
policy_store_get(#{state := State, owner := Owner}, Partition, Key)
    when is_binary(Partition), is_binary(Key) ->
    case safe_state(State) of
        0 ->
            Reference = make_ref(),
            Owner ! {policy_get, self(), Reference, Partition, Key},
            receive
                {Reference, {ok, Value}} -> {ok, Value};
                {Reference, missing} -> {error, 0}
            after ?OWNER_TIMEOUT ->
                {error, 1}
            end;
        _ -> {error, 1}
    end;
policy_store_get(_Store, _Partition, _Key) ->
    {error, 1}.

-spec close_policy_store(policy_store()) -> nil.
close_policy_store(#{state := State, owner := Owner}) ->
    case atomics:exchange(State, 1, 1) of
        0 ->
            Reference = make_ref(),
            Owner ! {policy_close, self(), Reference},
            receive
                {Reference, done} -> nil
            after ?OWNER_TIMEOUT ->
                nil
            end;
        _ -> nil
    end;
close_policy_store(_Store) ->
    nil.

-spec policy_store_loop(
    atomics:atomics_ref(), [policy_item()], pos_integer(), pos_integer()
) -> no_return().
policy_store_loop(State, Existing, MaximumEntries, MaximumBytes) ->
    Now = erlang:monotonic_time(millisecond),
    Items = prune_policy_items(Existing, Now, []),
    receive
        {
            policy_put,
            Sender,
            Reference,
            Partition,
            Key,
            Value,
            ExpiresAt,
            RetainedBytes
        } ->
            WithoutPrevious = remove_policy_item(
                Partition, Key, Items, []
            ),
            case RetainedBytes =< MaximumBytes of
                false ->
                    Sender ! {Reference, false},
                    policy_store_loop(
                        State, WithoutPrevious, MaximumEntries, MaximumBytes
                    );
                true when ExpiresAt =< Now ->
                    Sender ! {Reference, true},
                    policy_store_loop(
                        State, WithoutPrevious, MaximumEntries, MaximumBytes
                    );
                true ->
                    Updated = retain_policy_capacity(
                        [
                            {
                                Partition,
                                Key,
                                Value,
                                ExpiresAt,
                                RetainedBytes
                            }
                            | WithoutPrevious
                        ],
                        MaximumEntries,
                        MaximumBytes,
                        0,
                        0,
                        []
                    ),
                    Sender ! {Reference, true},
                    policy_store_loop(
                        State, Updated, MaximumEntries, MaximumBytes
                    )
            end;
        {policy_list, Sender, Reference, Partition} ->
            Values = [
                Value
             || {ItemPartition, _Key, Value, _ExpiresAt, _Bytes} <- Items,
                ItemPartition =:= Partition
            ],
            Sender ! {Reference, Values},
            policy_store_loop(State, Items, MaximumEntries, MaximumBytes);
        {policy_get, Sender, Reference, Partition, Key} ->
            case find_policy_item(Partition, Key, Items) of
                {ok, Value} ->
                    Sender ! {Reference, {ok, Value}},
                    policy_store_loop(
                        State,
                        promote_policy_item(Partition, Key, Items),
                        MaximumEntries,
                        MaximumBytes
                    );
                error ->
                    Sender ! {Reference, missing},
                    policy_store_loop(
                        State, Items, MaximumEntries, MaximumBytes
                    )
            end;
        {policy_close, Sender, Reference} ->
            Sender ! {Reference, done},
            exit(normal)
    after policy_store_wait(Items, Now) ->
        policy_store_loop(State, Items, MaximumEntries, MaximumBytes)
    end.

-spec prune_policy_items([policy_item()], integer(), [policy_item()]) ->
    [policy_item()].
prune_policy_items([], _Now, Retained) ->
    lists:reverse(Retained);
prune_policy_items([{_, _, _, ExpiresAt, _} | Rest], Now, Retained)
    when ExpiresAt =< Now ->
    prune_policy_items(Rest, Now, Retained);
prune_policy_items([Item | Rest], Now, Retained) ->
    prune_policy_items(Rest, Now, [Item | Retained]).

-spec remove_policy_item(
    binary(), binary(), [policy_item()], [policy_item()]
) -> [policy_item()].
remove_policy_item(_Partition, _Key, [], Retained) ->
    lists:reverse(Retained);
remove_policy_item(
    Partition,
    Key,
    [{Partition, Key, _Value, _ExpiresAt, _Bytes} | Rest],
    Retained
) ->
    lists:reverse(Retained, Rest);
remove_policy_item(Partition, Key, [Item | Rest], Retained) ->
    remove_policy_item(Partition, Key, Rest, [Item | Retained]).

-spec find_policy_item(binary(), binary(), [policy_item()]) ->
    {ok, term()} | error.
find_policy_item(_Partition, _Key, []) ->
    error;
find_policy_item(
    Partition,
    Key,
    [{Partition, Key, Value, _ExpiresAt, _Bytes} | _Rest]
) ->
    {ok, Value};
find_policy_item(Partition, Key, [_Item | Rest]) ->
    find_policy_item(Partition, Key, Rest).

-spec promote_policy_item(binary(), binary(), [policy_item()]) ->
    [policy_item()].
promote_policy_item(Partition, Key, Items) ->
    promote_policy_item(Partition, Key, Items, []).

-spec promote_policy_item(
    binary(), binary(), [policy_item()], [policy_item()]
) -> [policy_item()].
promote_policy_item(_Partition, _Key, [], Earlier) ->
    lists:reverse(Earlier);
promote_policy_item(
    Partition,
    Key,
    [{Partition, Key, _Value, _ExpiresAt, _Bytes} = Found | Rest],
    Earlier
) ->
    [Found | lists:reverse(Earlier, Rest)];
promote_policy_item(Partition, Key, [Item | Rest], Earlier) ->
    promote_policy_item(Partition, Key, Rest, [Item | Earlier]).

-spec retain_policy_capacity(
    [policy_item()],
    pos_integer(),
    pos_integer(),
    non_neg_integer(),
    non_neg_integer(),
    [policy_item()]
) -> [policy_item()].
retain_policy_capacity([], _MaximumEntries, _MaximumBytes, _Count, _Bytes, Acc) ->
    lists:reverse(Acc);
retain_policy_capacity(
    _Items, MaximumEntries, _MaximumBytes, Count, _Bytes, Acc
) when Count >= MaximumEntries ->
    lists:reverse(Acc);
retain_policy_capacity(
    [{_, _, _, _, ItemBytes} = Item | Rest],
    MaximumEntries,
    MaximumBytes,
    Count,
    Bytes,
    Acc
) ->
    case Bytes + ItemBytes =< MaximumBytes of
        true ->
            retain_policy_capacity(
                Rest,
                MaximumEntries,
                MaximumBytes,
                Count + 1,
                Bytes + ItemBytes,
                [Item | Acc]
            );
        false -> lists:reverse(Acc)
    end.

-spec policy_store_wait([policy_item()], integer()) -> pos_integer().
policy_store_wait([], _Now) ->
    2147483647;
policy_store_wait(Items, Now) ->
    Earliest = lists:min([
        ExpiresAt
     || {_Partition, _Key, _Value, ExpiresAt, _Bytes} <- Items
    ]),
    erlang:max(1, erlang:min(2147483647, Earliest - Now)).

-spec new_http2_pool(integer(), integer(), integer()) -> http2_pool().
new_http2_pool(Maximum, PerOrigin, IdleMilliseconds)
    when Maximum > 0, PerOrigin > 0, PerOrigin =< Maximum,
         Maximum =< 2147483647, IdleMilliseconds > 0,
         IdleMilliseconds =< 2147483647 ->
    State = atomics:new(1, [{signed, false}]),
    Limits = {Maximum, PerOrigin, IdleMilliseconds},
    Owner = spawn(fun() -> http2_pool_loop(State, [], Limits) end),
    #{state => State, owner => Owner};
new_http2_pool(_Maximum, _PerOrigin, _IdleMilliseconds) ->
    new_http2_pool(1, 1, 1).

-spec checkout_http2(http2_pool(), binary()) ->
    {ok, {term(), term(), cleanup()}} | {error, integer()}.
checkout_http2(#{state := State, owner := Owner}, Origin)
    when is_binary(Origin), byte_size(Origin) > 0 ->
    case safe_state(State) of
        0 -> checkout_http2_from_owner(Owner, Origin);
        _ -> {error, 1}
    end;
checkout_http2(_Pool, _Origin) ->
    {error, 1}.

-spec checkout_http2_from_owner(pid(), binary()) ->
    {ok, {term(), term(), cleanup()}} | {error, integer()}.
checkout_http2_from_owner(Owner, Origin) ->
    Reference = make_ref(),
    Owner ! {checkout_http2, self(), Reference, Origin},
    receive
        {Reference, {ok, Session}} -> {ok, Session};
        {Reference, empty} -> {error, 0};
        {Reference, closed} -> {error, 1}
    after ?OWNER_TIMEOUT ->
        {error, 1}
    end.

-spec checkin_http2(http2_pool(), binary(), term(), term(), cleanup()) ->
    boolean().
checkin_http2(
    #{state := State, owner := Owner},
    Origin,
    Socket,
    WireState,
    Cleanup
) when is_binary(Origin), byte_size(Origin) > 0, is_function(Cleanup, 0) ->
    case safe_state(State) of
        0 ->
            checkin_http2_with_owner(
                Owner, Origin, Socket, WireState, Cleanup
            );
        _ ->
            _ = http_transport_ffi:close(Socket),
            false
    end;
checkin_http2(_Pool, _Origin, Socket, _WireState, _Cleanup) ->
    _ = http_transport_ffi:close(Socket),
    false.

-spec checkin_http2_with_owner(pid(), binary(), term(), term(), cleanup()) ->
    boolean().
checkin_http2_with_owner(Owner, Origin, Socket, WireState, Cleanup) ->
    case http_transport_ffi:transfer_owner(Socket, Owner) of
        {ok, nil} ->
            Reference = make_ref(),
            Owner ! {
                checkin_http2,
                self(),
                Reference,
                Origin,
                Socket,
                WireState,
                Cleanup
            },
            receive
                {Reference, pooled} -> true;
                {Reference, rejected} -> false
            after ?OWNER_TIMEOUT ->
                _ = http_transport_ffi:close(Socket),
                false
            end;
        {error, _Reason} ->
            _ = http_transport_ffi:close(Socket),
            false
    end.

-spec drain_http2_pool(http2_pool()) -> nil.
drain_http2_pool(#{state := State, owner := Owner}) ->
    _ = transition_http2_pool(State, 1),
    http2_pool_call(Owner, drain),
    nil;
drain_http2_pool(_Pool) ->
    nil.

-spec close_http2_pool(http2_pool()) -> nil.
close_http2_pool(#{state := State, owner := Owner}) ->
    case atomics:exchange(State, 1, 2) of
        Previous when Previous =:= 0; Previous =:= 1 ->
            http2_pool_call(Owner, close);
        _ -> nil
    end;
close_http2_pool(_Pool) ->
    nil.

-spec transition_http2_pool(atomics:atomics_ref(), 1) -> nil.
transition_http2_pool(State, Next) ->
    case safe_state(State) of
        0 ->
            case atomics:compare_exchange(State, 1, 0, Next) of
                ok -> nil;
                _ -> transition_http2_pool(State, Next)
            end;
        _ -> nil
    end.

-spec http2_pool_call(pid(), drain | close) -> nil.
http2_pool_call(Owner, Command) ->
    Reference = make_ref(),
    Owner ! {Command, self(), Reference},
    receive
        {Reference, done} -> nil
    after ?OWNER_TIMEOUT ->
        nil
    end.

-spec http2_pool_loop(
    atomics:atomics_ref(),
    [http2_session()],
    pool_limits()
) -> no_return().
http2_pool_loop(State, ExistingSessions, Limits) ->
    Sessions = prune_http2_sessions(ExistingSessions),
    receive
        {checkout_http2, Sender, Reference, Origin} ->
            checkout_http2_session(
                State,
                Sessions,
                Origin,
                Sender,
                Reference,
                Limits
            );
        {
            checkin_http2,
            Sender,
            Reference,
            Origin,
            Socket,
            WireState,
            Cleanup
        } ->
            case safe_state(State) =:= 0 andalso
                http2_pool_has_capacity(Origin, Sessions, Limits)
            of
                true ->
                    {_Maximum, _PerOrigin, IdleMilliseconds} = Limits,
                    Deadline = erlang:monotonic_time(millisecond)
                        + IdleMilliseconds,
                    Sender ! {Reference, pooled},
                    http2_pool_loop(
                        State,
                        [
                            {Origin, Socket, WireState, Cleanup, Deadline}
                            | Sessions
                        ],
                        Limits
                    );
                false ->
                    _ = http_transport_ffi:close(Socket),
                    Sender ! {Reference, rejected},
                    http2_pool_loop(State, Sessions, Limits)
            end;
        {drain, Sender, Reference} ->
            close_http2_sessions(Sessions),
            Sender ! {Reference, done},
            http2_pool_loop(State, [], Limits);
        {close, Sender, Reference} ->
            close_http2_sessions(Sessions),
            Sender ! {Reference, done},
            exit(normal)
    after http2_pool_wait(Sessions) ->
        http2_pool_loop(State, Sessions, Limits)
    end.

-spec checkout_http2_session(
    atomics:atomics_ref(),
    [http2_session()],
    binary(),
    pid(),
    reference(),
    pool_limits()
) -> no_return().
checkout_http2_session(State, Sessions, Origin, Sender, Reference, Limits) ->
    case safe_state(State) of
        0 ->
            case take_http2_origin(Origin, Sessions, []) of
                empty ->
                    Sender ! {Reference, empty},
                    http2_pool_loop(State, Sessions, Limits);
                {found, Socket, WireState, Cleanup, Remaining} ->
                    case http_transport_ffi:transfer_owner(Socket, Sender) of
                        {ok, nil} ->
                            Sender ! {
                                Reference,
                                {ok, {Socket, WireState, Cleanup}}
                            },
                            http2_pool_loop(State, Remaining, Limits);
                        {error, _Reason} ->
                            _ = http_transport_ffi:close(Socket),
                            run_cleanup(Cleanup),
                            checkout_http2_session(
                                State,
                                Remaining,
                                Origin,
                                Sender,
                                Reference,
                                Limits
                            )
                    end
            end;
        _ ->
            Sender ! {Reference, closed},
            http2_pool_loop(State, Sessions, Limits)
    end.

-spec take_http2_origin(binary(), [http2_session()], [http2_session()]) ->
    empty | {found, term(), term(), cleanup(), [http2_session()]}.
take_http2_origin(_Origin, [], _Earlier) ->
    empty;
take_http2_origin(
    Origin,
    [{Origin, Socket, State, Cleanup, _} | Rest],
    Earlier
) ->
    {found, Socket, State, Cleanup, lists:reverse(Earlier, Rest)};
take_http2_origin(Origin, [Session | Rest], Earlier) ->
    take_http2_origin(Origin, Rest, [Session | Earlier]).

-spec http2_pool_has_capacity(binary(), [http2_session()], pool_limits()) ->
    boolean().
http2_pool_has_capacity(Origin, Sessions, {Maximum, PerOrigin, _Idle}) ->
    length(Sessions) < Maximum andalso
        count_http2_origin(Origin, Sessions, 0) < PerOrigin.

-spec count_http2_origin(binary(), [http2_session()], non_neg_integer()) ->
    non_neg_integer().
count_http2_origin(_Origin, [], Count) ->
    Count;
count_http2_origin(Origin, [{Origin, _, _, _, _} | Rest], Count) ->
    count_http2_origin(Origin, Rest, Count + 1);
count_http2_origin(Origin, [_ | Rest], Count) ->
    count_http2_origin(Origin, Rest, Count).

-spec prune_http2_sessions([http2_session()]) -> [http2_session()].
prune_http2_sessions(Sessions) ->
    prune_http2_sessions(
        Sessions,
        erlang:monotonic_time(millisecond),
        []
    ).

-spec prune_http2_sessions(
    [http2_session()], integer(), [http2_session()]
) -> [http2_session()].
prune_http2_sessions([], _Now, Retained) ->
    lists:reverse(Retained);
prune_http2_sessions(
    [{_, Socket, _, Cleanup, Deadline} | Rest], Now, Retained
)
    when Deadline =< Now ->
    _ = http_transport_ffi:close(Socket),
    run_cleanup(Cleanup),
    prune_http2_sessions(Rest, Now, Retained);
prune_http2_sessions([Session | Rest], Now, Retained) ->
    prune_http2_sessions(Rest, Now, [Session | Retained]).

-spec http2_pool_wait([http2_session()]) -> pos_integer().
http2_pool_wait([]) ->
    2147483647;
http2_pool_wait(Sessions) ->
    Now = erlang:monotonic_time(millisecond),
    Earliest = lists:min([
        Deadline
     || {_Origin, _Socket, _WireState, _Cleanup, Deadline} <- Sessions
    ]),
    erlang:max(1, Earliest - Now).

-spec close_http2_sessions([http2_session()]) -> nil.
close_http2_sessions(Sessions) ->
    lists:foreach(
        fun({_Origin, Socket, _WireState, Cleanup, _Deadline}) ->
            _ = http_transport_ffi:close(Socket),
            run_cleanup(Cleanup)
        end,
        Sessions
    ),
    nil.

-spec run_cleanup(cleanup()) -> nil.
run_cleanup(Cleanup) ->
    try Cleanup() of
        _ -> nil
    catch
        _Class:_Reason -> nil
    end.

-spec new_connection_guard() -> atomics:atomics_ref().
new_connection_guard() ->
    atomics:new(1, [{signed, false}]).

-spec mark_connection_released(atomics:atomics_ref()) -> boolean().
mark_connection_released(Guard) ->
    claim_connection_state(Guard, 1).

-spec claim_connection_close(atomics:atomics_ref()) -> boolean().
claim_connection_close(Guard) ->
    claim_connection_state(Guard, 2).

-spec claim_connection_state(atomics:atomics_ref(), 1 | 2) -> boolean().
claim_connection_state(Guard, State) ->
    try atomics:compare_exchange(Guard, 1, 0, State) of
        ok -> true;
        _Actual -> false
    catch
        _Class:_Reason -> false
    end.

-spec new_race_cancellation() -> atomics:atomics_ref().
new_race_cancellation() ->
    atomics:new(1, [{signed, false}]).

-spec cancel_race(atomics:atomics_ref()) -> nil.
cancel_race(Cancellation) ->
    try atomics:put(Cancellation, 1, 1) of
        ok -> nil
    catch
        _Class:_Reason -> nil
    end.

-spec race_cancelled(atomics:atomics_ref()) -> boolean().
race_cancelled(Cancellation) ->
    try atomics:get(Cancellation, 1) of
        0 -> false;
        _ -> true
    catch
        _Class:_Reason -> true
    end.

-spec new_lifecycle(integer(), integer(), integer()) -> lifecycle().
new_lifecycle(Maximum, PerOrigin, IdleMilliseconds)
    when Maximum > 0, PerOrigin > 0, PerOrigin =< Maximum,
         Maximum =< 2147483647, IdleMilliseconds > 0,
         IdleMilliseconds =< 2147483647 ->
    State = atomics:new(1, [{signed, false}]),
    Limits = {Maximum, PerOrigin, IdleMilliseconds},
    Owner = spawn(fun() -> lifecycle_loop(State, [], [], Limits) end),
    #{state => State, owner => Owner};
new_lifecycle(_Maximum, _PerOrigin, _IdleMilliseconds) ->
    new_lifecycle(1, 1, 1).

-spec state(lifecycle()) -> 0 | 1 | 2.
state(#{state := State}) ->
    try atomics:get(State, 1) of
        0 -> 0;
        1 -> 1;
        _ -> 2
    catch
        _Class:_Reason -> 2
    end;
state(_Lifecycle) ->
    2.

-spec is_closed(lifecycle()) -> boolean().
is_closed(Lifecycle) ->
    state(Lifecycle) =:= 2.

-spec drain(lifecycle()) -> 1 | 2.
drain(#{state := State, owner := Owner}) ->
    try drain_loop(State) of
        Result ->
            Owner ! drain_pool,
            Result
    catch
        _Class:_Reason -> 2
    end;
drain(_Lifecycle) ->
    2.

-spec drain_loop(atomics:atomics_ref()) -> 1 | 2.
drain_loop(State) ->
    case atomics:get(State, 1) of
        0 ->
            case atomics:compare_exchange(State, 1, 0, 1) of
                ok -> 1;
                _Actual -> drain_loop(State)
            end;
        1 -> 1;
        _ -> 2
    end.

-spec register_socket(lifecycle(), binary(), term()) ->
    {ok, registration()} | {error, integer()}.
register_socket(#{state := State, owner := Owner}, Origin, Socket)
    when is_binary(Origin), byte_size(Origin) > 0 ->
    case safe_state(State) of
        0 -> register_with_owner(Owner, Origin, Socket);
        _ ->
            _ = http_transport_ffi:close(Socket),
            {error, 1}
    end;
register_socket(_Lifecycle, _Origin, Socket) ->
    _ = http_transport_ffi:close(Socket),
    {error, 1}.

-spec register_with_owner(pid(), binary(), term()) ->
    {ok, registration()} | {error, integer()}.
register_with_owner(Owner, Origin, Socket) ->
    Reference = make_ref(),
    Owner ! {register_socket, self(), Reference, Origin, Socket},
    receive
        {Reference, {ok, Token}} ->
            {ok, {http_client_registration, Owner, Token}};
        {Reference, {error, Code}} ->
            {error, Code}
    after ?OWNER_TIMEOUT ->
        _ = http_transport_ffi:close(Socket),
        {error, 1}
    end.

-spec unregister_socket(registration()) -> nil.
unregister_socket({http_client_registration, Owner, Token}) ->
    Owner ! {unregister_socket, Token},
    nil;
unregister_socket(_Registration) ->
    nil.

-spec checkout_socket(lifecycle(), binary()) ->
    {ok, term()} | {error, integer()}.
checkout_socket(#{state := State, owner := Owner}, Origin)
    when is_binary(Origin), byte_size(Origin) > 0 ->
    case safe_state(State) of
        0 -> checkout_from_owner(Owner, Origin);
        _ -> {error, 1}
    end;
checkout_socket(_Lifecycle, _Origin) ->
    {error, 1}.

-spec checkout_from_owner(pid(), binary()) ->
    {ok, term()} | {error, integer()}.
checkout_from_owner(Owner, Origin) ->
    Reference = make_ref(),
    Owner ! {checkout_socket, self(), Reference, Origin},
    receive
        {Reference, {ok, Socket}} -> {ok, Socket};
        {Reference, empty} -> {error, 0};
        {Reference, closed} -> {error, 1}
    after ?OWNER_TIMEOUT ->
        {error, 1}
    end.

-spec checkin_socket(lifecycle(), binary(), term()) -> boolean().
checkin_socket(
    #{state := State, owner := Owner},
    Origin,
    Socket
) when is_binary(Origin), byte_size(Origin) > 0 ->
    case safe_state(State) of
        0 -> checkin_with_owner(Owner, Origin, Socket);
        _ ->
            _ = http_transport_ffi:close(Socket),
            false
    end;
checkin_socket(_Lifecycle, _Origin, Socket) ->
    _ = http_transport_ffi:close(Socket),
    false.

-spec checkin_with_owner(pid(), binary(), term()) -> boolean().
checkin_with_owner(Owner, Origin, Socket) ->
    case http_transport_ffi:transfer_owner(Socket, Owner) of
        {ok, nil} ->
            Reference = make_ref(),
            Owner ! {checkin_socket, self(), Reference, Origin, Socket},
            receive
                {Reference, pooled} -> true;
                {Reference, rejected} -> false
            after ?OWNER_TIMEOUT ->
                _ = http_transport_ffi:close(Socket),
                false
            end;
        {error, _Reason} ->
            _ = http_transport_ffi:close(Socket),
            false
    end.

-spec close(lifecycle()) -> nil.
close(#{state := State, owner := Owner}) ->
    try close_state(State, Owner)
    catch
        _Class:_Reason -> nil
    end;
close(_Lifecycle) ->
    nil.

-spec close_state(atomics:atomics_ref(), pid()) -> nil.
close_state(State, Owner) ->
    case atomics:exchange(State, 1, 2) of
        Previous when Previous =:= 0; Previous =:= 1 ->
            close_owner(State, Owner);
        2 ->
            await_closed(State);
        _ ->
            nil
    end.

-spec close_owner(atomics:atomics_ref(), pid()) -> nil.
close_owner(State, Owner) ->
    Reference = make_ref(),
    Owner ! {close, self(), Reference},
    receive
        {Reference, closed} -> nil
    after ?OWNER_TIMEOUT ->
        atomics:put(State, 1, 3),
        nil
    end.

-spec await_closed(atomics:atomics_ref()) -> nil.
await_closed(State) ->
    await_closed(State, erlang:monotonic_time(millisecond) + ?OWNER_TIMEOUT).

-spec await_closed(atomics:atomics_ref(), integer()) -> nil.
await_closed(State, Deadline) ->
    case safe_state(State) of
        2 ->
            case erlang:monotonic_time(millisecond) < Deadline of
                true ->
                    receive after 1 -> await_closed(State, Deadline) end;
                false -> nil
            end;
        _ -> nil
    end.

-spec lifecycle_loop(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    pool_limits()
) -> no_return().
lifecycle_loop(State, ExistingSockets, ExistingPool, Limits) ->
    {Sockets, Pool} = prune_expired(ExistingSockets, ExistingPool),
    receive
        {register_socket, Sender, Reference, Origin, Socket} ->
            case safe_state(State) of
                0 ->
                    case register_or_refresh(
                        Origin,
                        Socket,
                        Sockets,
                        Limits
                    ) of
                        {ok, Token, UpdatedSockets} ->
                            Sender ! {Reference, {ok, Token}},
                            lifecycle_loop(
                                State,
                                UpdatedSockets,
                                Pool,
                                Limits
                            );
                        capacity ->
                            _ = http_transport_ffi:close(Socket),
                            Sender ! {Reference, {error, 2}},
                            lifecycle_loop(State, Sockets, Pool, Limits)
                    end;
                _ ->
                    _ = http_transport_ffi:close(Socket),
                    Sender ! {Reference, {error, 1}},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {unregister_socket, Token} ->
            lifecycle_loop(
                State,
                lists:keydelete(Token, 1, Sockets),
                remove_pool_token(Token, Pool),
                Limits
            );
        {checkout_socket, Sender, Reference, Origin} ->
            case safe_state(State) of
                0 ->
                    checkout_pooled(
                        State,
                        Sockets,
                        Pool,
                        Origin,
                        Sender,
                        Reference,
                        Limits
                    );
                _ ->
                    Sender ! {Reference, closed},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        {checkin_socket, Sender, Reference, Origin, Socket} ->
            checkin_pooled(
                State,
                Sockets,
                Pool,
                Origin,
                Socket,
                Sender,
                Reference,
                Limits
            );
        drain_pool ->
            {RemainingSockets, _EmptyPool} = close_pool(Sockets, Pool),
            lifecycle_loop(State, RemainingSockets, [], Limits);
        {close, Sender, Reference} ->
            lists:foreach(
                fun({_Token, _Origin, Socket}) ->
                    _ = http_transport_ffi:close(Socket)
                end,
                Sockets
            ),
            atomics:put(State, 1, 3),
            Sender ! {Reference, closed},
            exit(normal)
    after pool_wait(Pool, Limits) ->
        lifecycle_loop(State, Sockets, Pool, Limits)
    end.

-spec register_or_refresh(
    binary(), term(), [registered_socket()], pool_limits()
) -> {ok, reference(), [registered_socket()]} | capacity.
register_or_refresh(Origin, Socket, Sockets, Limits) ->
    case socket_token(Socket, Sockets) of
        {ok, Token} ->
            {ok, Token, replace_socket(Token, Origin, Socket, Sockets)};
        error ->
            case connection_has_capacity(Origin, Sockets, Limits) of
                false -> capacity;
                true ->
                    Token = make_ref(),
                    {ok, Token, [{Token, Origin, Socket} | Sockets]}
            end
    end.

-spec checkout_pooled(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    binary(),
    pid(),
    reference(),
    pool_limits()
) -> no_return().
checkout_pooled(State, Sockets, Pool, Origin, Sender, Reference, Limits) ->
    case take_origin(Origin, Pool, []) of
        empty ->
            Sender ! {Reference, empty},
            lifecycle_loop(State, Sockets, Pool, Limits);
        {found, Token, Socket, RemainingPool} ->
            case http_transport_ffi:transfer_owner(Socket, Sender) of
                {ok, nil} ->
                    Sender ! {Reference, {ok, Socket}},
                    lifecycle_loop(State, Sockets, RemainingPool, Limits);
                {error, _Reason} ->
                    _ = http_transport_ffi:close(Socket),
                    checkout_pooled(
                        State,
                        lists:keydelete(Token, 1, Sockets),
                        RemainingPool,
                        Origin,
                        Sender,
                        Reference,
                        Limits
                    )
            end
    end.

-spec checkin_pooled(
    atomics:atomics_ref(),
    [registered_socket()],
    [pooled_socket()],
    binary(),
    term(),
    pid(),
    reference(),
    pool_limits()
) -> no_return().
checkin_pooled(
    State,
    Sockets,
    Pool,
    Origin,
    Socket,
    Sender,
    Reference,
    Limits = {_Maximum, _PerOrigin, IdleMilliseconds}
) ->
    case safe_state(State) =:= 0 andalso
        pool_has_capacity(Origin, Pool, Limits)
    of
        true ->
            case socket_token(Socket, Sockets) of
                {ok, Token} ->
                    Deadline = erlang:monotonic_time(millisecond)
                        + IdleMilliseconds,
                    UpdatedSockets = replace_socket(
                        Token,
                        Origin,
                        Socket,
                        Sockets
                    ),
                    Sender ! {Reference, pooled},
                    lifecycle_loop(
                        State,
                        UpdatedSockets,
                        [{Origin, Token, Socket, Deadline} | Pool],
                        Limits
                    );
                error ->
                    _ = http_transport_ffi:close(Socket),
                    Sender ! {Reference, rejected},
                    lifecycle_loop(State, Sockets, Pool, Limits)
            end;
        false ->
            _ = http_transport_ffi:close(Socket),
            UpdatedSockets = remove_socket(Socket, Sockets),
            Sender ! {Reference, rejected},
            lifecycle_loop(State, UpdatedSockets, Pool, Limits)
    end.

-spec pool_has_capacity(binary(), [pooled_socket()], pool_limits()) -> boolean().
pool_has_capacity(Origin, Pool, {Maximum, PerOrigin, _IdleMilliseconds}) ->
    length(Pool) < Maximum andalso
        count_origin(Origin, Pool, 0) < PerOrigin.

-spec connection_has_capacity(
    binary(), [registered_socket()], pool_limits()
) -> boolean().
connection_has_capacity(
    Origin,
    Sockets,
    {Maximum, PerOrigin, _IdleMilliseconds}
) ->
    length(Sockets) < Maximum andalso
        count_registered_origin(Origin, Sockets, 0) < PerOrigin.

-spec count_registered_origin(
    binary(), [registered_socket()], non_neg_integer()
) -> non_neg_integer().
count_registered_origin(_Origin, [], Count) ->
    Count;
count_registered_origin(Origin, [{_, Origin, _} | Rest], Count) ->
    count_registered_origin(Origin, Rest, Count + 1);
count_registered_origin(Origin, [_ | Rest], Count) ->
    count_registered_origin(Origin, Rest, Count).

-spec count_origin(binary(), [pooled_socket()], non_neg_integer()) ->
    non_neg_integer().
count_origin(_Origin, [], Count) ->
    Count;
count_origin(Origin, [{Origin, _, _, _} | Rest], Count) ->
    count_origin(Origin, Rest, Count + 1);
count_origin(Origin, [_ | Rest], Count) ->
    count_origin(Origin, Rest, Count).

-spec take_origin(binary(), [pooled_socket()], [pooled_socket()]) ->
    empty | {found, reference(), term(), [pooled_socket()]}.
take_origin(_Origin, [], _Earlier) ->
    empty;
take_origin(Origin, [{Origin, Token, Socket, _} | Rest], Earlier) ->
    {found, Token, Socket, lists:reverse(Earlier, Rest)};
take_origin(Origin, [Entry | Rest], Earlier) ->
    take_origin(Origin, Rest, [Entry | Earlier]).

-spec prune_expired([registered_socket()], [pooled_socket()]) ->
    {[registered_socket()], [pooled_socket()]}.
prune_expired(Sockets, Pool) ->
    prune_expired(
        Sockets,
        Pool,
        erlang:monotonic_time(millisecond),
        []
    ).

-spec prune_expired(
    [registered_socket()],
    [pooled_socket()],
    integer(),
    [pooled_socket()]
) -> {[registered_socket()], [pooled_socket()]}.
prune_expired(Sockets, [], _Now, Retained) ->
    {Sockets, lists:reverse(Retained)};
prune_expired(Sockets, [{_, Token, Socket, Deadline} | Rest], Now, Retained)
    when Deadline =< Now ->
    _ = http_transport_ffi:close(Socket),
    prune_expired(lists:keydelete(Token, 1, Sockets), Rest, Now, Retained);
prune_expired(Sockets, [Entry | Rest], Now, Retained) ->
    prune_expired(Sockets, Rest, Now, [Entry | Retained]).

-spec pool_wait([pooled_socket()], pool_limits()) -> pos_integer().
pool_wait([], {_Maximum, _PerOrigin, _IdleMilliseconds}) ->
    2147483647;
pool_wait(Pool, _Limits) ->
    Now = erlang:monotonic_time(millisecond),
    Earliest = lists:min([Deadline || {_, _, _, Deadline} <- Pool]),
    erlang:max(1, Earliest - Now).

-spec close_pool([registered_socket()], [pooled_socket()]) ->
    {[registered_socket()], []}.
close_pool(Sockets, Pool) ->
    Remaining = lists:foldl(
        fun({_Origin, Token, Socket, _Deadline}, Acc) ->
            _ = http_transport_ffi:close(Socket),
            lists:keydelete(Token, 1, Acc)
        end,
        Sockets,
        Pool
    ),
    {Remaining, []}.

-spec remove_pool_token(reference(), [pooled_socket()]) -> [pooled_socket()].
remove_pool_token(Token, Pool) ->
    [Entry || Entry = {_, EntryToken, _, _} <- Pool, EntryToken =/= Token].

-spec socket_token(term(), [registered_socket()]) ->
    {ok, reference()} | error.
socket_token(_Socket, []) ->
    error;
socket_token(Socket, [{Token, _Origin, Candidate} | Rest]) ->
    case same_socket(Socket, Candidate) of
        true -> {ok, Token};
        false -> socket_token(Socket, Rest)
    end.

-spec replace_socket(reference(), binary(), term(), [registered_socket()]) ->
    [registered_socket()].
replace_socket(Token, Origin, Socket, Sockets) ->
    [{Token, Origin, Socket} | lists:keydelete(Token, 1, Sockets)].

-spec remove_socket(term(), [registered_socket()]) -> [registered_socket()].
remove_socket(Socket, Sockets) ->
    [Entry || Entry = {_Token, _Origin, Candidate} <- Sockets,
        not same_socket(Socket, Candidate)].

-spec same_socket(term(), term()) -> boolean().
same_socket(
    #{kind := Kind, socket := Socket},
    #{kind := Kind, socket := Socket}
) ->
    true;
same_socket(_Left, _Right) ->
    false.

-spec safe_state(atomics:atomics_ref()) -> integer().
safe_state(State) ->
    try atomics:get(State, 1)
    catch
        _Class:_Reason -> 3
    end.
