%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-module(http_cookie_store_test).

-include_lib("eunit/include/eunit.hrl").

-export([
    close_removes_session_state/0,
    expiry_and_last_access_control_eviction/0
]).

expiry_and_last_access_control_eviction() ->
    Store = http_client_ffi:new_policy_store(2, 1024),
    Now = erlang:monotonic_time(millisecond),
    try
        true = http_client_ffi:policy_store_put(
            Store, <<"partition">>, <<"expired">>, <<"expired">>, Now, 8
        ),
        ?assertEqual([], http_client_ffi:policy_store_list(
            Store, <<"partition">>
        )),
        true = http_client_ffi:policy_store_put(
            Store, <<"partition">>, <<"a">>, <<"a">>, Now + 60000, 1
        ),
        true = http_client_ffi:policy_store_put(
            Store, <<"partition">>, <<"b">>, <<"b">>, Now + 60000, 1
        ),
        nil = http_client_ffi:policy_store_touch(
            Store, <<"partition">>, [<<"a">>]
        ),
        true = http_client_ffi:policy_store_put(
            Store, <<"partition">>, <<"c">>, <<"c">>, Now + 60000, 1
        ),
        ?assertEqual(
            [<<"c">>, <<"a">>],
            http_client_ffi:policy_store_list(Store, <<"partition">>)
        ),
        ?assertEqual([], http_client_ffi:policy_store_list(
            Store, <<"different-partition">>
        )),
        nil
    after
        http_client_ffi:close_policy_store(Store)
    end.

close_removes_session_state() ->
    Store = #{owner := Owner} = http_client_ffi:new_policy_store(2, 1024),
    Monitor = monitor(process, Owner),
    Now = erlang:monotonic_time(millisecond),
    true = http_client_ffi:policy_store_put(
        Store, <<"partition">>, <<"session">>, <<"session">>,
        Now + 60000, 7
    ),
    nil = http_client_ffi:close_policy_store(Store),
    receive
        {'DOWN', Monitor, process, Owner, normal} -> nil
    after 1000 ->
        ?assert(false)
    end,
    ?assertEqual([], http_client_ffi:policy_store_list(
        Store, <<"partition">>
    )),
    nil.
