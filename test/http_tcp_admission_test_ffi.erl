%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_tcp_admission_test_ffi).
-include_lib("eunit/include/eunit.hrl").
-export([adoption_preserves_capacity/0, replacement_is_atomic/0,
    cancelled_adoption_closes_socket/0, lifecycle_close_closes_adopted_socket/0,
    dial_failure_cancels_reservation/0, refusal_never_calls_dial/0]).

dial_failure_cancels_reservation() ->
    Parent = self(),
    Reference = make_ref(),
    Reservation = 'http@internal@tcp_reservation':new(
        fun(_) -> Parent ! {Reference, attached}, {ok, nil} end,
        fun() -> Parent ! {Reference, cancelled}, nil end),
    Result = 'http@internal@tcp_reservation':connect(
        fun(_) -> {ok, Reservation} end, <<"origin">>, fun() -> {error, connect_failure} end),
    ?assertEqual({error, connect_failure}, Result),
    receive {Reference, cancelled} -> ok after 1000 -> ?assert(false) end,
    receive {Reference, _} -> ?assert(false) after 0 -> nil end.

refusal_never_calls_dial() ->
    Parent = self(),
    Reference = make_ref(),
    Result = 'http@internal@tcp_reservation':connect(
        fun(_) -> {error, capacity} end, <<"origin">>,
        fun() -> Parent ! {Reference, dialled}, {error, unexpected} end),
    ?assertEqual({error, capacity}, Result),
    receive {Reference, _} -> ?assert(false) after 0 -> nil end.

adoption_preserves_capacity() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    {Socket, Peer} = socket_pair(),
    try
        {ok, Reservation} = http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
        ?assertEqual({ok, nil}, http_client_ffi:attach_reserved_socket(Reservation, Socket)),
        {ok, Attached} = http_client_ffi:register_socket(Lifecycle, <<"origin">>, Socket),
        ?assert(Attached =:= Reservation),
        ?assertEqual({error, 2}, http_client_ffi:reserve_resource(Lifecycle, <<"other">>)),
        nil = http_client_ffi:unregister_socket(Attached),
        ?assertMatch({ok, _}, http_client_ffi:reserve_resource(Lifecycle, <<"other">>)),
        nil
    after http_client_ffi:close(Lifecycle), close_pair(Socket, Peer) end.

replacement_is_atomic() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    {Raw, RawPeer} = socket_pair(),
    {Upgraded, UpgradedPeer} = socket_pair(),
    try
        {ok, Reservation} = http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
        {ok, nil} = http_client_ffi:attach_reserved_socket(Reservation, Raw),
        {ok, RawRegistration} = http_client_ffi:register_socket(Lifecycle, <<"origin">>, Raw),
        ?assertEqual({ok, nil}, http_client_ffi:replace_socket(Lifecycle, Raw, Upgraded)),
        nil = http_client_ffi:unregister_socket(RawRegistration),
        ?assertEqual({error, 2}, http_client_ffi:reserve_resource(Lifecycle, <<"other">>)),
        {ok, UpgradedRegistration} = http_client_ffi:register_socket(Lifecycle, <<"origin">>, Upgraded),
        ?assert(UpgradedRegistration =/= RawRegistration),
        nil = http_client_ffi:cancel_resource(Reservation),
        ?assertEqual({error, 2}, http_client_ffi:reserve_resource(Lifecycle, <<"other">>)),
        nil = http_client_ffi:unregister_socket(UpgradedRegistration),
        ?assertMatch({ok, _}, http_client_ffi:reserve_resource(Lifecycle, <<"other">>)),
        nil
    after http_client_ffi:close(Lifecycle), close_pair(Raw, RawPeer), close_pair(Upgraded, UpgradedPeer) end.

cancelled_adoption_closes_socket() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    {Socket, Peer} = socket_pair(),
    try
        {ok, Reservation} = http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
        nil = http_client_ffi:cancel_resource(Reservation),
        ?assertEqual({error, 1}, http_client_ffi:attach_reserved_socket(Reservation, Socket)),
        ?assertEqual({error, closed}, gen_tcp:recv(Peer, 0, 1000)),
        ?assertMatch({ok, _}, http_client_ffi:reserve_resource(Lifecycle, <<"origin">>)),
        nil
    after http_client_ffi:close(Lifecycle), close_pair(Socket, Peer) end.

lifecycle_close_closes_adopted_socket() ->
    Lifecycle = http_client_ffi:new_lifecycle(1, 1, 1000),
    {Socket, Peer} = socket_pair(),
    try
        {ok, Reservation} = http_client_ffi:reserve_resource(Lifecycle, <<"origin">>),
        {ok, nil} = http_client_ffi:attach_reserved_socket(Reservation, Socket),
        nil = http_client_ffi:close(Lifecycle),
        ?assertEqual({error, closed}, gen_tcp:recv(Peer, 0, 1000)),
        nil
    after http_client_ffi:close(Lifecycle), close_pair(Socket, Peer) end.

socket_pair() ->
    {ok, Listener} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127,0,0,1}}]),
    try
        {ok, {_, Port}} = inet:sockname(Listener),
        {ok, Socket} = gen_tcp:connect({127,0,0,1}, Port, [binary, {active, false}], 1000),
        {ok, Peer} = gen_tcp:accept(Listener, 1000),
        {#{kind => tcp, socket => Socket, buffered => <<>>}, Peer}
    after gen_tcp:close(Listener) end.

close_pair(Socket, Peer) ->
    _ = http_transport_ffi:close(Socket),
    gen_tcp:close(Peer).
