%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(quic_core_udp_advisory_test_ffi).
-include_lib("eunit/include/eunit.hrl").
-export([classifies_unverified_path_errors/0, preserves_connection_state/0]).

classifies_unverified_path_errors() ->
    Socket = make_ref(), Other = make_ref(),
    Handle = #{socket => Socket},
    Dual = #{socket => Socket, ipv4_socket => Other},
    lists:foreach(fun(Reason) ->
        ?assertEqual({error, 10}, quic_core_udp_ffi:active_datagram(Handle, {udp_error, Socket, Reason})),
        ?assertEqual({error, 10}, quic_core_udp_ffi:active_datagram(Dual, {udp_error, Other, Reason}))
    end, [econnreset, econnrefused, ehostunreach, enetunreach]),
    ?assertEqual({error, 3}, quic_core_udp_ffi:active_datagram(Handle, {udp_closed, Socket})),
    ?assertEqual({error, 4}, quic_core_udp_ffi:active_datagram(Handle, {udp_error, Socket, eacces})),
    ?assertEqual({error, 1}, quic_core_udp_ffi:active_datagram(Handle, {udp_error, Other, econnreset})),
    nil.

preserves_connection_state() ->
    Socket = make_ref(), Previous = make_ref(),
    Handle = #{socket => Socket},
    %% The authenticated transport is opaque to this classifier: preserving
    %% it exactly means no buffered bytes, timers, CIDs, or progress are reset.
    State = {state, Handle, authenticated_connection_marker, none, version_1, <<"h3">>, none, true},
    Migrating = setelement(4, State, {some, #{socket => Previous}}),
    lists:foreach(fun({Current, Port}) ->
        Outcome = 'quic_core@internal@runtime@client_transport':receive_active(
            Current, {udp_error, Port, econnreset}),
        ?assert(Outcome =:= {ok, Current})
    end, [{State, Socket}, {Migrating, Socket}, {Migrating, Previous}]),
    ?assertEqual({error, socket_unavailable},
        'quic_core@internal@runtime@client_transport':receive_active(State, {udp_closed, Socket})),
    nil.
