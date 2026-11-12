%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(qlog_absolute_deadline_tests).
-include_lib("eunit/include/eunit.hrl").

stall_reaching_absolute_deadline_does_not_rebase_or_dispatch_close_test() ->
    Deadline = quic_core_udp_ffi:monotonic_millisecond(),
    ?assertEqual(
        {error, 6},
        quic_core_qlog_ffi:close_confirmed_until(self(), Deadline)
    ),
    %% An expired boundary is rejected before the writer command is emitted;
    %% there is no later `now + remaining` close hidden behind the result.
    receive
        {qlog_call, _Alias, _Reference, close} -> ?assert(false)
    after 0 ->
        ok
    end.

absolute_deadline_domain_rejects_invalid_scalars_test() ->
    ?assertEqual(
        {error, 1},
        quic_core_qlog_ffi:close_confirmed_until(self(), -1)
    ),
    ?assertEqual(
        {error, 1},
        quic_core_qlog_ffi:close_confirmed_until(
            self(), 9223372036854775808
        )
    ).
