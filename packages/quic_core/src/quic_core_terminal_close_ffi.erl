%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(quic_core_terminal_close_ffi).
-export([new/0, publish/2, read/1]).

%% Exactly one unsigned word; three consecutive 62-bit ranges denote peer
%% application, peer transport, and local transport codes. Zero is pending.
%% CAS makes the first authenticated cause final.
%% The reference is garbage-collected with the opaque connection handles.
-spec new() -> atomics:atomics_ref().
new() -> atomics:new(1, [{signed, false}]).

-spec publish(atomics:atomics_ref(), integer()) -> boolean().
publish(Close, Value)
        when is_integer(Value), Value > 0, Value =< 13835058055282163712 ->
    atomics:compare_exchange(Close, 1, 0, Value) =:= ok;
publish(_Close, _Value) -> false.

-spec read(atomics:atomics_ref()) -> integer().
read(Close) -> atomics:get(Close, 1).
