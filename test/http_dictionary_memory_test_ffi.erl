%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_dictionary_memory_test_ffi).
-export([sub_binary/1, referenced_bytes/1, retained_upper_bound/1]).

sub_binary(Bytes) when is_binary(Bytes), byte_size(Bytes) > 64, byte_size(Bytes) =< 2048 ->
    Parent = <<Bytes/binary, 0:8388608>>,
    binary:part(Parent, 0, byte_size(Bytes)).

referenced_bytes(Bytes) when is_binary(Bytes) -> binary:referenced_byte_size(Bytes).

%% A conservative measurement of the actual selected record: all heap terms
%% plus every referenced binary backing allocation. Only the scalar escapes.
retained_upper_bound(Term) ->
    erts_debug:flat_size(Term) * erlang:system_info(wordsize) + referenced(Term).

referenced(Bytes) when is_binary(Bytes) -> binary:referenced_byte_size(Bytes);
referenced(Tuple) when is_tuple(Tuple) -> referenced(tuple_to_list(Tuple));
referenced([Head | Tail]) -> referenced(Head) + referenced(Tail);
referenced(_) -> 0.
