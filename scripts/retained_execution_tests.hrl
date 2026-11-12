%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_RETAINED_EXECUTION_TESTS_HRL).
-define(HTTP_RETAINED_EXECUTION_TESTS_HRL, true).

%% Exercise the real files left by an owned, joined child. Every corruption
%% must change an accepted proof into a rejection, and restoring the exact
%% bytes must restore acceptance. Never print the corrupted bytes or paths.
retained_execution_self_test(Valid, [ChildPath | BeamPaths]) ->
    true = Valid(),
    ChildBytes = runtime_matrix_read(ChildPath, 16777216),
    Child = evidence_json_decode(ChildBytes),
    ChildMutations = [
        iolist_to_binary(json:encode(Child#{<<"private">> => <<"private-retained-marker">>})),
        iolist_to_binary(json:encode(Child#{<<"nonce">> => <<"wrong-run">>})),
        <<"{\"nonce\":1,\"n\\u006fnce\":2}">>
    ],
    lists:foreach(fun(Bytes) -> retained_execution_corruption(Valid, ChildPath, Bytes) end,
        ChildMutations),
    lists:foreach(fun(Path) -> retained_execution_corruption(Valid, Path, <<0>>) end, BeamPaths),
    Extra = filename:join(filename:dirname(ChildPath), "unexpected-artifact"),
    ok = file:write_file(Extra, <<0>>, [exclusive]),
    try false = Valid() after ok = file:delete(Extra) end,
    true = Valid(),
    io:put_chars("retained execution: actual child and code accepted; substituted child, code and extra files rejected\n").

retained_execution_corruption(Valid, Path, Corrupt) ->
    Original = runtime_matrix_read(Path, 16777216),
    try
        ok = file:write_file(Path, Corrupt),
        false = Valid(),
        ok = file:delete(Path),
        false = Valid()
    after
        ok = file:write_file(Path, Original)
    end,
    true = Valid().
-endif.
