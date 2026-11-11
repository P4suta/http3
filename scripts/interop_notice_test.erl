%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(interop_notice_test).
-export([test/0]).
-include("../test/interop_notice.hrl").

test() ->
    Directory = filename:join(["build", "interop-notice-test",
        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16), lowercase))]),
    Path = filename:join(Directory, "ready.json"),
    ok = filelib:ensure_dir(Path),
    Owner = self(),
    {Reader, Monitor} = spawn_monitor(fun() ->
        receive {read_now, Ref} ->
            Absent = file:read_file(Path) =:= {error, enoent},
            Owner ! {observed, Ref, Absent}
        after 3000 -> exit(checkpoint_timeout) end
    end),
    Bytes = <<"{\"port\":443}">>,
    Write = fun(File, Data) ->
        Ref = make_ref(), Reader ! {read_now, Ref},
        receive {observed, Ref, Absent} -> put(notice_absent, Absent)
        after 3000 -> error(reader_checkpoint_timeout) end,
        file:write(File, Data)
    end,
    try
        ok = interop_publish_notice_with(Path, Bytes, Write),
        receive {'DOWN', Monitor, process, Reader, normal} -> ok
        after 3000 -> error(reader_not_joined) end,
        case erase(notice_absent) of true -> ok; _ -> error(partial_readiness_visible) end,
        true = file:read_file(Path) =:= {ok, Bytes},
        true = interop_read_notice(Path, 256) =:= {ok, Bytes},
        true = interop_read_notice(Path, 4) =:= {error, notice_too_large},
        true = try interop_publish_notice(Path, <<"replacement">>), false catch _:_ -> true end,
        true = file:read_file(Path) =:= {ok, Bytes},
        {ok, ["ready.json"]} = file:list_dir(Directory),
        ok = file:delete(Path),
        Failed = try interop_publish_notice_with(Path, Bytes,
            fun(_, _) -> error(controlled_write_failure) end), false catch _:_ -> true end,
        true = Failed,
        false = filelib:is_regular(Path),
        {ok, []} = file:list_dir(Directory),
        true = try interop_publish_notice(Path, binary:copy(<<0>>, 257)), false catch _:_ -> true end,
        false = filelib:is_regular(Path),
        io:put_chars("native notice controls: atomic visibility, existing record, write failure and bound verified\n"),
        ok
    after
        exit(Reader, kill),
        CleanupMonitor = monitor(process, Reader),
        receive {'DOWN', CleanupMonitor, process, Reader, _} -> ok
        after 3000 -> error(reader_cleanup_timeout) end,
        demonitor(Monitor, [flush]), erase(notice_absent),
        file:delete(Path), file:delete(Path ++ ".pending"), file:del_dir(Directory)
    end.
