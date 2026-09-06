#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

main([]) ->
    try run() of ok -> ok catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "interop audit failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end;
main(_) -> erlang:error(interop_audit_usage).

run() ->
    Profile = json:decode(read("standards/interop-profile.json")),
    ensure(maps:get(<<"baseline_date">>, Profile) =:= <<"2026-08-30">>,
           invalid_interop_baseline),
    Peers = maps:get(<<"peers">>, Profile),
    Ids = [maps:get(<<"id">>, Peer) || Peer <- Peers],
    ensure(length(Ids) =:= length(lists:usort(Ids)), duplicate_interop_peer),
    lists:foreach(fun audit_pin/1, Peers),
    Missing = [maps:get(<<"id">>, Peer) || Peer <- Peers,
        maps:get(<<"pin">>, Peer, null) =:= null orelse
        maps:get(<<"evidence">>, Peer, null) =:= null],
    Status = case Missing of [] -> <<"Ready">>; _ -> <<"Blocked">> end,
    Report = #{status => Status, baseline_date => <<"2026-08-30">>,
               peers => length(Peers), missing => Missing},
    write_report(Report),
    case Status of
        <<"Ready">> -> io:format("interop audit: all ~B peer rows ready~n",
                                  [length(Peers)]);
        _ -> erlang:error({interop_matrix_incomplete, Missing})
    end.

audit_pin(Peer) ->
    case maps:get(<<"id">>, Peer) of
        <<"aioquic-h3">> ->
            ensure(file_digest("packages/http3/test/interop/requirements.lock")
                   =:= maps:get(<<"lock_sha256">>, Peer),
                   aioquic_lock_drift);
        <<"quic-go-h3">> ->
            ensure(file_digest("packages/http3/test/interop/quicgo/go.sum")
                   =:= maps:get(<<"lock_sha256">>, Peer),
                   quicgo_lock_drift);
        _ -> ok
    end,
    case maps:get(<<"evidence">>, Peer, null) of
        null -> ok;
        Path -> ensure(filelib:is_regular(binary_to_list(Path)),
                       {missing_interop_evidence_source, Path})
    end.

write_report(Report) ->
    Path = "build/interop/report.json",
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [json:encode(Report), <<"\n">>]).

file_digest(Path) -> string:lowercase(hex(crypto:hash(sha256, read(Path)))).

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
