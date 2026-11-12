#!/usr/bin/env escript
%%! +S 1:1 +SDcpu 1 +SDio 1 +A 1
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("evidence_publication.hrl").

main([]) ->
    ok = file:set_cwd(filename:dirname(filename:dirname(
        filename:absname(escript:script_name())))),
    Root = filename:absname(filename:join(
        "build/evidence-publication-self-test",
        binary_to_list(binary:encode_hex(
            crypto:strong_rand_bytes(16), lowercase)))),
    ok = filelib:ensure_dir(filename:join(Root, "placeholder")),
    try
        concurrent_no_replace(Root),
        incomplete_temporary_is_not_evidence(Root),
        hardlink_is_rejected(Root),
        locked_replace_requires_current_bytes(Root),
        bounds_fail_before_publication(Root),
        ParentLink = optional_parent_link_is_rejected(),
        io:format("evidence_publication atomic_no_replace=verified "
                  "partial_visibility=rejected hardlink=rejected "
                  "stale_replace=rejected bounds=verified parent_link=~s~n",
                  [ParentLink])
    after cleanup(Root) end;
main(_) -> erlang:halt(2).

concurrent_no_replace(Root) ->
    Target = filename:join(Root, "concurrent.json"),
    Parent = self(),
    Start = make_ref(),
    Worker = fun(Bytes) ->
        receive Start -> ok end,
        Result = try evidence_publish_new(Target, Bytes, 1024) of
            ok -> published
        catch _:_ -> rejected end,
        Parent ! {publication_result, self(), Result}
    end,
    {First, FirstMonitor} = spawn_monitor(fun() -> Worker(<<"first">>) end),
    {Second, SecondMonitor} = spawn_monitor(fun() -> Worker(<<"second">>) end),
    First ! Start,
    Second ! Start,
    [published, rejected] = lists:sort([result(), result()]),
    down(FirstMonitor),
    down(SecondMonitor),
    Published = evidence_publication_read(Target, 1024),
    true = lists:member(Published, [<<"first">>, <<"second">>]),
    no_pending_files(Root).

incomplete_temporary_is_not_evidence(Root) ->
    Target = filename:join(Root, "partial.json"),
    Pending = Target ++ ".pending-hostile",
    ok = file:write_file(Pending, <<"{">>, [binary, exclusive]),
    true = path_absent(Target),
    true = try evidence_publication_read(Target, 1024), false
           catch _:_ -> true end,
    ok = file:delete(Pending).

hardlink_is_rejected(Root) ->
    Source = filename:join(Root, "hardlink-source.json"),
    Alias = filename:join(Root, "hardlink-alias.json"),
    ok = evidence_publish_new(Source, <<"safe">>, 1024),
    ok = file:make_link(Source, Alias),
    true = try evidence_publication_read(Source, 1024), false
           catch _:_ -> true end,
    true = try evidence_publication_read(Alias, 1024), false
           catch _:_ -> true end,
    ok = file:delete(Alias),
    <<"safe">> = evidence_publication_read(Source, 1024).

locked_replace_requires_current_bytes(Root) ->
    Target = filename:join(Root, "replace.json"),
    ok = evidence_publish_new(Target, <<"old">>, 1024),
    true = try evidence_replace_locked(
                   Target, <<"stale">>, <<"new">>, 1024), false
           catch _:_ -> true end,
    <<"old">> = evidence_publication_read(Target, 1024),
    ok = evidence_replace_locked(Target, <<"old">>, <<"new">>, 1024),
    <<"new">> = evidence_publication_read(Target, 1024),
    no_pending_files(Root).

bounds_fail_before_publication(Root) ->
    Empty = filename:join(Root, "empty.json"),
    Oversize = filename:join(Root, "oversize.json"),
    true = try evidence_publish_new(Empty, <<>>, 4), false
           catch _:_ -> true end,
    true = try evidence_publish_new(Oversize, <<"12345">>, 4), false
           catch _:_ -> true end,
    true = path_absent(Empty),
    true = path_absent(Oversize).

optional_parent_link_is_rejected() ->
    case os:getenv("HTTP_EVIDENCE_PUBLICATION_PARENT_LINK") of
        false -> "not_requested";
        Value when is_list(Value), Value =/= [] ->
            Parent = filename:absname(Value),
            Target = filename:join(Parent, "must-not-exist.json"),
            true = try evidence_publish_new(Target, <<"forbidden">>, 1024),
                       false
                   catch _:_ -> true end,
            true = path_absent(Target),
            "rejected"
    end.

result() ->
    receive {publication_result, _, Result} -> Result
    after 2000 -> erlang:error(publication_worker_timeout) end.

down(Monitor) ->
    receive
        {'DOWN', Monitor, process, _, normal} -> ok;
        {'DOWN', Monitor, process, _, _} ->
            erlang:error(publication_worker_failed)
    after 2000 -> erlang:error(publication_worker_exit_unconfirmed) end.

no_pending_files(Root) ->
    {ok, Names} = file:list_dir(Root),
    false = lists:any(fun(Name) ->
        string:find(Name, ".pending-") =/= nomatch
    end, Names),
    ok.

cleanup(Root) ->
    case file:list_dir(Root) of
        {ok, Names} ->
            lists:foreach(fun(Name) ->
                ok = file:delete(filename:join(Root, Name))
            end, Names),
            ok = file:del_dir(Root);
        {error, enoent} -> ok
    end.

path_absent(Path) ->
    case file:read_link_info(Path) of {error, enoent} -> true; _ -> false end.
