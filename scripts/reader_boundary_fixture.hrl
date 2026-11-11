%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_READER_BOUNDARY_FIXTURE_HRL).
-define(HTTP_READER_BOUNDARY_FIXTURE_HRL, true).

%% A Windows test harness supplies an already-created junction. Keeping its
%% creation outside the BEAM test avoids adding an unsupervised native process
%% launcher to qualification code. Other platforms can create a symlink using
%% the Erlang file API. Missing platform capability remains explicit.
reader_boundary_supplied_parent_path() ->
    case os:getenv("HTTP_READER_BOUNDARY_PARENT_PATH") of
        Path when is_list(Path), Path =/= [], length(Path) =< 4096 ->
            case filename:pathtype(Path) of
                absolute -> {ok, filename:absname(Path)};
                _ -> none
            end;
        _ -> none
    end.

reader_boundary_make_parent_link(Target0, Link0) ->
    Target = filename:absname(Target0),
    Link = filename:absname(Link0),
    case os:type() of
        {win32, _} -> {<<"junction">>, <<"unavailable">>};
        _ ->
            case file:make_symlink(Target, Link) of
                ok -> {<<"symlink">>, <<"verified">>};
                {error, _} -> {<<"symlink">>, <<"unavailable">>}
            end
    end.

reader_boundary_remove_parent_link(Link) ->
    %% del_dir removes a Windows junction without traversing its target.
    case file:del_dir(Link) of
        ok -> ok;
        {error, enoent} -> ok;
        {error, _} ->
            case file:delete(Link) of
                ok -> ok;
                {error, enoent} -> ok;
                {error, _} -> erlang:error(reader_boundary_link_cleanup_failed)
            end
    end.

-endif.
