%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_EXAMPLES_SOURCE).
-define(HTTP_EXAMPLES_SOURCE, true).
-include_lib("kernel/include/file.hrl").

%% Prune generated/dependency trees before descent, so retained snapshots do
%% not multiply discovery work. No symbolic path can escape this repository.
examples_markdown_files() ->
    {_, Files} = examples_walk(".", 0, 100000, []),
    lists:usort(Files).

examples_walk(Directory, Depth, Remaining, Acc) ->
    examples_ensure(Depth =< 32 andalso Remaining > 0, example_discovery_limit),
    {ok, Names} = file:list_dir(Directory),
    examples_ensure(length(Names) =< Remaining, example_discovery_limit),
    lists:foldl(fun(Name, {Left, Files}) ->
        Path = examples_normalise(filename:join(Directory, Name)),
        case examples_documented(Path) of
            false -> {Left - 1, Files};
            true ->
                {ok, Info} = file:read_link_info(Path),
                case Info#file_info.type of
                    directory -> examples_walk(Path, Depth + 1, Left - 1, Files);
                    regular ->
                        case filename:extension(Name) of
                            ".md" -> {Left - 1, [Path | Files]};
                            _ -> {Left - 1, Files}
                        end;
                    symlink -> erlang:error(symbolic_document_path);
                    _ -> {Left - 1, Files}
                end
        end
    end, {Remaining, Acc}, lists:sort(Names)).

examples_normalise("./" ++ Path) -> Path;
examples_normalise(Path) -> Path.

examples_documented(Path) ->
    Segments = filename:split(examples_normalise(Path)),
    not lists:any(fun(Segment) ->
        Segment =:= "build" orelse Segment =:= "deps" orelse Segment =:= "node_modules"
            orelse (Segment =/= "." andalso hd(Segment) =:= $.)
    end, Segments).

examples_extract(Path) ->
    Lines = [string:trim(Line, trailing, "\r") || Line <- binary:split(examples_read(Path, 8388608), <<"\n">>, [global])],
    lists:reverse(examples_parse_lines(Lines, Path, 1, none, none, [])).

examples_parse_lines([], Path, _Line, _Pending, {collecting, _, _, _, _}, _Examples) ->
    erlang:error({unterminated_gleam_fence, Path});
examples_parse_lines([], _Path, _Line, none, none, Examples) -> Examples;
examples_parse_lines([], _Path, _Line, _Pending, none, _Examples) ->
    erlang:error(unused_example_annotation);
examples_parse_lines([Line | Rest], Path, Number, Pending, none, Examples) ->
    case examples_annotation(Line) of
        {ok, Package, Id} ->
            examples_ensure(Pending =:= none, {unused_example_annotation, Path, Number}),
            examples_parse_lines(Rest, Path, Number + 1, {Package, Id, Number}, none,
                        Examples);
        no ->
            case Line of
                <<"```gleam">> ->
                    case Pending of
                        none -> erlang:error({unannotated_gleam_fence,
                                              Path, Number});
                        {Package, Id, AnnotationLine} ->
                            Module = <<Package/binary, "_", Id/binary>>,
                            examples_validate_identifier(Module, Path, Number),
                            Collecting = {collecting, Package, Module,
                                          AnnotationLine, []},
                            examples_parse_lines(Rest, Path, Number + 1, none,
                                        Collecting, Examples)
                    end;
                _ ->
                    examples_ensure(Pending =:= none,
                           {annotation_not_followed_by_fence, Path, Number}),
                    examples_parse_lines(Rest, Path, Number + 1, none, none, Examples)
            end
    end;
examples_parse_lines([<<"```">> | Rest], Path, Number, Pending,
            {collecting, Package, Module, AnnotationLine, Reversed}, Examples) ->
    examples_ensure(length(Examples) < 256, invalid_example_count),
    Source = iolist_to_binary(lists:join(<<"\n">>, lists:reverse(Reversed))),
    examples_ensure(byte_size(Source) =< 524288, example_source_limit),
    examples_ensure(binary:match(Source, <<"pub fn main">>) =/= nomatch,
           {example_missing_main, Path, AnnotationLine}),
    Example = #{package => Package, module => Module,
                document => unicode:characters_to_binary(Path),
                line => AnnotationLine,
                sha256 => binary:encode_hex(crypto:hash(sha256, Source)), source => Source},
    examples_parse_lines(Rest, Path, Number + 1, Pending, none,
                [Example | Examples]);
examples_parse_lines([Line | Rest], Path, Number, Pending,
            {collecting, Package, Module, AnnotationLine, Reversed}, Examples) ->
    examples_parse_lines(Rest, Path, Number + 1, Pending,
                {collecting, Package, Module, AnnotationLine,
                 [Line | Reversed]}, Examples).

examples_annotation(Line) ->
    Pattern = <<"^<!-- example: package=([a-z0-9_]+) id=([a-z0-9_]+) -->$">>,
    case re:run(Line, Pattern, [{capture, [1, 2], binary}]) of
        {match, [Package, Id]} -> {ok, Package, Id};
        nomatch -> no
    end.

examples_validate_identifier(Value, Path, Line) ->
    case re:run(Value, <<"^[a-z][a-z0-9_]{0,127}$">>) of
        {match, _} -> ok;
        nomatch -> erlang:error({invalid_example_identifier, Path, Line, Value})
    end.

examples_sources() ->
    Markdown = examples_markdown_files(),
    examples_ensure(length(Markdown) =< 4096, too_many_markdown_files),
    {_, _, Groups} = lists:foldl(fun(Path, {Count, Bytes, Acc}) ->
        Group = examples_extract(Path),
        NextCount = Count + length(Group),
        NextBytes = Bytes + lists:sum([byte_size(maps:get(source, E)) || E <- Group]),
        examples_ensure(NextCount =< 256, invalid_example_count),
        examples_ensure(NextBytes =< 16777216, example_sources_limit),
        {NextCount, NextBytes, [Group | Acc]}
    end, {0, 0, []}, Markdown),
    Examples = lists:append(lists:reverse(Groups)),
    examples_ensure(Examples =/= [] andalso length(Examples) =< 256, invalid_example_count),
    examples_ensure(lists:sum([byte_size(maps:get(source, E)) || E <- Examples])
                        =< 16777216, example_sources_limit),
    examples_ensure(lists:all(fun(E) -> lists:member(maps:get(package, E),
        [<<"http">>, <<"http3">>, <<"quic_core">>]) end, Examples), unknown_example_package),
    Ids = [maps:get(module, Example) || Example <- Examples],
    examples_ensure(length(Ids) =:= length(lists:usort(Ids)), duplicate_example_module),
    {Markdown, Examples}.

examples_read(Path, Limit) ->
    examples_real_path(Path),
    {ok, #file_info{type = regular}} = file:read_link_info(Path),
    {ok, Handle} = file:open(Path, [read, raw, binary]),
    try
        case file:read(Handle, Limit + 1) of
            eof -> <<>>;
            {ok, Bytes} when byte_size(Bytes) =< Limit ->
                eof = file:read(Handle, 1), Bytes;
            _ -> erlang:error(example_input_limit)
        end
    after file:close(Handle) end.

examples_real_path(Path) ->
    lists:foldl(fun(Segment, Parent) ->
        Current = case Parent of [] -> Segment; _ -> filename:join(Parent, Segment) end,
        {ok, Info} = file:read_link_info(Current),
        examples_ensure(Info#file_info.type =/= symlink, symbolic_example_path),
        Current
    end, [], filename:split(filename:absname(Path))),
    ok.

examples_ensure(true, _) -> ok;
examples_ensure(false, Reason) -> erlang:error(Reason).
-endif.
