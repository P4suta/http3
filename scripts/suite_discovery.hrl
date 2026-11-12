%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_SUITE_DISCOVERY_HRL).
-define(HTTP_SUITE_DISCOVERY_HRL, true).
-compile({nowarn_unused_function, [
    {suite_inventory_unchanged, 3},
    {suite_require_inventory_unchanged, 3},
    {suite_inventory_units, 1},
    {suite_source_modules, 1},
    {suite_source_module, 2},
    {suite_beam_units, 2},
    {suite_inventory_document_valid, 1},
    {suite_inventory_document_modules, 1},
    {suite_inventory_document_units, 1},
    {suite_inventory_from_document, 1},
    {suite_relation_from_document, 1},
    {suite_unit_from_document, 1}
]}).

%% Build one fail-closed relation from every test source to its generated BEAM
%% and exported EUnit entry points. The relation is retained in evidence because
%% a count alone cannot prove that a source was compiled or executed.
suite_inventory(Root, Ebin) ->
    Sources = suite_source_inventory(Root),
    Relations = [suite_source_beam_relation(Ebin, Source) || Source <- Sources],
    Units = lists:sort(fun suite_unit_less/2,
        lists:append([maps:get(units, Relation) || Relation <- Relations])),
    suite_inventory_ensure(length(Units) =< 10000, unit_limit_exceeded),
    PublicRelations = [maps:without([units], Relation) || Relation <- Relations],
    Inventory = #{schema => 1,
        source_files => length(Sources), modules => length(Relations),
        beam_files => length(Relations), configured_units => length(Units),
        relations => PublicRelations, units => Units,
        inventory_sha256 => suite_inventory_digest(Relations, Units)},
    suite_inventory_ensure(suite_inventory_schema_valid(Inventory),
                           internally_invalid_inventory),
    Inventory.

suite_inventory_units(Inventory) -> maps:get(units, Inventory).

suite_inventory_modules(Inventory) ->
    [maps:get(module, Relation) || Relation <- maps:get(relations, Inventory)].

suite_inventory_unchanged(Before, Root, Ebin) ->
    try suite_inventory(Root, Ebin) of
        After -> maps:get(inventory_sha256, Before) =:=
                     maps:get(inventory_sha256, After)
                 andalso Before =:= After
    catch _:_ -> false end.

suite_require_inventory_unchanged(Before, Root, Ebin) ->
    suite_inventory_ensure(suite_inventory_unchanged(Before, Root, Ebin),
                           stale_suite_inventory),
    ok.

suite_source_inventory(Root) ->
    Files = suite_source_paths(Root),
    suite_inventory_ensure(Files =/= [], no_test_sources),
    suite_inventory_ensure(length(Files) =< 10000, source_limit_exceeded),
    Sources = [suite_source_entry(Root, Path) || Path <- Files],
    %% A directory mutation during source reads must not silently change the
    %% suite represented by this inventory.
    Files = suite_source_paths(Root),
    suite_reject_duplicate_modules(Sources),
    Sources.

suite_source_paths(Root0) ->
    Root = filename:absname(Root0),
    {_Remaining, Files} = suite_walk_source_tree(Root, 0, 50000, []),
    lists:sort(Files).

suite_walk_source_tree(Path, Depth, Remaining, Acc) ->
    suite_inventory_ensure(Depth =< 64, source_tree_depth_limit),
    Before = suite_directory_info(Path),
    Names = case file:list_dir(Path) of
        {ok, Entries} -> lists:sort(Entries);
        {error, _} -> suite_inventory_error(source_tree_read_failed)
    end,
    suite_inventory_ensure(length(Names) =< Remaining,
                           source_tree_entry_limit),
    Result = lists:foldl(fun(Name, {Left, Paths}) ->
        suite_inventory_ensure(Left > 0, source_tree_entry_limit),
        suite_inventory_ensure(Name =/= "" andalso Name =/= "."
                               andalso Name =/= "..",
                               unsafe_source_path),
        Member = filename:join(Path, Name),
        case file:read_link_info(Member) of
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= directory ->
                suite_walk_source_tree(Member, Depth + 1, Left - 1, Paths);
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= regular ->
                case lists:member(filename:extension(Name), [".gleam", ".erl"]) of
                    true -> {Left - 1, [Member | Paths]};
                    false -> {Left - 1, Paths}
                end;
            {ok, Info} when element(1, Info) =:= file_info,
                            element(3, Info) =:= symlink ->
                suite_inventory_error(source_tree_link_rejected);
            {ok, _} ->
                suite_inventory_error(source_tree_special_file_rejected);
            {error, enoent} ->
                suite_inventory_error(source_tree_changed_while_reading);
            {error, _} ->
                suite_inventory_error(source_tree_inspection_failed)
        end
    end, {Remaining, Acc}, Names),
    After = suite_directory_info(Path),
    suite_inventory_ensure(suite_file_identity(Before) =:=
                           suite_file_identity(After),
                           source_tree_changed_while_reading),
    Result.

suite_directory_info(Path) ->
    case file:read_link_info(Path) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory -> Info;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            suite_inventory_error(source_tree_link_rejected);
        {ok, _} -> suite_inventory_error(source_tree_special_file_rejected);
        {error, enoent} -> suite_inventory_error(source_tree_missing);
        {error, _} -> suite_inventory_error(source_tree_inspection_failed)
    end.

%% Compatibility helpers are kept for older callers, but now inherit the
%% collision, declared-module, path, and BEAM checks above.
suite_source_modules(Root) ->
    [maps:get(module, Source) || Source <- suite_source_inventory(Root)].

suite_source_module(Root, Path) ->
    maps:get(module, suite_source_entry(Root, Path)).

suite_beam_units(Ebin, Name) ->
    maps:get(units, suite_beam_entry(Ebin, Name)).

suite_source_entry(Root, Path) ->
    Relative = suite_relative_path(Root, Path),
    Extension = filename:extension(Path),
    Bytes = suite_read_regular(Path, source),
    {Language, Module} = case Extension of
        ".erl" ->
            Expected = unicode:characters_to_binary(filename:basename(Path, ".erl")),
            {<<"erlang">>, suite_erlang_declared_module(Bytes, Expected)};
        ".gleam" ->
            Stem = filename:rootname(Relative, ".gleam"),
            {<<"gleam">>, unicode:characters_to_binary(
                string:replace(Stem, "/", "@", all))};
        _ -> suite_inventory_error(unsupported_source_extension)
    end,
    suite_inventory_ensure(suite_safe_module(Module), unsafe_module_name),
    #{source => unicode:characters_to_binary(Relative), language => Language,
      module => Module, source_sha256 => suite_inventory_sha256(Bytes),
      source_bytes => byte_size(Bytes)}.

suite_source_beam_relation(Ebin, Source) ->
    Beam = suite_beam_entry(Ebin, maps:get(module, Source)),
    Source#{beam => maps:get(beam, Beam),
            beam_sha256 => maps:get(beam_sha256, Beam),
            beam_bytes => maps:get(beam_bytes, Beam),
            unit_count => length(maps:get(units, Beam)),
            units => maps:get(units, Beam)}.

suite_beam_entry(Ebin, Name) ->
    suite_inventory_ensure(suite_safe_module(Name), unsafe_module_name),
    BeamName = binary_to_list(Name) ++ ".beam",
    Beam = filename:join(Ebin, BeamName),
    Bytes = suite_read_regular(Beam, beam),
    {Module, Exports} = case beam_lib:chunks(Bytes, [exports]) of
        {ok, {BeamModule, [{exports, BeamExports}]}}
          when is_atom(BeamModule), is_list(BeamExports) ->
            suite_inventory_ensure(length(BeamExports) =< 100000,
                                   beam_export_limit_exceeded),
            {BeamModule, BeamExports};
        {error, beam_lib, _} -> suite_inventory_error(malformed_beam);
        _ -> suite_inventory_error(unreadable_beam_metadata)
    end,
    Actual = atom_to_binary(Module),
    suite_inventory_ensure(suite_safe_module(Actual), unsafe_beam_module),
    suite_inventory_ensure(Actual =:= Name, beam_module_mismatch),
    Units0 = [#{module => Name, function => atom_to_binary(Function), kind => Kind}
        || {Function, 0} <- Exports,
           Kind <- suite_test_kind(atom_to_binary(Function))],
    Units = lists:sort(fun suite_unit_less/2, Units0),
    suite_inventory_ensure(lists:all(fun suite_discovery_unit_schema/1, Units),
                           unsafe_eunit_export),
    #{beam => unicode:characters_to_binary(BeamName),
      beam_sha256 => suite_inventory_sha256(Bytes),
      beam_bytes => byte_size(Bytes),
      units => Units}.

suite_erlang_declared_module(Bytes, Expected) ->
    Pattern = <<"(?m)^[\\t ]*-module[\\t ]*\\([\\t ]*(?:([a-z][a-zA-Z0-9_@]*)|'([a-z][a-zA-Z0-9_@]*)')[\\t ]*\\)[\\t ]*\\.">>,
    Matches = case re:run(Bytes, Pattern, [global, {capture, [1, 2], binary}]) of
        {match, Captures} -> [suite_module_capture(Row) || Row <- Captures];
        nomatch -> []
    end,
    case Matches of
        [Expected] -> Expected;
        [_] -> suite_inventory_error(erlang_declared_module_mismatch);
        [] -> suite_inventory_error(erlang_module_declaration_missing);
        _ -> suite_inventory_error(erlang_module_declaration_ambiguous)
    end.

suite_module_capture([First, _Second])
  when is_binary(First), byte_size(First) > 0 ->
    First;
suite_module_capture([_First, Second])
  when is_binary(Second), byte_size(Second) > 0 ->
    Second;
suite_module_capture(_) ->
    suite_inventory_error(erlang_module_declaration_ambiguous).

suite_reject_duplicate_modules(Sources) ->
    {_Seen, Duplicate} = lists:foldl(fun(Source, {Seen, Found}) ->
        Module = maps:get(module, Source),
        case maps:is_key(Module, Seen) of
            true -> {Seen, true};
            false -> {Seen#{Module => true}, Found}
        end
    end, {#{}, false}, Sources),
    suite_inventory_ensure(not Duplicate, duplicate_source_module),
    ok.

suite_relative_path(Root0, Path0) ->
    Root = filename:split(filename:absname(Root0)),
    Path = filename:split(filename:absname(Path0)),
    suite_inventory_ensure(lists:prefix(Root, Path), source_outside_test_root),
    Parts = lists:nthtail(length(Root), Path),
    suite_inventory_ensure(Parts =/= [] andalso
        lists:all(fun(Part) -> Part =/= "" andalso Part =/= "."
                                   andalso Part =/= ".." end, Parts),
        unsafe_source_path),
    string:join(Parts, "/").

suite_read_regular(Path, Kind) ->
    Initial = suite_regular_info(Path, Kind),
    Size = element(2, Initial),
    suite_inventory_ensure(is_integer(Size) andalso Size >= 0
                           andalso Size =< 16777216,
                           suite_kind_error(Kind, size_rejected)),
    suite_inventory_ensure(element(9, Initial) =:= 1,
                           suite_kind_error(Kind, hardlink_rejected)),
    File = case file:open(Path, [read, binary, raw]) of
        {ok, Handle} -> Handle;
        {error, _} -> suite_inventory_error(suite_kind_error(Kind, read_failed))
    end,
    {Bytes, Finished} = try
        Opened = case file:read_file_info(File) of
            {ok, Info} -> Info;
            {error, _} -> suite_inventory_error(
                suite_kind_error(Kind, inspection_failed))
        end,
        suite_inventory_ensure(element(3, Opened) =:= regular andalso
                               element(9, Opened) =:= 1 andalso
                               suite_file_identity(Initial) =:=
                                   suite_file_identity(Opened),
                               suite_kind_error(Kind, changed_while_reading)),
        Captured = suite_read_bounded(File, Size, [], Kind),
        FinalHandle = case file:read_file_info(File) of
            {ok, Info2} -> Info2;
            {error, _} -> suite_inventory_error(
                suite_kind_error(Kind, inspection_failed))
        end,
        suite_inventory_ensure(suite_file_identity(Opened) =:=
                               suite_file_identity(FinalHandle) andalso
                               byte_size(Captured) =:= Size,
                               suite_kind_error(Kind, changed_while_reading)),
        {Captured, FinalHandle}
    after
        ok = file:close(File)
    end,
    FinalPath = suite_regular_info(Path, Kind),
    suite_inventory_ensure(suite_file_identity(Finished) =:=
                           suite_file_identity(FinalPath),
                           suite_kind_error(Kind, changed_while_reading)),
    Bytes.

suite_regular_info(Path, Kind) ->
    suite_regular_components(
        filename:split(filename:absname(Path)), "", Kind).

suite_regular_components([Name], Parent, Kind) ->
    Current = suite_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= regular -> Info;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            suite_inventory_error(suite_kind_error(Kind, link_rejected));
        {ok, _} ->
            suite_inventory_error(suite_kind_error(Kind, special_file_rejected));
        {error, enoent} ->
            suite_inventory_error(suite_kind_error(Kind, missing));
        {error, _} ->
            suite_inventory_error(suite_kind_error(Kind, inspection_failed))
    end;
suite_regular_components([Name | Rest], Parent, Kind) ->
    Current = suite_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            suite_regular_components(Rest, Current, Kind);
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            suite_inventory_error(
                suite_kind_error(Kind, parent_link_rejected));
        {ok, _} ->
            suite_inventory_error(
                suite_kind_error(Kind, parent_special_file_rejected));
        {error, enoent} ->
            suite_inventory_error(suite_kind_error(Kind, missing));
        {error, _} ->
            suite_inventory_error(suite_kind_error(Kind, inspection_failed))
    end;
suite_regular_components([], _Parent, _Kind) ->
    suite_inventory_error(unsafe_source_path).

suite_join_component("", Name) -> Name;
suite_join_component(Parent, Name) -> filename:join(Parent, Name).

suite_read_bounded(File, Remaining, Acc, Kind) when Remaining >= 0 ->
    Request = erlang:min(Remaining + 1, 65536),
    case file:read(File, Request) of
        eof -> iolist_to_binary(lists:reverse(Acc));
        {ok, Chunk} when byte_size(Chunk) > 0,
                         byte_size(Chunk) =< Remaining ->
            suite_read_bounded(File, Remaining - byte_size(Chunk),
                               [Chunk | Acc], Kind);
        {ok, _} -> suite_inventory_error(
            suite_kind_error(Kind, changed_while_reading));
        {error, _} -> suite_inventory_error(suite_kind_error(Kind, read_failed))
    end.

suite_file_identity(Info) ->
    %% atime (element 5) is deliberately excluded.  Reading a file or listing
    %% a directory may update it on otherwise immutable inputs, especially on
    %% Unix filesystems using relatime.  Size, type, mode, mtime, ctime, link
    %% count, device and inode still detect replacement and relevant mutation.
    {element(2, Info), element(3, Info), element(4, Info), element(6, Info),
     element(7, Info), element(8, Info), element(9, Info), element(10, Info),
     element(11, Info), element(12, Info)}.

suite_kind_error(source, size_rejected) -> source_size_rejected;
suite_kind_error(source, changed_while_reading) -> source_changed_while_reading;
suite_kind_error(source, read_failed) -> source_read_failed;
suite_kind_error(source, link_rejected) -> source_link_rejected;
suite_kind_error(source, parent_link_rejected) -> source_parent_link_rejected;
suite_kind_error(source, hardlink_rejected) -> source_hardlink_rejected;
suite_kind_error(source, special_file_rejected) -> source_special_file_rejected;
suite_kind_error(source, parent_special_file_rejected) ->
    source_parent_special_file_rejected;
suite_kind_error(source, missing) -> source_missing;
suite_kind_error(source, inspection_failed) -> source_inspection_failed;
suite_kind_error(beam, size_rejected) -> beam_size_rejected;
suite_kind_error(beam, changed_while_reading) -> beam_changed_while_reading;
suite_kind_error(beam, read_failed) -> beam_read_failed;
suite_kind_error(beam, link_rejected) -> beam_link_rejected;
suite_kind_error(beam, parent_link_rejected) -> beam_parent_link_rejected;
suite_kind_error(beam, hardlink_rejected) -> beam_hardlink_rejected;
suite_kind_error(beam, special_file_rejected) -> beam_special_file_rejected;
suite_kind_error(beam, parent_special_file_rejected) ->
    beam_parent_special_file_rejected;
suite_kind_error(beam, missing) -> beam_missing;
suite_kind_error(beam, inspection_failed) -> beam_inspection_failed.

suite_test_kind(Name) ->
    Text = binary_to_list(Name),
    case {lists:suffix("_test", Text), lists:suffix("_test_", Text)} of
        {true, _} -> [<<"test">>];
        {_, true} -> [<<"generator">>];
        _ -> []
    end.

suite_unit_less(Left, Right) ->
    {maps:get(module, Left), maps:get(function, Left), maps:get(kind, Left)} <
        {maps:get(module, Right), maps:get(function, Right), maps:get(kind, Right)}.

suite_discovery_unit_schema(Unit) ->
    lists:sort(maps:keys(Unit)) =:= lists:sort([module, function, kind])
        andalso suite_safe_module(maps:get(module, Unit, invalid))
        andalso suite_safe_function(maps:get(function, Unit, invalid))
        andalso lists:member(maps:get(kind, Unit, invalid),
                            [<<"test">>, <<"generator">>]).

suite_safe_module(Value) when is_binary(Value), byte_size(Value) > 0,
                                   byte_size(Value) =< 128 ->
    re:run(Value, <<"^[a-z][a-z0-9_]*(?:@[a-z][a-z0-9_]*)*$">>,
           [{capture, none}]) =:= match;
suite_safe_module(_) -> false.

suite_safe_function(Value) when is_binary(Value), byte_size(Value) > 0,
                                     byte_size(Value) =< 128 ->
    re:run(Value, <<"^[a-zA-Z0-9_@]+$">>, [{capture, none}]) =:= match;
suite_safe_function(_) -> false.

suite_inventory_digest(Relations, Units) ->
    RelationFrames = [suite_relation_frame(Relation) || Relation <- Relations],
    UnitFrames = [suite_unit_frame(Unit) || Unit <- Units],
    suite_inventory_sha256([<<"http-suite-inventory-v1", 0,
                    (length(Relations)):64/unsigned-big,
                    (length(Units)):64/unsigned-big>>,
                  RelationFrames, UnitFrames]).

suite_relation_frame(Relation) ->
    suite_fields_frame([maps:get(source, Relation),
        maps:get(language, Relation), maps:get(module, Relation),
        maps:get(source_sha256, Relation), maps:get(beam, Relation),
        maps:get(beam_sha256, Relation),
        integer_to_binary(maps:get(source_bytes, Relation)),
        integer_to_binary(maps:get(beam_bytes, Relation)),
        integer_to_binary(maps:get(unit_count, Relation))]).

suite_unit_frame(Unit) ->
    suite_fields_frame([maps:get(module, Unit), maps:get(function, Unit),
                        maps:get(kind, Unit)]).

suite_fields_frame(Fields) ->
    [<<(length(Fields)):32/unsigned-big>> |
     [<<(byte_size(Field)):64/unsigned-big, Field/binary>> || Field <- Fields]].

suite_inventory_sha256(Bytes) ->
    binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).

suite_inventory_schema_valid(Inventory) ->
    try
        true = lists:sort(maps:keys(Inventory)) =:= lists:sort([
            schema, source_files, modules, beam_files, configured_units,
            relations, units, inventory_sha256]),
        1 = maps:get(schema, Inventory),
        Relations = maps:get(relations, Inventory),
        Units = maps:get(units, Inventory),
        Count = maps:get(source_files, Inventory),
        true = is_integer(Count) andalso Count > 0 andalso Count =< 10000,
        Count = maps:get(modules, Inventory),
        Count = maps:get(beam_files, Inventory),
        Count = length(Relations),
        true = maps:get(configured_units, Inventory) =:= length(Units),
        true = lists:all(fun suite_relation_schema/1, Relations),
        true = lists:all(fun suite_discovery_unit_schema/1, Units),
        true = suite_relations_ordered_unique(Relations),
        true = suite_units_ordered_unique(Units),
        true = suite_relation_unit_counts_valid(Relations, Units),
        Digest = maps:get(inventory_sha256, Inventory),
        true = is_binary(Digest) andalso byte_size(Digest) =:= 64,
        true = re:run(Digest, <<"^[0-9a-f]{64}$">>,
                      [{capture, none}]) =:= match,
        Digest = suite_inventory_digest(Relations, Units),
        true
    catch _:_ -> false end.

suite_inventory_document_valid(Document) ->
    try
        Inventory = suite_inventory_from_document(Document),
        true = suite_inventory_schema_valid(Inventory),
        true
    catch _:_ -> false end.

suite_inventory_document_modules(Document) ->
    suite_inventory_modules(suite_inventory_from_document(Document)).

suite_inventory_document_units(Document) ->
    suite_inventory_units(suite_inventory_from_document(Document)).

suite_inventory_from_document(Document) ->
    true = lists:sort(maps:keys(Document)) =:= lists:sort([
        <<"schema">>, <<"source_files">>, <<"modules">>, <<"beam_files">>,
        <<"configured_units">>, <<"relations">>, <<"units">>,
        <<"inventory_sha256">>]),
    #{schema => maps:get(<<"schema">>, Document),
      source_files => maps:get(<<"source_files">>, Document),
      modules => maps:get(<<"modules">>, Document),
      beam_files => maps:get(<<"beam_files">>, Document),
      configured_units => maps:get(<<"configured_units">>, Document),
      relations => [suite_relation_from_document(Relation)
                    || Relation <- maps:get(<<"relations">>, Document)],
      units => [suite_unit_from_document(Unit)
                || Unit <- maps:get(<<"units">>, Document)],
      inventory_sha256 => maps:get(<<"inventory_sha256">>, Document)}.

suite_relation_from_document(Relation) ->
    true = lists:sort(maps:keys(Relation)) =:= lists:sort([
        <<"source">>, <<"language">>, <<"module">>, <<"source_sha256">>,
        <<"source_bytes">>, <<"beam">>, <<"beam_sha256">>, <<"beam_bytes">>,
        <<"unit_count">>]),
    #{source => maps:get(<<"source">>, Relation),
      language => maps:get(<<"language">>, Relation),
      module => maps:get(<<"module">>, Relation),
      source_sha256 => maps:get(<<"source_sha256">>, Relation),
      source_bytes => maps:get(<<"source_bytes">>, Relation),
      beam => maps:get(<<"beam">>, Relation),
      beam_sha256 => maps:get(<<"beam_sha256">>, Relation),
      beam_bytes => maps:get(<<"beam_bytes">>, Relation),
      unit_count => maps:get(<<"unit_count">>, Relation)}.

suite_unit_from_document(Unit) ->
    true = lists:sort(maps:keys(Unit)) =:= lists:sort([
        <<"module">>, <<"function">>, <<"kind">>]),
    #{module => maps:get(<<"module">>, Unit),
      function => maps:get(<<"function">>, Unit),
      kind => maps:get(<<"kind">>, Unit)}.

suite_relation_schema(Relation) ->
    try
        true = lists:sort(maps:keys(Relation)) =:= lists:sort([
            source, language, module, source_sha256, source_bytes,
            beam, beam_sha256, beam_bytes, unit_count]),
        Source = maps:get(source, Relation),
        Beam = maps:get(beam, Relation),
        true = is_binary(Source) andalso byte_size(Source) > 0
            andalso byte_size(Source) =< 512,
        true = suite_safe_relative_source(Source),
        true = is_binary(Beam) andalso byte_size(Beam) > 5
            andalso byte_size(Beam) =< 133,
        true = lists:member(maps:get(language, Relation),
                            [<<"gleam">>, <<"erlang">>]),
        Module = maps:get(module, Relation),
        true = suite_safe_module(Module),
        true = Beam =:= <<Module/binary, ".beam">>,
        true = suite_relation_source_module_valid(
            Source, maps:get(language, Relation), Module),
        true = suite_digest_value(maps:get(source_sha256, Relation)),
        true = suite_digest_value(maps:get(beam_sha256, Relation)),
        true = suite_bounded_count(maps:get(source_bytes, Relation), 16777216),
        true = suite_bounded_count(maps:get(beam_bytes, Relation), 16777216),
        true = suite_bounded_count(maps:get(unit_count, Relation), 10000),
        true
    catch _:_ -> false end.

suite_relations_ordered_unique(Relations) ->
    Keys = [{maps:get(source, Relation), maps:get(module, Relation)}
            || Relation <- Relations],
    Keys =:= lists:sort(Keys)
        andalso length(Keys) =:= length(lists:usort(Keys))
        andalso length(Relations) =:=
            length(lists:usort([maps:get(module, Relation)
                                || Relation <- Relations])).

suite_units_ordered_unique(Units) ->
    Keys = [{maps:get(module, Unit), maps:get(function, Unit),
             maps:get(kind, Unit)} || Unit <- Units],
    Keys =:= lists:sort(Keys)
        andalso length(Keys) =:= length(lists:usort(Keys)).

suite_relation_unit_counts_valid(Relations, Units) ->
    lists:all(fun(Relation) ->
        Module = maps:get(module, Relation),
        maps:get(unit_count, Relation) =:=
            length([ok || Unit <- Units, maps:get(module, Unit) =:= Module])
    end, Relations)
    andalso lists:all(fun(Unit) ->
        lists:any(fun(Relation) ->
            maps:get(module, Relation) =:= maps:get(module, Unit)
        end, Relations)
    end, Units).

suite_relation_source_module_valid(Source, <<"gleam">>, Module) ->
    case filename:extension(binary_to_list(Source)) of
        ".gleam" ->
            Stem = filename:rootname(binary_to_list(Source), ".gleam"),
            unicode:characters_to_binary(
                string:replace(Stem, "/", "@", all)) =:= Module;
        _ -> false
    end;
suite_relation_source_module_valid(Source, <<"erlang">>, Module) ->
    filename:extension(binary_to_list(Source)) =:= ".erl"
        andalso unicode:characters_to_binary(filename:basename(
            binary_to_list(Source), ".erl")) =:= Module;
suite_relation_source_module_valid(_, _, _) -> false.

suite_safe_relative_source(Value) when is_binary(Value) ->
    re:run(Value,
        <<"^[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*\\.(?:gleam|erl)$">>,
        [{capture, none}]) =:= match
        andalso not lists:member(<<"..">>, binary:split(
            Value, <<"/">>, [global]));
suite_safe_relative_source(_) -> false.

suite_digest_value(Value) ->
    is_binary(Value) andalso byte_size(Value) =:= 64 andalso
        re:run(Value, <<"^[0-9a-f]{64}$">>, [{capture, none}]) =:= match.

suite_bounded_count(Value, Maximum) ->
    is_integer(Value) andalso Value >= 0 andalso Value =< Maximum.

suite_inventory_ensure(true, _) -> ok;
suite_inventory_ensure(false, Reason) -> suite_inventory_error(Reason).

suite_inventory_error(Reason) ->
    erlang:error({suite_inventory_rejected, Reason}).
-endif.
