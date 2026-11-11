%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

requirement_symbol_present(Path, Symbol) ->
    case filename:extension(binary_to_list(Path)) of
        ".erl" -> requirement_erlang_symbol(Path, Symbol);
        ".escript" -> requirement_erlang_symbol(Path, Symbol);
        _ ->
            %% Gleam references currently include constructors and types as
            %% well as functions. Their declaration validation is separate.
            BaseSymbol = hd(binary:split(Symbol, <<"/">>)),
            {ok, Bytes} = file:read_file(binary_to_list(Path)),
            symbol_present(BaseSymbol, Bytes)
    end.

requirement_erlang_symbol(Path, Symbol) ->
    Functions = requirement_erlang_functions(Path),
    case binary:split(Symbol, <<"/">>) of
        [Name] -> lists:any(fun({Function, _Arity}) -> Function =:= Name end, Functions);
        [Name, Arity] -> lists:member({Name, binary_to_integer(Arity)}, Functions)
    end.

requirement_erlang_functions(Path) ->
    Key = {requirement_function_inventory, Path},
    case get(Key) of
        undefined ->
            Functions = requirement_parse_erlang(Path),
            put(Key, Functions),
            Functions;
        Functions -> Functions
    end.

requirement_parse_erlang(Path) ->
    Name = binary_to_list(Path),
    case file:open(Name, [read]) of
        {ok, File} ->
            try
                Location = case filename:extension(Name) of
                    ".escript" ->
                        case file:read_line(File) of
                            {ok, [$#, $! | _]} -> 2;
                            _ -> {ok, 0} = file:position(File, bof), 1
                        end;
                    _ -> 1
                end,
                case epp:open([{name, Name}, {fd, File}, {location, Location},
                               {includes, [filename:dirname(Name)]}]) of
                    {ok, Epp} ->
                        try requirement_erlang_forms(Epp, filename:absname(Name), true, [], Path)
                        after ok = epp:close(Epp) end;
                    _ -> erlang:error({invalid_evidence_source, Path})
                end
            after ok = file:close(File) end;
        _ -> erlang:error({invalid_evidence_source, Path})
    end.

requirement_erlang_forms(Epp, Root, InSource, Functions, Path) ->
    %% epp expands macros and excludes inactive branches. Parsing never
    %% compiles or executes the referenced functions or parse transforms.
    %% Included function definitions belong to the included file, not Root.
    case epp:parse_erl_form(Epp) of
        {ok, {attribute, Annotation, file, {Source, _}}} ->
            requirement_erlang_forms(
                Epp, Root,
                requirement_file_origin(Annotation, Source, Root, InSource),
                Functions, Path);
        {ok, {function, _, Name, Arity, _Clauses}} when InSource ->
            requirement_erlang_forms(Epp, Root, InSource,
                                     [{atom_to_binary(Name), Arity} | Functions], Path);
        {ok, _} -> requirement_erlang_forms(Epp, Root, InSource, Functions, Path);
        {eof, _} -> lists:usort(Functions);
        _ -> erlang:error({invalid_evidence_source, Path})
    end.

requirement_file_origin(Annotation, Source, Root, InSource) ->
    %% epp marks source-authored -file attributes as generated. They are line
    %% metadata and must not be allowed to forge a transition out of an
    %% include (or hide a later declaration in Root). epp's own ungenerated
    %% file attributes are the trusted include-entry and include-return
    %% boundaries.
    case erl_anno:generated(Annotation) of
        true -> InSource;
        false -> filename:absname(Source) =:= Root
    end.
