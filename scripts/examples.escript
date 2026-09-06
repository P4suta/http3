#!/usr/bin/env escript

%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-define(OUTPUT, "build/examples").

main([]) ->
    try run() of
        ok -> ok
    catch
        Class:Reason:Stacktrace ->
            io:format(standard_error, "documentation example gate failed: ~p:~p~n~p~n",
                      [Class, Reason, Stacktrace]),
            halt(1)
    end;
main(_) ->
    io:put_chars(standard_error, "usage: escript scripts/examples.escript\n"),
    halt(1).

run() ->
    reset_output(),
    Markdown = markdown_files(),
    Examples = lists:append([extract(Path) || Path <- Markdown]),
    ensure(Examples =/= [], no_documented_gleam_examples),
    Ids = [maps:get(module, Example) || Example <- Examples],
    ensure(length(Ids) =:= length(lists:usort(Ids)),
           {duplicate_example_module, Ids}),
    write_project(Examples),
    ok = filelib:ensure_dir(filename:join(?OUTPUT, "out/placeholder")),
    CompileOutput = run_command([
        "compile-package", "--target", "erlang", "--package", ?OUTPUT,
        "--out", filename:join(?OUTPUT, "out"), "--lib", "build/dev/erlang"
    ]),
    ensure(binary:match(CompileOutput, <<"warning:">>) =:= nomatch,
           {example_compiler_warning, CompileOutput}),
    add_runtime_paths(),
    lists:foreach(fun execute_example/1, Examples),
    ReportExamples = [maps:without([source], Example) || Example <- Examples],
    Report = #{status => <<"Ready">>, count => length(Examples),
               markdown_files_scanned => length(Markdown),
               examples => ReportExamples},
    ok = file:write_file(filename:join(?OUTPUT, "report.json"),
                         [json:encode(Report), <<"\n">>]),
    io:format("documentation examples: extracted, built, and ran ~B modules~n",
              [length(Examples)]),
    ok.

%% Every documented Markdown file in the repository, not a list of the places
%% examples happen to live today. A `gleam` block outside such a list is
%% extracted by nothing: it is never compiled, never run, and rots silently
%% while reading like verified documentation. Build outputs, vendored
%% dependencies, and dot-directories are the only things skipped.
markdown_files() ->
    Files = filelib:fold_files(".", ".*\\.md$", true,
                               fun(File, Acc) -> [File | Acc] end, []),
    lists:usort([normalise(File) || File <- Files, documented(File)]).

normalise("./" ++ Path) -> Path;
normalise(Path) -> Path.

documented(Path) ->
    Segments = filename:split(normalise(Path)),
    not lists:any(fun(Segment) ->
        Segment =:= "build" orelse Segment =:= "deps"
            orelse (Segment =/= "." andalso hd(Segment) =:= $.)
    end, Segments).

extract(Path) ->
    Lines = binary:split(read(Path), <<"\n">>, [global]),
    lists:reverse(parse_lines(Lines, Path, 1, none, none, [])).

parse_lines([], Path, _Line, _Pending, {collecting, _, _, _, _}, _Examples) ->
    erlang:error({unterminated_gleam_fence, Path});
parse_lines([], _Path, _Line, _Pending, none, Examples) -> Examples;
parse_lines([Line | Rest], Path, Number, Pending, none, Examples) ->
    case annotation(Line) of
        {ok, Package, Id} ->
            ensure(Pending =:= none, {unused_example_annotation, Path, Number}),
            parse_lines(Rest, Path, Number + 1, {Package, Id, Number}, none,
                        Examples);
        no ->
            case Line of
                <<"```gleam">> ->
                    case Pending of
                        none -> erlang:error({unannotated_gleam_fence,
                                              Path, Number});
                        {Package, Id, AnnotationLine} ->
                            Module = <<Package/binary, "_", Id/binary>>,
                            validate_identifier(Module, Path, Number),
                            Collecting = {collecting, Package, Module,
                                          AnnotationLine, []},
                            parse_lines(Rest, Path, Number + 1, none,
                                        Collecting, Examples)
                    end;
                _ ->
                    ensure(Pending =:= none,
                           {annotation_not_followed_by_fence, Path, Number}),
                    parse_lines(Rest, Path, Number + 1, none, none, Examples)
            end
    end;
parse_lines([<<"```">> | Rest], Path, Number, Pending,
            {collecting, Package, Module, AnnotationLine, Reversed}, Examples) ->
    Source = iolist_to_binary(lists:join(<<"\n">>, lists:reverse(Reversed))),
    ensure(binary:match(Source, <<"pub fn main">>) =/= nomatch,
           {example_missing_main, Path, AnnotationLine}),
    Example = #{package => Package, module => Module,
                document => unicode:characters_to_binary(Path),
                line => AnnotationLine,
                sha256 => hex(crypto:hash(sha256, Source)), source => Source},
    parse_lines(Rest, Path, Number + 1, Pending, none,
                [Example | Examples]);
parse_lines([Line | Rest], Path, Number, Pending,
            {collecting, Package, Module, AnnotationLine, Reversed}, Examples) ->
    parse_lines(Rest, Path, Number + 1, Pending,
                {collecting, Package, Module, AnnotationLine,
                 [Line | Reversed]}, Examples).

annotation(Line) ->
    Pattern = <<"^<!-- example: package=([a-z0-9_]+) id=([a-z0-9_]+) -->$">>,
    case re:run(Line, Pattern, [{capture, [1, 2], binary}]) of
        {match, [Package, Id]} -> {ok, Package, Id};
        nomatch -> no
    end.

validate_identifier(Value, Path, Line) ->
    case re:run(Value, <<"^[a-z][a-z0-9_]*$">>) of
        {match, _} -> ok;
        nomatch -> erlang:error({invalid_example_identifier, Path, Line, Value})
    end.

write_project(Examples) ->
    Manifest = <<
        "name = \"documentation_examples\"\n"
        "version = \"0.0.0\"\n"
        "target = \"erlang\"\n"
        "gleam = \">= 1.18.1\"\n\n"
        "[dependencies]\n"
        "http = { path = \"../..\" }\n"
        "http3 = { path = \"../../packages/http3\" }\n"
        "quic_core = { path = \"../../packages/quic_core\" }\n"
        "gleam_http = \">= 4.3.0 and < 5.0.0\"\n"
        "gleam_stdlib = \">= 1.0.0 and < 2.0.0\"\n"
    >>,
    ok = filelib:ensure_dir(filename:join(?OUTPUT, "src/placeholder")),
    ok = file:write_file(filename:join(?OUTPUT, "gleam.toml"), Manifest),
    ok = file:write_file(filename:join(?OUTPUT, "manifest.toml"),
                         example_lockfile()),
    lists:foreach(fun(Example) ->
        Path = filename:join([?OUTPUT, "src",
                              binary_to_list(maps:get(module, Example)) ++
                              ".gleam"]),
        ok = file:write_file(Path, [maps:get(source, Example), <<"\n">>])
    end, Examples).

example_lockfile() ->
    Root = read("manifest.toml"),
    [PackageSection, _RootRequirements] =
        binary:split(Root, <<"[requirements]\n">>),
    WithPaths = binary:replace(
        binary:replace(PackageSection,
                       <<"path = \"packages/http3\"">>,
                       <<"path = \"../../packages/http3\"">>, [global]),
        <<"path = \"packages/quic_core\"">>,
        <<"path = \"../../packages/quic_core\"">>, [global]),
    Http = <<
        "  { name = \"http\", version = \"0.1.0\", "
        "build_tools = [\"gleam\"], requirements = [\"gleam_erlang\", "
        "\"gleam_http\", \"gleam_stdlib\", \"http3\"], source = \"local\", "
        "path = \"../..\" },\n"
    >>,
    Packages = binary:replace(WithPaths, <<"packages = [\n">>,
                              <<"packages = [\n", Http/binary>>),
    Requirements = <<
        "[requirements]\n"
        "gleam_http = { version = \">= 4.3.0 and < 5.0.0\" }\n"
        "gleam_stdlib = { version = \">= 1.0.0 and < 2.0.0\" }\n"
        "http = { path = \"../..\" }\n"
        "http3 = { path = \"../../packages/http3\" }\n"
        "quic_core = { path = \"../../packages/quic_core\" }\n"
    >>,
    <<Packages/binary, Requirements/binary>>.

run_command(Arguments) ->
    Executable = case os:find_executable("gleam") of
        false -> erlang:error(gleam_not_found);
        Path -> Path
    end,
    Port = open_port({spawn_executable, Executable},
                     [binary, exit_status, use_stdio, stderr_to_stdout,
                      {args, Arguments}, {cd, filename:absname(".")}]),
    {Status, Output} = collect_port(Port, []),
    Bytes = iolist_to_binary(lists:reverse(Output)),
    case Status of
        0 -> Bytes;
        _ -> erlang:error({example_command_failed, Arguments, Status,
                           Bytes})
    end.

add_runtime_paths() ->
    Paths = [filename:join([?OUTPUT, "out", "ebin"]) |
             filelib:wildcard("build/dev/erlang/*/ebin")],
    lists:foreach(fun(Path) -> true = code:add_patha(filename:absname(Path)) end,
                  Paths).

execute_example(Example) ->
    Module = binary_to_atom(maps:get(module, Example)),
    Beam = filename:join([?OUTPUT, "out", "ebin",
                          atom_to_list(Module) ++ ".beam"]),
    ensure(filelib:is_regular(Beam), {missing_example_beam, Module, Beam}),
    case code:load_abs(filename:rootname(filename:absname(Beam), ".beam")) of
        {module, Module} -> ok;
        Error -> erlang:error({cannot_load_example, Module, Error})
    end,
    ensure(apply(Module, main, []) =:= nil,
           {example_main_did_not_return_nil, Module}).

collect_port(Port, Output) ->
    receive
        {Port, {data, Bytes}} -> collect_port(Port, [Bytes | Output]);
        {Port, {exit_status, Status}} -> {Status, Output}
    after 120000 ->
        port_close(Port),
        erlang:error(example_command_timeout)
    end.

reset_output() ->
    Expected = filename:join(filename:absname("build"), "examples"),
    case filename:absname(?OUTPUT) of
        Expected ->
            _ = file:del_dir_r(Expected),
            ok = filelib:ensure_dir(filename:join(Expected, "placeholder"));
        Unsafe -> erlang:error({unsafe_example_output, Unsafe})
    end.

read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

ensure(true, _Reason) -> ok;
ensure(false, Reason) -> erlang:error(Reason).
