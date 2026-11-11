%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(examples_child).
-export([compile_examples/4, run_example/4]).
-include("diagnostic_failure.hrl").

compile_examples(Files, Ebin, Path, Nonce) ->
    Result = try
        true = length(Files) > 0 andalso length(Files) =< 256,
        Rows = [compile_example(File, Ebin) || File <- Files],
        #{schema => 1, nonce => Nonce, status => <<"Passed">>, modules => Rows}
    catch Class:Reason:Stack ->
        Details = diagnostic_failure_details(Class, Reason, Stack),
        #{schema => 1, nonce => Nonce, status => <<"Failed">>, modules => [],
          classification => maps:get(exception_reason, Details),
          exception_class => maps:get(exception_class, Details),
          stack_depth => erlang:min(length(Stack), 16)}
    end,
    ok = file:write_file(Path, [json:encode(Result), $\n], [exclusive]),
    halt(case maps:get(status, Result) of <<"Passed">> -> 0; _ -> 1 end).

compile_example(#{module := Name, path := Source, sha256 := Expected}, Ebin) ->
    {ok, Input} = file:read_file(Source),
    Expected = hex(crypto:hash(sha256, Input)),
    Module = binary_to_atom(Name),
    {ok, Module, Beam, []} = compile:file(Source,
        [binary, return_errors, return_warnings,
         {i, filename:dirname(Source)}, {i, filename:join(filename:dirname(Ebin), "include")}]),
    true = lists:member({main, 0}, beam_exports(Beam)),
    {ok, After} = file:read_file(Source),
    Expected = hex(crypto:hash(sha256, After)),
    ok = file:write_file(filename:join(Ebin, binary_to_list(Name) ++ ".beam"), Beam, [exclusive]),
    #{module => Name, generated_sha256 => Expected,
      beam_sha256 => hex(crypto:hash(sha256, Beam))}.

beam_exports(Beam) ->
    {ok, {_, [{exports, Exports}]}} = beam_lib:chunks(Beam, [exports]),
    Exports.

run_example(Name, Path, Nonce, Milliseconds) ->
    Module = binary_to_atom(Name),
    Units = [#{module => Name, function => <<"main">>, kind => <<"test">>}],
    Run = fun() ->
        case apply(Module, main, []) of
            nil -> ok;
            _ -> erlang:error(example_main_returned_non_nil)
        end
    end,
    Descriptors = [{<<"documented main">>, {timeout, Milliseconds / 1000, Run}}],
    qualification_eunit_listener:run_descriptors(Units, Descriptors, Path, Nonce).

hex(Bytes) -> binary:encode_hex(Bytes).
