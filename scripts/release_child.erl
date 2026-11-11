%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(release_child).
-export([compile_modules/5, compile_modules/6]).
-include("diagnostic_failure.hrl").

%% No application code runs in this compiler. Every input is fixed by the
%% parent, bounded and hash checked again after compilation. Warning text and
%% compiler terms never leave the child; only finite classifications do.
compile_modules(Files, Supports, Ebin, Path, Nonce) ->
    compile_modules(Files, Supports, Ebin, Path, Nonce, 134217728).

%% Compilation needs a different, declared budget from application execution.
%% Only these owned workers receive 1 GiB; consumer actors retain 256 MiB.
compile_modules(Files, Supports, Ebin, Path, Nonce, HeapWords) ->
    Result = try
        true = is_integer(HeapWords) andalso HeapWords > 0 andalso HeapWords =< 134217728,
        %% OTP's Core Erlang inliner spawns its own linked compiler worker.
        %% Set this compiler-only VM's default too, so that descendant receives
        %% the declared budget instead of the consumer VM's lower default.
        erlang:system_flag(max_heap_size, #{size => HeapWords, kill => true,
            error_logger => false, include_shared_binaries => true}),
        true = is_list(Files) andalso length(Files) > 0 andalso length(Files) =< 1024,
        true = is_list(Supports) andalso length(Supports) =< 2048,
        ok = stage(<<"input_support">>, fun() -> verify_supports(Supports) end),
        compile_all(Files, Supports, Ebin, HeapWords, [])
    catch Class:Reason:Stack ->
        (failure(Class, Reason, Stack))#{status => <<"Failed">>, modules => [],
            failed_module => <<"none">>}
    end,
    Report = Result#{schema => 2, nonce => Nonce,
        compiler_worker_heap_words => HeapWords,
        compiler_heap_includes_shared_binaries => true,
        compiler_workers_joined => true},
    ok = file:write_file(Path, [json:encode(Report), $\n], [exclusive]),
    halt(case maps:get(status, Result) of <<"Passed">> -> 0; _ -> 1 end).

compile_all([], Supports, _, _, Rows) ->
    try stage(<<"output_support">>, fun() -> verify_supports(Supports) end) of
        ok -> #{status => <<"Passed">>, modules => lists:reverse(Rows)}
    catch Class:Reason:Stack ->
        (failure(Class, Reason, Stack))#{status => <<"Failed">>,
            modules => lists:reverse(Rows), failed_module => <<"none">>}
    end;
compile_all([#{module := Name} = File | Rest], Supports, Ebin, HeapWords, Rows) ->
    %% The result travels only with DOWN: publication proves that the compiler
    %% worker has exited, including failure. No late result remains in a mailbox.
    {Worker, Monitor} = spawn_opt(fun() ->
        Result = try {passed, compile_one(File, Ebin)}
            catch Class:Reason:Stack -> {failed, failure(Class, Reason, Stack)} end,
        exit({release_compile_result, Result})
    end, [monitor, {fullsweep_after, 0}, {max_heap_size, #{size => HeapWords,
        kill => true, error_logger => false, include_shared_binaries => true}}]),
    receive
        {'DOWN', Monitor, process, Worker, {release_compile_result, {passed, Row}}} ->
            compile_all(Rest, Supports, Ebin, HeapWords, [Row | Rows]);
        {'DOWN', Monitor, process, Worker, {release_compile_result, {failed, Error}}} ->
            Error#{status => <<"Failed">>, modules => lists:reverse(Rows), failed_module => Name};
        {'DOWN', Monitor, process, Worker, Reason} ->
            Error = case Reason of killed -> <<"resource_limit">>; _ -> <<"compiler_worker_exit">> end,
            (fixed_failure(<<"compiler">>, Error))#{status => <<"Failed">>,
                modules => lists:reverse(Rows), failed_module => Name}
    end.

verify_supports(Supports) ->
    lists:foreach(fun(#{path := Path, sha256 := Hash}) ->
        Hash = digest(binary_to_list(Path))
    end, Supports), ok.

compile_one(#{module := Name, path := Path, sha256 := Expected}, Ebin) ->
    Source = binary_to_list(Path),
    stage(<<"input_source">>, fun() -> Expected = digest(Source) end),
    Module = binary_to_atom(Name),
    Beam = stage(<<"compiler">>, fun() ->
        case compile:noenv_file(Source, [no_spawn_compiler_process, binary, return_errors, return_warnings,
            {i, filename:dirname(Source)}, {i, filename:join(filename:dirname(Ebin), "include")}]) of
            {ok, Module, Bytes, []} when is_binary(Bytes), byte_size(Bytes) =< 16777216 -> Bytes;
            {ok, Module, _, Warnings} -> throw({release_compile_failure,
                (fixed_failure(<<"compiler">>, <<"compiler_warnings">>))#{warning_count => count(Warnings)}});
            {error, Errors, Warnings} -> throw({release_compile_failure,
                (fixed_failure(<<"compiler">>, <<"compiler_errors">>))#{
                    error_count => count(Errors), warning_count => count(Warnings)}});
            _ -> throw({release_compile_failure, fixed_failure(<<"compiler">>, <<"compiler_result">>)})
        end
    end),
    stage(<<"output_source">>, fun() -> Expected = digest(Source) end),
    stage(<<"write_beam">>, fun() ->
        ok = file:write_file(filename:join(Ebin, binary_to_list(Name) ++ ".beam"), Beam, [exclusive])
    end),
    #{module => Name, generated_sha256 => Expected,
        beam_sha256 => binary:encode_hex(crypto:hash(sha256, Beam))}.

stage(Phase, Action) ->
    try Action() catch
        throw:{release_compile_failure, _} = Failure -> throw(Failure);
        Class:Reason:Stack -> throw({release_compile_failure,
            (failure(Class, Reason, Stack))#{phase => Phase}})
    end.

failure(throw, {release_compile_failure, Failure}, _) -> Failure;
failure(Class, Reason, Stack) ->
    Details = diagnostic_failure_details(Class, Reason, Stack),
    (fixed_failure(<<"validation">>, maps:get(exception_reason, Details)))#{
        exception_class => maps:get(exception_class, Details), stack_depth => min(length(Stack), 16)}.

fixed_failure(Phase, Classification) ->
    #{phase => Phase, classification => Classification, exception_class => <<"error">>,
        stack_depth => 0, error_count => 0, warning_count => 0}.

count(Items) when is_list(Items) -> min(length(Items), 65535);
count(_) -> 0.

digest(Path) ->
    {ok, File} = file:open(Path, [read, raw, binary]),
    try
        {ok, Bytes} = file:read(File, 16777217),
        true = byte_size(Bytes) =< 16777216,
        binary:encode_hex(crypto:hash(sha256, Bytes))
    after file:close(File) end.
