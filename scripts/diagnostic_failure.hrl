%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_DIAGNOSTIC_FAILURE).
-define(HTTP_DIAGNOSTIC_FAILURE, true).

%% Retain a bounded code location and classification, never exception payloads,
%% stack arguments, source paths, process identifiers, sockets, or credentials.
diagnostic_failure_details(Class, Reason, Stack) ->
    #{exception_class => diagnostic_exception_class(Class),
      exception_reason => diagnostic_failure_category(Reason),
      stacktrace => iolist_to_binary(json:encode(diagnostic_stack(Stack)))}.

diagnostic_exception_class(error) -> <<"error">>;
diagnostic_exception_class(exit) -> <<"exit">>;
diagnostic_exception_class(throw) -> <<"throw">>;
diagnostic_exception_class(_) -> <<"unknown">>.

diagnostic_failure_category({badmatch, _}) -> <<"pattern_mismatch">>;
diagnostic_failure_category({case_clause, _}) -> <<"unexpected_variant">>;
diagnostic_failure_category(#{gleam_error := assert}) -> <<"assertion_failed">>;
%% EUnit assertion properties may contain payloads, process identifiers, and
%% secrets. Classify only the fixed assertion tag; never inspect its values.
%% stdlib assert.hrl aliases (including assertNot, assertError/Exit/Throw) and
%% EUnit deferred assertions share these tags. command_failed is intentionally
%% excluded: executing a failed command is not itself an assertion.
diagnostic_failure_category({assert, _}) -> <<"assertion_failed">>;
diagnostic_failure_category({assertEqual, _}) -> <<"assertion_failed">>;
diagnostic_failure_category({assertNotEqual, _}) -> <<"assertion_failed">>;
diagnostic_failure_category({assertMatch, _}) -> <<"assertion_failed">>;
diagnostic_failure_category({assertNotMatch, _}) -> <<"assertion_failed">>;
diagnostic_failure_category({assertException, _}) -> <<"assertion_failed">>;
diagnostic_failure_category({assertNotException, _}) -> <<"assertion_failed">>;
diagnostic_failure_category({assertCmd_failed, _}) -> <<"assertion_failed">>;
diagnostic_failure_category({assertCmdOutput_failed, _}) -> <<"assertion_failed">>;
diagnostic_failure_category(#{gleam_error := let_assert}) -> <<"pattern_mismatch">>;
diagnostic_failure_category(#{gleam_error := panic}) -> <<"callback_failed">>;
diagnostic_failure_category(badarg) -> <<"invalid_argument">>;
diagnostic_failure_category(function_clause) -> <<"invalid_argument">>;
diagnostic_failure_category(system_limit) -> <<"resource_limit">>;
diagnostic_failure_category({child_start_failed, _}) -> <<"startup_failed">>;
diagnostic_failure_category(timeout) -> <<"deadline_exceeded">>;
diagnostic_failure_category(stale_or_missing_evidence_identity) -> <<"stale_source">>;
diagnostic_failure_category({stale_build_sources, _}) -> <<"stale_build">>;
diagnostic_failure_category({modified_build_artifacts, _}) -> <<"modified_build">>;
diagnostic_failure_category(_) -> <<"validation_failed">>.

diagnostic_stack(Stack) when is_list(Stack) ->
    [diagnostic_frame(Frame) || Frame <- lists:sublist(Stack, 16)];
diagnostic_stack(_) -> [].

diagnostic_frame({Module, Function, Arity, Info}) when is_atom(Module), is_atom(Function), is_list(Info) ->
    Count = diagnostic_arity(Arity, 0),
    %% erlang:raise/3 can forge arbitrary atom-valued stack frames. A lexical
    %% identifier check alone would disclose secrets disguised as function or
    %% module names. Consult VM metadata without invoking user module_info/1.
    case diagnostic_known_function(Module, Function, Count) of
        true -> #{module => diagnostic_identifier(Module),
                  function => diagnostic_identifier(Function), arity => Count,
                  line => diagnostic_line(proplists:get_value(line, lists:sublist(Info, 16), 0))};
        false -> diagnostic_frame(unknown)
    end;
diagnostic_frame(_) -> #{module => <<"unknown">>, function => <<"unknown">>, arity => 0, line => 0}.

diagnostic_known_function(Module, Function, Arity) ->
    try lists:member({Function, Arity}, erlang:get_module_info(Module, functions))
        orelse erlang:is_builtin(Module, Function, Arity)
    catch _:_ -> false end.

diagnostic_identifier(Value) ->
    Bytes = atom_to_binary(Value),
    case byte_size(Bytes) =< 128 andalso
         re:run(Bytes, <<"^[a-zA-Z0-9_@]+$">>, [{capture, none}]) =:= match of
        true -> Bytes;
        false -> <<"unknown">>
    end.

diagnostic_arity(Arity, 0) when is_integer(Arity), Arity >= 0, Arity =< 255 -> Arity;
diagnostic_arity(_, 255) -> 255;
diagnostic_arity([], Count) -> Count;
diagnostic_arity([_ | Rest], Count) -> diagnostic_arity(Rest, Count + 1);
diagnostic_arity(_, _) -> 0.

diagnostic_line(Value) when is_integer(Value), Value > 0, Value =< 2147483647 -> Value;
diagnostic_line(_) -> 0.

-endif.
