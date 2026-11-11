%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(diagnostic_assertion_fixture).
-export([manifest/0]).
-include_lib("eunit/include/eunit.hrl").
-include("diagnostic_failure.hrl").

%% Real OTP macros, including aliases and deferred EUnit assertions. Command
%% assertion reason shapes are synthetic: their external command never
%% contributed to classification, while spawning it made the diagnostic test
%% itself a source of unjoined Windows consoles. The last seven cases are
%% negative classification controls, not assertion failures.
cases() ->
    [{boolean, assert}, {boolean_not, assert}, {boolean_value, assert},
     {boolean_not_value, assert}, {equal, assertEqual}, {not_equal, assertNotEqual},
     {match, assertMatch}, {not_match, assertNotMatch},
     {exception_return, assertException}, {exception_class, assertException},
     {exception_reason, assertException}, {error_alias, assertException},
     {exit_alias, assertException}, {throw_alias, assertException},
     {not_error, assertNotException}, {not_exit, assertNotException},
     {not_throw, assertNotException}, {deferred, assert}, {deferred_not, assert},
     {command_status, assertCmd_failed}, {command_output, assertCmdOutput_failed},
     {ordinary_error, ordinary_error}, {ordinary_exit, ordinary_exit},
     {ordinary_throw, ordinary_throw}, {command_failure, command_failed},
     {unknown_tag, assertion_like}, {wrong_shape, assert},
     {expression_error, badarg}].

category(Id) when Id =:= ordinary_error; Id =:= ordinary_exit;
                  Id =:= ordinary_throw; Id =:= command_failure;
                  Id =:= unknown_tag; Id =:= wrong_shape -> <<"validation_failed">>;
category(expression_error) -> <<"invalid_argument">>;
category(_) -> <<"assertion_failed">>.

manifest() ->
    [#{id => atom_to_binary(Id), tag => atom_to_binary(Tag), category => category(Id)}
     || {Id, Tag} <- cases()].

contract_test_() ->
    [?_test(contract(Id, Tag)) || {Id, Tag} <- cases()].

failure_test_() ->
    %% Positive stdout/stderr control: the collector sees this value, while
    %% the retained report and its safe process record must not contain it.
    io:format(standard_error, "~s~n", [marker()]),
    [?_test(failure(Id)) || {Id, _} <- cases()].

contract(Id, Tag) ->
    Captured = try failure(Id) of _ -> returned
               catch Class:Reason:Stack -> {caught, Class, Reason, Stack} end,
    ?assertMatch({caught, _, _, _}, Captured),
    {caught, Class0, Reason0, Stack0} = Captured,
    ?assertEqual(Tag, reason_tag(Reason0)),
    case Id of
        expression_error -> ok;
        _ -> ?assertNotEqual(nomatch, binary:match(term_to_binary(Reason0), marker()))
    end,
    Details = diagnostic_failure_details(Class0, Reason0, Stack0),
    ?assertEqual(category(Id), maps:get(exception_reason, Details)),
    ?assertEqual(atom_to_binary(Class0), maps:get(exception_class, Details)),
    Encoded = iolist_to_binary(json:encode(Details)),
    ?assertEqual(nomatch, binary:match(Encoded, marker())),
    ?assert(byte_size(Encoded) =< 8192),
    ?assert(length(json:decode(maps:get(stacktrace, Details))) =< 16).

reason_tag(Reason) when is_tuple(Reason) -> element(1, Reason);
reason_tag(Reason) -> Reason.

marker() -> <<"diagnostic-assertion-private-marker">>.
private_value() ->
    #{authorization => marker(), cookie => marker(), path => marker(),
      process => self(), reference => make_ref()}.
value(Value) -> Value.
failure(boolean) -> ?assert(value(false), private_value());
failure(boolean_not) -> ?assertNot(value(true), private_value());
failure(boolean_value) -> ?assert(private_value());
failure(boolean_not_value) -> ?assertNot(private_value());
failure(equal) -> ?assertEqual(expected, private_value());
failure(not_equal) ->
    Value = private_value(), ?assertNotEqual(Value, value(Value));
failure(match) -> ?assertMatch({expected, _}, private_value());
failure(not_match) -> ?assertNotMatch(#{authorization := _}, private_value());
failure(exception_return) -> ?assertException(error, expected, private_value());
failure(exception_class) -> ?assertException(exit, _, erlang:error(private_value()));
failure(exception_reason) -> ?assertException(error, expected, erlang:error(private_value()));
failure(error_alias) -> ?assertError(expected, erlang:error(private_value()));
failure(exit_alias) -> ?assertExit(expected, exit(private_value()));
failure(throw_alias) -> ?assertThrow(expected, throw(private_value()));
failure(not_error) -> ?assertNotException(error, #{authorization := _}, erlang:error(private_value()));
failure(not_exit) -> ?assertNotException(exit, #{authorization := _}, exit(private_value()));
failure(not_throw) -> ?assertNotException(throw, #{authorization := _}, throw(private_value()));
failure(deferred) ->
    {_Line, Test} = ?_assert(value(<<"diagnostic-assertion-private-marker">>) =:= true), Test();
failure(deferred_not) ->
    {_Line, Test} = ?_assertNot(value(<<"diagnostic-assertion-private-marker">>) =/= true), Test();
failure(command_status) -> synthetic_command_assertion(assertCmd_failed);
failure(command_output) -> synthetic_command_assertion(assertCmdOutput_failed);
failure(ordinary_error) -> erlang:error({ordinary_error, private_value()});
failure(ordinary_exit) -> exit({ordinary_exit, private_value()});
failure(ordinary_throw) -> throw({ordinary_throw, private_value()});
%% Deliberate reason-shape controls: command_failed is not an assertion tag.
failure(command_failure) -> erlang:error({command_failed, private_value()});
failure(unknown_tag) -> erlang:error({assertion_like, private_value()});
failure(wrong_shape) -> erlang:error({assert, private_value(), extra});
failure(expression_error) -> ?assert(erlang:error(badarg)).

synthetic_command_assertion(Tag) ->
    %% Preserve the command assertion tag and private-value positions consumed
    %% by the classifier without starting an operating-system process.
    erlang:error({Tag, [{command, marker()}, {output, marker()}]}).
