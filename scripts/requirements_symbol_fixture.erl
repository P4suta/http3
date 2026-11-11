%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(requirements_symbol_fixture).
-export([declared/2, quoted_name/0, guarded/2, macro_name/1, decoys/0,
         included_only/0, forged_origin/0, root_after_file_metadata/0]).
-include("requirements_symbol_include_fixture.hrl").
-type type_only() :: atom().
-export_type([type_only/0]).

%% comment_only(Value) -> Value.
%% declared/99 is not a declaration.
declared(_First, _Second) -> erlang:error(symbol_fixture_must_not_execute).
'quoted_name'() -> ok.
guarded(First, Second) when is_atom(First) -> {First, Second};
guarded(First, Second) -> [First, Second].
-define(FUNCTION, macro_name).
?FUNCTION(Value) -> Value.
decoys() ->
    {"string_only(Value) -> Value.", atom_only, missing:call_only()}.
-ifdef(REQUIREMENTS_SYMBOL_DISABLED_BRANCH).
inactive() -> ok.
-endif.
-file("source-metadata-only.erl", 40).
root_after_file_metadata() -> ok.
