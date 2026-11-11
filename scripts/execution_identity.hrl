%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_EXECUTION_IDENTITY_HRL).
-define(HTTP_EXECUTION_IDENTITY_HRL, true).
%% Read-only report auditors need runtime identity without invoking a build.
-compile({nowarn_unused_function, [{execution_build_tools, 0},
                                  {execution_tool, 3}, {execution_tool_path, 1},
                                  {execution_tool_pin, 2}]}).

%% Host paths and environment variables never enter shared reports. Runtime
%% values are observed; configuration pins are explicitly labelled declared.
execution_runtime() ->
    Release = erlang:system_info(otp_release),
    VersionPath = filename:join([code:root_dir(), "releases", Release, "OTP_VERSION"]),
    {ok, VersionBytes} = file:read_file(VersionPath),
    Version = string:trim(VersionBytes),
    true = byte_size(Version) > 0 andalso byte_size(Version) =< 64,
    {match, _} = re:run(Version, <<"^[0-9]+(?:\\.[0-9]+)*(?:[-+][A-Za-z0-9.]+)?$">>),
    {Family, Name} = os:type(),
    #{<<"otp_version">> => Version,
      <<"erts_version">> => list_to_binary(erlang:system_info(version)),
      <<"system_architecture">> => list_to_binary(erlang:system_info(system_architecture)),
      <<"os_family">> => atom_to_binary(Family),
      <<"os_name">> => atom_to_binary(Name),
      <<"word_size">> => erlang:system_info(wordsize)}.

execution_build_tools() ->
    {ok, Configuration} = file:read_file(".mise.toml"),
    #{<<"runtime">> => execution_runtime(),
      <<"gleam">> => execution_tool("gleam", "gleam", Configuration),
      <<"rebar3">> => execution_tool("rebar3", "rebar", Configuration)}.

execution_tool(Executable, Pin, Configuration) ->
    Path = execution_tool_path(Executable),
    true = is_list(Path),
    Size = filelib:file_size(Path),
    true = Size > 0 andalso Size =< 67108864,
    {ok, Bytes} = file:read_file(Path),
    #{<<"declared_version">> => execution_tool_pin(Pin, Configuration),
      <<"executable_sha256">> => binary:encode_hex(crypto:hash(sha256, Bytes), lowercase)}.

execution_tool_pin(Pin, Configuration) ->
    Pattern = ["^", Pin, " = \"([0-9][0-9A-Za-z.+-]{0,63})\"$"],
    {match, [Declared]} = re:run(Configuration, Pattern,
        [multiline, {capture, [1], binary}]),
    Declared.

%% Windows os:find_executable only considers executable suffixes; rebar3 is
%% the extensionless escript Gleam passes to its Erlang toolchain.
execution_tool_path("rebar3") ->
    Separator = case os:type() of {win32, _} -> ";"; _ -> ":" end,
    case os:getenv("PATH") of
        false -> false;
        Search ->
            Candidates = [filename:join(Directory, "rebar3") ||
                Directory <- string:lexemes(Search, Separator)],
            case [Path || Path <- Candidates, filelib:is_regular(Path)] of
                [Path | _] -> Path;
                [] -> os:find_executable("rebar3")
            end
    end;
execution_tool_path(Executable) -> os:find_executable(Executable).

-endif.
