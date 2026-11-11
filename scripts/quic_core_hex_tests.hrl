%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

hex_self_test() ->
    Nonce = binary_to_list(hex(crypto:strong_rand_bytes(16))),
    Directory = filename:join("build/hex-package-self-test", "run-" ++ Nonce),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    Names = ["README.md", "gleam.toml", "src/quic_core.gleam",
        "src/quic_core/client.gleam", "src/quic_core/config.gleam",
        "src/quic_core/diagnostics.gleam", "src/quic_core/failure.gleam",
        "src/quic_core/server.gleam"],
    Good = [{N, <<"synthetic package audit fixture">>} || N <- Names],
    Cases = [{positive, Good, true},
        {unsafe_path, Good ++ [{"../hex_private_marker", <<>>}], false},
        {credential_path, Good ++ [{"src/hex_private_marker.pem", <<>>}], false},
        {private_content, Good ++ [{"src/hex_private_marker.erl",
            <<"-----BEGIN PRIVATE KEY-----">>}], false}],
    Rows = [hex_control(Directory, Label, Files, Expected) ||
        {Label, Files, Expected} <- Cases],
    Report = #{schema => 1, actual_cli => true, run_nonce => list_to_binary(Nonce),
        otp_release => list_to_binary(erlang:system_info(otp_release)),
        erts_version => list_to_binary(erlang:system_info(version)), tests => Rows},
    ok = file:write_file(filename:join(Directory, "result.json"), json:encode(Report)),
    ensure(lists:all(fun(#{passed := P}) -> P end, Rows), hex_cli_contract_failed),
    io:format("Hex CLI: positive archive and 3 private failure controls passed~n").

hex_control(Directory, Label, Files, Expected) ->
    Prefix = filename:join(Directory, atom_to_list(Label)),
    Input = Prefix ++ "-input.tar", OutputPath = Prefix ++ "-output.tar",
    ContentsPath = Prefix ++ "-contents.tar.gz",
    ok = erl_tar:create(ContentsPath, Files, [compressed]),
    {ok, Contents} = file:read_file(ContentsPath),
    Metadata = iolist_to_binary([io_lib:format("~0tp.~n", [T]) || T <-
        [{<<"name">>, <<"quic_core">>}, {<<"app">>, <<"quic_core">>},
         {<<"version">>, <<"0.1.0">>},
         {<<"files">>, [list_to_binary(N) || {N, _} <- Files]}]]),
    Checksum = hex(crypto:hash(sha256, [<<"3">>, Metadata, Contents])),
    ok = erl_tar:create(Input, [{"VERSION", <<"3">>}, {"metadata.config", Metadata},
        {"contents.tar.gz", Contents}, {"CHECKSUM", Checksum}], []),
    Escript = filename:join([code:root_dir(), "bin", case os:type() of
        {win32, _} -> "escript.exe"; _ -> "escript" end]),
    Started = erlang:monotonic_time(millisecond),
    Environment = [{"ERL_CRASH_DUMP_BYTES", "0"},
        {"ERL_CRASH_DUMP_SECONDS", "0"}, {"ERL_AFLAGS", false},
        {"ERL_FLAGS", false}, {"ERL_ZFLAGS", false}],
    {Port, Identity} = open_owned_process(Escript,
        [filename:absname(escript:script_name()), "normalize", Input, OutputPath],
        filename:absname("."), Environment, Started + 30000),
    {Status, Process} = collect_eunit(Port, new_output(Identity), Started + 30000),
    FullyObserved = maps:get(output_bytes, Process) =< 65536,
    PrivateExcluded = FullyObserved andalso
        binary:match(output_tail(Process), <<"hex_private_marker">>) =:= nomatch,
    ModeValid = case Expected andalso Status =:= 0 of
        true ->
            {ok, Table} = erl_tar:table(OutputPath, [verbose]),
            lists:all(fun
                ({_, regular, _, 0, 8#100644, 0, 0}) -> true;
                (_) -> false
            end, Table);
        false -> not Expected
    end,
    ExpectedExit = case Expected of true -> 0; false -> 1 end,
    Passed = process_status_verified(Status, ExpectedExit, Process)
        andalso PrivateExcluded andalso ModeValid,
    #{case_name => Label, passed => Passed, exit_status => Status,
      private_output_excluded => PrivateExcluded, canonical_outer_metadata => ModeValid,
      fixture_output_fully_observed => FullyObserved,
      absolute_deadline_ms => 30000,
      process => maps:without([tail, output_sha256], Process)}.
