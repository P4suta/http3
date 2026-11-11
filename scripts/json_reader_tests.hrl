%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

%% Exercise actual filesystem readers, including escaped and nested duplicate
%% keys in both orders. No duplicate-key interpretation can publish evidence.
json_reader_duplicate_controls(Label, Paths, Read) ->
    Directory = filename:absname(filename:join("build/json-reader-controls",
        Label ++ "-" ++ binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8))))),
    Good = <<"{\"source_sha256\":\"current\",\"toolchain\":{\"otp_release\":\"29\"}}">>,
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    {ok, Previous} = file:get_cwd(),
    try
        ok = file:set_cwd(Directory),
        lists:foreach(fun(Path) ->
            ok = filelib:ensure_dir(Path), ok = file:write_file(Path, Good)
        end, Paths),
        true = Read(),
        Invalid = [
            <<"{\"source_sha256\":\"current\",\"source_sha256\":\"old\"}">>,
            <<"{\"source_sha256\":\"old\",\"source_sha256\":\"current\"}">>,
            <<"{\"source_sha256\":\"current\",\"source_\\u0073ha256\":\"old\"}">>,
            <<"{\"source_\\u0073ha256\":\"old\",\"source_sha256\":\"current\"}">>,
            <<"{\"toolchain\":{\"otp_release\":\"29\",\"otp_release\":\"28\"}}">>,
            <<"{\"toolchain\":{\"otp_release\":\"28\",\"otp_\\u0072elease\":\"29\"}}">>
        ],
        Rejected = [begin
            ok = file:write_file(hd(Paths), Bytes),
            try not Read() catch error:_ -> true end
        end || Bytes <- Invalid],
        All = lists:all(fun(Value) -> Value end, Rejected),
        io:format("~s duplicate_json_keys_rejected=~p cases=~B~n", [Label, All, length(Invalid)]),
        case All of true -> ok; false -> erlang:error(ambiguous_json_evidence_accepted) end
    after
        lists:foreach(fun(Path) -> ok = file:delete(Path) end, Paths),
        ok = file:set_cwd(Previous)
    end.
