%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

bundle_capture_self_test() ->
    Directory = "build/audit-bundle-self-test/run-" ++
        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16))),
    ok = filelib:ensure_dir(filename:join(Directory, "placeholder")),
    bundle_with_directory(Directory, fun() ->
        Good = <<"{\"status\":\"Ready\",\"checked\":true}">>,
        Bad = <<"{\"status\":\"Failed\",\"private\":\"bundle-private-marker\"}">>,
        ok = file:write_file("report.json", Good),
        Captured = bundle_capture(["report.json"]),
        [Entry] = bundle_entries(Captured),
        %% Real legacy read-again Red: replace the source after its manifest
        %% digest was calculated. The old archive input now has another hash.
        ok = file:write_file("report.json", Bad),
        LegacyBytes = read("report.json"),
        true = maps:get(sha256, Entry) =/= hex(crypto:hash(sha256, LegacyBytes)),
        ok = bundle_materialize("good", Captured),
        ok = bundle_validate_capture("good", Captured, fun bundle_test_ready/0),
        GoodArchive = bundle_archive("good.tar", Captured),
        {ok, GoodTable} = erl_tar:table({binary, GoodArchive}, [verbose]),
        true = lists:all(fun
            ({_, regular, _, 0, 8#100644, 0, 0}) -> true;
            (_) -> false
        end, GoodTable),
        {ok, [{"report.json", Good}]} = erl_tar:extract({binary, GoodArchive}, [memory]),
        true = maps:get(bytes, Entry) =:= byte_size(Good),
        true = maps:get(sha256, Entry) =:= hex(crypto:hash(sha256, Good)),
        nomatch = binary:match(GoodArchive, <<"bundle-private-marker">>),
        %% A benign replacement cannot rescue invalid captured evidence.
        Invalid = bundle_capture(["report.json"]),
        ok = file:write_file("report.json", Good),
        ok = bundle_materialize("bad", Invalid),
        expect_error(captured_failed_report, fun() ->
            bundle_validate_capture("bad", Invalid, fun bundle_test_ready/0)
        end),
        %% A validator that accidentally writes must fail the final seal.
        expect_error(validator_changes_input, fun() ->
            bundle_validate_capture("good", Captured, fun() ->
                bundle_test_ready(), file:write_file("report.json", Bad)
            end)
        end),
        ok = file:write_file("good/report.json", Good),
        expect_error(validator_adds_input, fun() ->
            bundle_validate_capture("good", Captured, fun() ->
                bundle_test_ready(), file:write_file("extra.json", Good)
            end)
        end),
        ok = file:delete("good/extra.json"),
        ok = file:delete("report.json"),
        ok = bundle_validate_capture("good", Captured, fun bundle_test_ready/0),
        GoodArchive = bundle_archive("same.tar", Captured),
        ok = file:write_file("small", <<1, 2, 3, 4>>),
        ok = file:write_file("other", <<1, 2, 3, 4>>),
        Limits = bundle_limits(),
        expect_error(file_cap, fun() -> bundle_capture(["small"], Limits#{file_bytes => 3}) end),
        expect_error(total_cap, fun() -> bundle_capture(["other", "small"], Limits#{total_bytes => 7}) end),
        expect_error(file_count_cap, fun() -> bundle_capture(["small"], Limits#{files => 0}) end),
        expect_error(duplicate, fun() -> bundle_capture(["small", "small"]) end),
        expect_error(case_alias, fun() -> bundle_capture(["Small", "small"]) end),
        expect_error(unsorted, fun() -> bundle_capture(["small", "other"]) end),
        expect_error(directory_member, fun() -> bundle_capture(["good"]) end),
        lists:foreach(fun(Path) -> expect_error(unsafe_path, fun() -> bundle_path(Path) end) end,
            ["../small", "./small", "/small", "C:/small", "x\\small", "x//small", "small:stream", "x/../small"]),
        expect_error(invalid_release_nonce, fun() ->
            release_selected_paths(#{<<"run_nonce">> => <<"../private">>})
        end),
        Report = #{schema => 1, status => <<"Passed">>, legacy_reopen_red => true,
            captured_good_survives_source_replacement => true,
            captured_failure_cannot_be_replaced => true, manifest_archive_bytes_identical => true,
            private_replacement_excluded => true, validator_mutation_rejected => true,
            source_deletion_after_capture_safe => true, deterministic_archive => true,
            bounded_capture => true},
        write_json("result.json", Report)
    end),
    io:put_chars("bundle captured-byte, tamper, privacy, and limit tests passed\n").

bundle_test_ready() ->
    #{<<"status">> := <<"Ready">>, <<"checked">> := true} =
        evidence_json_decode(read("report.json")),
    ok.
