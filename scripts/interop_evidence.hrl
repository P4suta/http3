%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

%% The producer and final bundle use the same execution-evidence validator.
-include("fresh_build_identity.hrl").
-include("interop_go_evidence.hrl").
-include("interop_browser_evidence.hrl").

interop_audit_peer_report(Peer, Report, Source) ->
    ExpectedKeys = lists:sort([<<"schema">>, <<"status">>, <<"peer">>,
        <<"pin">>, <<"source_sha256">>, <<"roles">>, <<"results">>,
        <<"runtime">>, <<"run_id">>, <<"invocations">>, <<"build">>]),
    interop_ensure(lists:sort(maps:keys(Report)) =:= ExpectedKeys,
           invalid_execution_fields),
    interop_ensure(maps:get(<<"schema">>, Report) =:= 2, invalid_execution_schema),
    interop_ensure(maps:get(<<"status">>, Report) =:= <<"Ready">>,
           execution_not_complete),
    interop_ensure(maps:get(<<"source_sha256">>, Report) =:= Source,
           stale_execution),
    interop_ensure(maps:get(<<"peer">>, Report) =:= maps:get(<<"id">>, Peer),
           wrong_execution_peer),
    interop_ensure(maps:get(<<"pin">>, Peer, null) =/= null andalso
           maps:get(<<"pin">>, Report) =:= maps:get(<<"pin">>, Peer),
           wrong_peer_version),
    interop_ensure(maps:get(<<"roles">>, Report) =:= maps:get(<<"roles">>, Peer),
           missing_execution_role),
    Expected = interop_expected_scenarios(Peer),
    Results = maps:get(<<"results">>, Report),
    interop_ensure(is_list(Results) andalso length(Results) =< 256,
           invalid_execution_results),
    interop_ensure(lists:sort(Results) =:= Expected, missing_or_duplicate_scenario),
    interop_digest(maps:get(<<"run_id">>, Report)),
    Build = maps:get(<<"build">>, Report),
    interop_keys(Build, [<<"target">>, <<"manifest_sha256">>, <<"end_manifest_sha256">>,
                         <<"artifact_sha256">>]),
    interop_ensure(maps:get(<<"target">>, Build) =:= maps:get(<<"build_target">>, Peer),
                   wrong_native_build),
    interop_digest(maps:get(<<"manifest_sha256">>, Build)),
    interop_digest(maps:get(<<"artifact_sha256">>, Build)),
    interop_ensure(maps:get(<<"manifest_sha256">>, Build) =:=
                   maps:get(<<"end_manifest_sha256">>, Build), native_build_changed),
    Invocations = maps:get(<<"invocations">>, Report),
    interop_ensure(is_list(Invocations) andalso length(Invocations) =:= length(Expected),
                   missing_peer_invocation),
    lists:foreach(fun(Invocation) ->
        interop_audit_invocation(Peer, Report, Invocation)
    end, Invocations),
    interop_ensure(lists:sort([maps:with([<<"role">>, <<"scenario">>], I)
                    || I <- Invocations]) =:= Expected,
                   missing_or_duplicate_invocation),
    %% Roles and scenarios must execute the same dependency/runtime identity.
    %% Python client/server fixtures legitimately differ, but not packages.
    lists:foreach(fun(Role) ->
        interop_ensure(length(lists:usort([maps:remove(<<"fixture_sha256">>,
            maps:get(<<"identity">>, I)) || I <- Invocations,
                maps:get(<<"role">>, I) =:= Role])) =:= 1,
            peer_identity_changed_between_scenarios)
    end, maps:get(<<"roles">>, Peer)),
    Runtime = maps:get(<<"runtime">>, Report),
    interop_ensure(lists:sort(maps:keys(Runtime)) =:= [<<"os">>, <<"otp">>],
           invalid_runtime_fields),
    interop_ensure(lists:member(maps:get(<<"os">>, Runtime),
                        [<<"linux">>, <<"darwin">>, <<"win32">>]),
           invalid_execution_platform),
    interop_ensure(lists:member(maps:get(<<"otp">>, Runtime), [<<"28">>, <<"29">>]),
           unsupported_execution_runtime),
    ok.

%% A deliberately narrow contract for shareable failed-scenario evidence.
%% Exception text, arguments, endpoints, paths, output bytes and output hashes
%% have no representable field. The current source and attempt nonce are
%% supplied by the independent Erlang auditor rather than trusted from JSON.
interop_audit_failure_report(Peer, Report, Source, RunId) ->
    interop_keys(Report, [<<"schema">>, <<"status">>, <<"peer">>,
        <<"run_id">>, <<"source_sha256">>, <<"role">>, <<"scenario">>,
        <<"phase">>, <<"completion">>, <<"result">>]),
    interop_ensure(maps:get(<<"schema">>, Report) =:= 1 andalso
                   maps:get(<<"status">>, Report) =:= <<"Failed">>,
                   invalid_failure_status),
    interop_digest(Source),
    interop_digest(RunId),
    interop_ensure(maps:get(<<"peer">>, Report) =:= maps:get(<<"id">>, Peer),
                   wrong_failure_peer),
    interop_ensure(maps:get(<<"source_sha256">>, Report) =:= Source,
                   stale_failure_source),
    interop_ensure(maps:get(<<"run_id">>, Report) =:= RunId,
                   stale_failure_run),
    Scenario = maps:with([<<"role">>, <<"scenario">>], Report),
    interop_ensure(lists:member(Scenario, interop_expected_scenarios(Peer)),
                   unknown_failure_scenario),
    Phase = maps:get(<<"phase">>, Report),
    interop_ensure(lists:member(Phase, [<<"identity_before">>, <<"execution">>,
        <<"identity_after">>, <<"exit_validation">>, <<"publication">>]),
        invalid_failure_phase),
    Result = maps:get(<<"result">>, Report),
    interop_keys(Result, [<<"kind">>, <<"exit_status">>]),
    Kind = maps:get(<<"kind">>, Result),
    ExitStatus = maps:get(<<"exit_status">>, Result),
    interop_integer(ExitStatus, 1, 255),
    SignalStatuses = [130, 143, 149],
    interop_ensure((Kind =:= <<"cancelled">> andalso
                    lists:member(ExitStatus, SignalStatuses)) orelse
                   (Kind =:= <<"failed">> andalso
                    not lists:member(ExitStatus, SignalStatuses)),
                   invalid_failure_result),
    interop_audit_failure_completion(
        maps:get(<<"completion">>, Report), Phase),
    ok.

interop_audit_failure_completion(null, Phase) ->
    interop_ensure(lists:member(Phase,
        [<<"identity_before">>, <<"execution">>]),
        missing_failure_completion);
interop_audit_failure_completion(Completion, Phase) ->
    interop_ensure(Phase =/= <<"identity_before">>,
                   unexpected_failure_completion),
    interop_keys(Completion, [<<"outcome">>, <<"exit_status">>,
        <<"exit_observed">>, <<"controlled_shutdown">>,
        <<"elapsed_milliseconds">>, <<"stdout_bytes">>, <<"stderr_bytes">>]),
    interop_ensure(lists:member(maps:get(<<"outcome">>, Completion),
        [<<"completed">>, <<"timeout">>, <<"output_limit">>]),
        invalid_failure_outcome),
    interop_integer(maps:get(<<"exit_status">>, Completion), -255, 255),
    interop_ensure(maps:get(<<"exit_observed">>, Completion) =:= true,
                   unobserved_failure_exit),
    interop_ensure(lists:member(maps:get(<<"controlled_shutdown">>, Completion),
                               [true, false]),
                   invalid_failure_shutdown),
    interop_integer(maps:get(<<"elapsed_milliseconds">>, Completion), 0, 125000),
    Stdout = maps:get(<<"stdout_bytes">>, Completion),
    Stderr = maps:get(<<"stderr_bytes">>, Completion),
    interop_integer(Stdout, 0, 8388608),
    interop_integer(Stderr, 0, 8388608),
    interop_ensure(Stdout + Stderr =< 8388608,
                   oversized_failure_output),
    ok.

interop_audit_invocation(Peer, Report, Invocation) ->
    Extra = case maps:get(<<"id">>, Peer) of
        <<"masque-independent">> -> [<<"native">>];
        BrowserId when BrowserId=:=<<"chromium">>;BrowserId=:=<<"firefox">> -> [<<"browser">>,<<"native">>]; _ -> [] end,
    interop_keys(Invocation, [<<"role">>, <<"scenario">>, <<"run_id">>,
        <<"source_sha256">>, <<"identity">>, <<"completion">>] ++ Extra),
    case maps:get(<<"id">>,Peer) of
        <<"masque-independent">>->interop_audit_masque_native(Report,Invocation);
        BrowserPeer when BrowserPeer=:=<<"chromium">>;BrowserPeer=:=<<"firefox">> -> interop_browser_audit(Report,Invocation);
        _->ok
    end,
    interop_ensure(maps:get(<<"run_id">>, Invocation) =:= maps:get(<<"run_id">>, Report),
                   stale_invocation_nonce),
    interop_ensure(maps:get(<<"source_sha256">>, Invocation) =:=
                   maps:get(<<"source_sha256">>, Report), stale_invocation_source),
    Scenario = maps:with([<<"role">>, <<"scenario">>], Invocation),
    interop_ensure(lists:member(Scenario, interop_expected_scenarios(Peer)),
                   unknown_invocation_scenario),
    Identity = maps:get(<<"identity">>, Invocation),
    Kind = maps:get(<<"identity_kind">>, Peer),
    interop_keys(Identity, [<<"kind">>, <<"executable">>, <<"version">>,
        <<"lock_sha256">>, <<"fixture_sha256">>, <<"dependencies">>] ++
        case Kind of <<"go">>->[<<"build">>];_->[] end),
    interop_ensure(maps:get(<<"kind">>, Identity) =:= Kind, wrong_identity_kind),
    Executable = maps:get(<<"executable">>, Identity),
    interop_keys(Executable, [<<"sha256">>, <<"bytes">>]),
    interop_digest(maps:get(<<"sha256">>, Executable)),
    interop_integer(maps:get(<<"bytes">>, Executable), 1, 268435456),
    Version = maps:get(<<"version">>, Identity),
    interop_text(Version, <<"^[A-Za-z0-9][A-Za-z0-9 .+_-]{0,127}$">>),
    interop_ensure(maps:get(<<"lock_sha256">>, Identity) =:=
                   maps:get(<<"lock_sha256">>, Peer, null), wrong_dependency_lock),
    case Kind of
        Fixture when Fixture =:= <<"python">>; Fixture =:= <<"rust">>; Fixture =:= <<"native">>; Fixture =:= <<"node">>; Fixture =:= <<"go">>; Fixture =:= <<"browser">> ->
            interop_digest(maps:get(<<"fixture_sha256">>, Identity));
        _ -> interop_ensure(maps:get(<<"fixture_sha256">>, Identity) =:= null,
                            unexpected_peer_fixture)
    end,
    Dependencies = maps:get(<<"dependencies">>, Identity),
    interop_ensure(is_list(Dependencies) andalso length(Dependencies) > 0 andalso
                   length(Dependencies) =< 128, invalid_dependency_inventory),
    lists:foreach(fun(Dependency) ->
        interop_keys(Dependency, [<<"name">>, <<"version">>, <<"sha256">>, <<"files">>]),
        interop_text(maps:get(<<"name">>, Dependency),
                     <<"^[A-Za-z0-9][A-Za-z0-9._/+@-]{0,191}$">>),
        interop_text(maps:get(<<"version">>, Dependency),
                     <<"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$">>),
        interop_digest(maps:get(<<"sha256">>, Dependency)),
        interop_integer(maps:get(<<"files">>, Dependency), 0, 20000)
    end, Dependencies),
    Names = [maps:get(<<"name">>, D) || D <- Dependencies],
    interop_ensure(length(Names) =:= length(lists:usort(Names)), duplicate_dependency),
    Pin = maps:get(<<"pin">>, Peer),
    PinObserved = case Kind of
        Native when Native =:= <<"curl">>; Native =:= <<"nghttp2">>; Native =:= <<"browser">> -> Version =:= Pin;
        _ ->
            Separator = case Kind of
                <<"python">> -> <<"==">>;
                Compiled when Compiled =:= <<"go">>; Compiled =:= <<"rust">>; Compiled =:= <<"native">>; Compiled =:= <<"node">> -> <<"@">>
            end,
            lists:any(fun(D) ->
                <<(maps:get(<<"name">>, D))/binary, Separator/binary,
                  (maps:get(<<"version">>, D))/binary>> =:= Pin
            end, Dependencies)
    end,
    interop_ensure(PinObserved, pinned_package_not_executed),
    case Kind of
        <<"rust">> -> interop_audit_rust_identity(Peer, Identity);
        <<"native">> -> interop_audit_native_identity(Peer, Identity, maps:get(<<"role">>, Invocation));
        <<"node">> -> interop_audit_node_identity(Peer, Identity);
        <<"go">> -> interop_go_audit_identity(Peer, Identity);
        <<"browser">> -> interop_browser_identity(Peer, Identity);
        _ -> ok
    end,
    Completion = maps:get(<<"completion">>, Invocation),
    interop_keys(Completion, [<<"outcome">>, <<"exit_status">>, <<"exit_observed">>,
        <<"controlled_shutdown">>, <<"elapsed_milliseconds">>, <<"stdout_bytes">>, <<"stderr_bytes">>]),
    {ExpectedExit, Controlled} = case {maps:get(<<"id">>, Peer), maps:get(<<"role">>, Scenario), maps:get(<<"scenario">>, Scenario)} of
        {<<"curl-h1-h2">>, <<"client">>, <<"untrusted certificate refused">>} -> {60, false};
        {<<"ngtcp2-nghttp3-h3">>, <<"client">>, <<"untrusted certificate refused">>} -> {60, false};
        {<<"nghttp2-h2">>, <<"server">>, _} -> {-15, true};
        {<<"quiche-h3">>, <<"server">>, _} -> {-15, true};
        {<<"ngtcp2-nghttp3-h3">>, <<"server">>, _} -> {-15, true};
        _ -> {0, false}
    end,
    interop_ensure(maps:get(<<"outcome">>, Completion) =:= <<"completed">> andalso
        maps:get(<<"exit_observed">>, Completion) =:= true andalso
        maps:get(<<"controlled_shutdown">>, Completion) =:= Controlled andalso
        maps:get(<<"exit_status">>, Completion) =:= ExpectedExit,
        incomplete_or_failed_peer_process),
    interop_integer(maps:get(<<"elapsed_milliseconds">>, Completion), 0, 125000),
    interop_integer(maps:get(<<"stdout_bytes">>, Completion), 0, 8388608),
    interop_integer(maps:get(<<"stderr_bytes">>, Completion), 0, 8388608),
    interop_ensure(maps:get(<<"stdout_bytes">>, Completion) +
        maps:get(<<"stderr_bytes">>, Completion) =< 8388608, oversized_peer_output),
    ok.

interop_audit_masque_native(Report, Invocation) ->
    Native = maps:get(<<"native">>, Invocation),
    interop_keys(Native, [<<"schema">>, <<"status">>, <<"role">>, <<"configured_flows">>,
        <<"configured_datagrams">>, <<"configured_rejections">>, <<"timeout_seconds">>,
        <<"nonce">>, <<"fixture">>, <<"completion">>, <<"child">>, <<"run_id">>, <<"source_sha256">>]),
    interop_ensure(maps:get(<<"schema">>,Native)=:=1 andalso maps:get(<<"status">>,Native)=:=<<"Passed">>,
        native_opposite_incomplete),
    Role = case maps:get(<<"role">>,Invocation) of <<"client">> -> <<"proxy">>; <<"proxy">> -> <<"client">> end,
    interop_ensure(maps:get(<<"role">>,Native)=:=Role,wrong_native_opposite_role),
    interop_ensure(maps:get(<<"run_id">>,Native)=:=maps:get(<<"run_id">>,Report)
        andalso maps:get(<<"source_sha256">>,Native)=:=maps:get(<<"source_sha256">>,Report),stale_native_opposite),
    interop_ensure(maps:get(<<"configured_flows">>,Native)=:=2
        andalso maps:get(<<"configured_datagrams">>,Native)=:=16
        andalso maps:get(<<"configured_rejections">>,Native)=:=1,incomplete_native_scope),
    Timeout = case Role of <<"proxy">> -> 45; <<"client">> -> 30 end,
    interop_ensure(maps:get(<<"timeout_seconds">>,Native)=:=Timeout,changed_native_deadline),
    Nonce=maps:get(<<"nonce">>,Native),interop_text(Nonce,<<"^[a-f0-9]{32}$">>),
    Expected=#{<<"schema">>=>1,<<"nonce">>=>Nonce,<<"completed_flows">>=>2,
        <<"completed_datagrams">>=>16,<<"completed_rejections">>=>1,<<"workers_down">>=>true},
    interop_ensure(maps:get(<<"child">>,Native)=:=Expected,incomplete_native_work_or_cleanup),
    Fixture=maps:get(<<"fixture">>,Native),
    interop_keys(Fixture,[<<"source">>,<<"beam">>,<<"runtime">>]),
    lists:foreach(fun(Value) ->
        interop_keys(Value,[<<"sha256">>,<<"bytes">>]),
        interop_digest(maps:get(<<"sha256">>,Value)),
        interop_integer(maps:get(<<"bytes">>,Value),1,268435456)
    end,maps:values(Fixture)),
    interop_ensure(maps:get(<<"sha256">>,maps:get(<<"source">>,Fixture))=:=
        interop_file_digest("test/interop/masquego/http_masque_interop.erl"),stale_native_fixture),
    Completion=maps:get(<<"completion">>,Native),
    interop_keys(Completion,[<<"outcome">>,<<"exit_status">>,<<"exit_observed">>,
        <<"controlled_shutdown">>,<<"elapsed_milliseconds">>,<<"stdout_bytes">>,<<"stderr_bytes">>]),
    interop_ensure(maps:get(<<"outcome">>,Completion)=:=<<"completed">>
        andalso maps:get(<<"exit_status">>,Completion)=:=0
        andalso maps:get(<<"exit_observed">>,Completion)=:=true
        andalso maps:get(<<"controlled_shutdown">>,Completion)=:=false
        andalso maps:get(<<"stdout_bytes">>,Completion)=:=0
        andalso maps:get(<<"stderr_bytes">>,Completion)=:=0,failed_or_private_native_execution),
    interop_integer(maps:get(<<"elapsed_milliseconds">>,Completion),0,Timeout*1000+5000),ok.

interop_audit_masque_retained_at(Report,Directory)->
    Invocations=maps:get(<<"invocations">>,Report),
    interop_ensure(is_list(Invocations) andalso length(Invocations)=:=2,missing_masque_native_roles),
    interop_ensure(lists:sort([maps:get(<<"role">>,I)||I<-Invocations])=:=
        [<<"client">>,<<"proxy">>],missing_masque_native_roles),
    lists:foreach(fun(Invocation)->
        interop_audit_masque_native(Report,Invocation),Native=maps:get(<<"native">>,Invocation),
        Role=case maps:get(<<"role">>,Invocation) of <<"client">>->"proxy";<<"proxy">>->"client" end,
        Bytes=interop_go_read(Directory++"/"++Role++".json",1048576),
        interop_ensure(evidence_json_decode(Bytes)=:=Native,replaced_masque_native_receipt)
    end,Invocations),ok.

interop_audit_node_identity(Peer, Identity) ->
    interop_ensure(maps:get(<<"version">>, Identity) =:= maps:get(<<"node_version">>, Peer),
                   wrong_node_version),
    interop_ensure(maps:get(<<"fixture_sha256">>, Identity) =:=
        interop_file_digest(binary_to_list(maps:get(<<"fixture">>, Peer))), stale_node_fixture),
    LockPath = binary_to_list(maps:get(<<"lock">>, Peer)),
    interop_ensure(interop_file_digest(LockPath) =:= maps:get(<<"lock_sha256">>, Peer), node_lock_drift),
    Lock = evidence_json_decode(interop_read(LockPath)),
    interop_ensure(maps:get(<<"lockfileVersion">>, Lock) =:= 3, invalid_node_lock),
    Packages = maps:remove(<<>>, maps:get(<<"packages">>, Lock)),
    interop_ensure(map_size(Packages) > 0 andalso map_size(Packages) =< 128, invalid_node_package_count),
    Dependencies = maps:get(<<"dependencies">>, Identity),
    maps:foreach(fun(<<"node_modules/", Name/binary>>, Metadata) ->
        interop_ensure(lists:any(fun(Dependency) ->
            maps:get(<<"name">>, Dependency) =:= Name andalso
            maps:get(<<"version">>, Dependency) =:= maps:get(<<"version">>, Metadata) andalso
            maps:get(<<"files">>, Dependency) > 0
        end, Dependencies), missing_locked_node_dependency)
    end, Packages),
    interop_ensure(lists:all(fun(Dependency) ->
        maps:get(<<"version">>, Dependency) =:= <<"binary">> orelse
        maps:is_key(<<"node_modules/", (maps:get(<<"name">>, Dependency))/binary>>, Packages)
    end, Dependencies), unlocked_node_dependency).

interop_audit_rust_identity(Peer, Identity) ->
    Patch = binary_to_list(maps:get(<<"identity_patch">>, Peer)),
    interop_ensure(maps:get(<<"fixture_sha256">>, Identity) =:= interop_file_digest(Patch),
                   stale_compiled_identity_patch),
    Rust = maps:get(<<"rust_version">>, Peer),
    interop_ensure(maps:get(<<"version">>, Identity) =:= <<"rustc ", Rust/binary>>,
                   wrong_rust_compiler_version),
    Dependencies = maps:get(<<"dependencies">>, Identity),
    Expected = [{<<"quiche-source-revision">>, <<"git">>, 0,
                 interop_bytes_digest(maps:get(<<"source_commit">>, Peer))},
                {<<"cargo-lock">>, <<"locked">>, 1, maps:get(<<"lock_sha256">>, Peer)}] ++
        [{Name, Rust, 1, any} || Name <- [<<"rustc">>, <<"rustc-driver">>, <<"cargo">>]] ++
        [{<<"build-", Name/binary>>, <<"binary">>, 1, any}
            || Name <- [<<"cc">>, <<"c++">>, <<"clang">>, <<"cmake">>, <<"make">>, <<"ar">>, <<"ld">>]],
    lists:foreach(fun({Name, Version, Files, Digest}) ->
        interop_ensure(lists:any(fun(D) ->
            maps:get(<<"name">>, D) =:= Name andalso maps:get(<<"version">>, D) =:= Version
            andalso maps:get(<<"files">>, D) =:= Files andalso
            (Digest =:= any orelse maps:get(<<"sha256">>, D) =:= Digest)
        end, Dependencies), missing_rust_build_identity)
    end, Expected).

interop_audit_native_identity(Peer, Identity, Role) ->
    LockPath = binary_to_list(maps:get(<<"lock">>, Peer)),
    Lock = evidence_json_decode(interop_read(LockPath)),
    Compiler = maps:get(<<"compiler_version">>, Peer),
    interop_ensure(maps:get(<<"compiler_version">>, Lock) =:= Compiler andalso
        maps:get(<<"version">>, Identity) =:= <<"gcc ", Compiler/binary>>, wrong_native_compiler),
    interop_ensure(maps:get(<<"fixture_sha256">>, Identity) =:=
        interop_file_digest(binary_to_list(maps:get(<<"identity_patch">>, Peer))), stale_native_patch),
    LockHash = interop_file_digest(LockPath),
    interop_ensure(LockHash =:= maps:get(<<"lock_sha256">>, Peer), native_lock_drift),
    Sources = maps:get(<<"sources">>, Lock),
    interop_ensure(length(Sources) =:= 3, invalid_native_source_inventory),
    Expected = lists:append([[{maps:get(<<"name">>, S), maps:get(<<"version">>, S), positive, any},
        {<<(maps:get(<<"name">>, S))/binary, "-archive">>, maps:get(<<"version">>, S), 1,
         maps:get(<<"sha256">>, S)}] || S <- Sources]) ++
        [{<<"build-", Name/binary>>, <<"binary">>, 1, any}
            || Name <- [<<"gcc">>, <<"g++">>, <<"cc1">>, <<"cc1plus">>, <<"as">>, <<"ld">>,
                        <<"ar">>, <<"ranlib">>, <<"cmake">>, <<"make">>, <<"pkg-config">>, <<"patchelf">>]] ++
        [{<<"peer-role">>, Role, 0, interop_bytes_digest(Role)},
         {<<"source-lock">>, <<"locked">>, 1, LockHash},
         {<<"build-recipe">>, <<"locked">>, 1,
          interop_file_digest(binary_to_list(maps:get(<<"build_recipe">>, Peer)))}],
    Dependencies = maps:get(<<"dependencies">>, Identity),
    lists:foreach(fun({Name, Version, Files, Digest}) ->
        interop_ensure(lists:any(fun(D) ->
            Count = maps:get(<<"files">>, D),
            maps:get(<<"name">>, D) =:= Name andalso maps:get(<<"version">>, D) =:= Version
            andalso (Count =:= Files orelse (Files =:= positive andalso Count > 0))
            andalso (Digest =:= any orelse maps:get(<<"sha256">>, D) =:= Digest)
        end, Dependencies), missing_native_build_identity)
    end, Expected).

interop_keys(Map, Keys) ->
    interop_ensure(is_map(Map) andalso lists:sort(maps:keys(Map)) =:= lists:sort(Keys),
                   invalid_identity_fields).

interop_text(Value, Pattern) ->
    interop_ensure(is_binary(Value) andalso byte_size(Value) =< 256 andalso
        re:run(Value, Pattern, [{capture, none}]) =:= match, invalid_identity_text).

interop_digest(Value) -> interop_text(Value, <<"^[0-9a-fA-F]{64}$">>).

interop_integer(Value, Minimum, Maximum) ->
    interop_ensure(is_integer(Value) andalso Value >= Minimum andalso Value =< Maximum,
                   invalid_execution_measurement).

interop_expected_scenarios(Peer) ->
    Scenarios = maps:get(<<"scenarios">>, Peer, []),
    interop_ensure(Scenarios =/= [] andalso length(Scenarios) =< 256,
           missing_scenario_inventory),
    interop_ensure(length(Scenarios) =:= length(lists:usort(Scenarios)),
           duplicate_scenario_inventory),
    lists:foreach(fun(Scenario) ->
        interop_ensure(lists:sort(maps:keys(Scenario)) =:= [<<"role">>, <<"scenario">>],
               invalid_scenario_fields),
        interop_ensure(lists:member(maps:get(<<"role">>, Scenario),
                            maps:get(<<"roles">>, Peer)), invalid_scenario_role),
        Name = maps:get(<<"scenario">>, Scenario),
        interop_ensure(is_binary(Name) andalso byte_size(Name) > 0 andalso
               byte_size(Name) =< 128, invalid_scenario_name)
    end, Scenarios),
    interop_ensure(lists:usort([maps:get(<<"role">>, S) || S <- Scenarios]) =:=
           lists:usort(maps:get(<<"roles">>, Peer)), uncovered_peer_role),
    lists:sort(Scenarios).

interop_peer_row(Peer, Source) ->
    Id = maps:get(<<"id">>, Peer),
    Path = interop_peer_path(binary_to_list(Id)),
    try
        Bytes = interop_read_bounded(Path, 1048576),
        Report = evidence_json_decode(Bytes),
        interop_audit_peer_report(Peer, Report, Source),
        ExpectedOtp = interop_expected_peer_otp(),
        ExpectedOtp = maps:get(<<"otp">>, maps:get(<<"runtime">>, Report)),
        interop_audit_retained_build(Peer, Report),
        #{peer => Id, status => <<"Ready">>,
          report_sha256 => interop_bytes_digest(Bytes)}
    catch error:_ -> #{peer => Id, status => <<"Blocked">>} end.

interop_expected_peer_otp() ->
    Value = case os:getenv("HTTP_INTEROP_EXPECTED_OTP") of
        false -> list_to_binary(erlang:system_info(otp_release));
        Text -> unicode:characters_to_binary(Text)
    end,
    interop_ensure(lists:member(Value, [<<"28">>, <<"29">>]),
                   invalid_expected_interop_otp),
    Value.

interop_native_build(Peer) ->
    Target = maps:get(<<"build_target">>, Peer),
    fresh_with_verified_build(binary_to_list(Target), fun(Snapshot) ->
        Manifest = maps:get(report, Snapshot),
        Build = #{<<"target">> => Target,
            <<"manifest_sha256">> => maps:get(sha256, Snapshot),
            <<"artifact_sha256">> =>
                maps:get(<<"artifact_sha256">>, Manifest)},
        {Build, maps:get(bytes, Snapshot)}
    end).

interop_manifest_path(Id, Phase) ->
    filename:join(["build", "interop", "manifests", Id ++ "." ++ Phase ++ ".json"]).

interop_audit_retained_build(Peer, Report) ->
    Id = binary_to_list(maps:get(<<"id">>, Peer)),
    Before = interop_manifest_path(Id, "begin"),
    After = interop_manifest_path(Id, "end"),
    Build = maps:get(<<"build">>, Report),
    BeforeBytes = interop_read_bounded(Before, 1048576),
    AfterBytes = interop_read_bounded(After, 1048576),
    interop_ensure(interop_bytes_digest(BeforeBytes) =:= maps:get(<<"manifest_sha256">>, Build),
                   replaced_initial_manifest),
    interop_ensure(interop_bytes_digest(AfterBytes) =:= maps:get(<<"end_manifest_sha256">>, Build),
                   replaced_final_manifest),
    Initial = evidence_json_decode(BeforeBytes),
    interop_ensure(Initial =:= evidence_json_decode(AfterBytes), native_build_changed),
    interop_audit_native_manifest(Peer, Report, Initial),
    case maps:get(<<"id">>,Peer) of
        <<"masque-independent">>->interop_audit_masque_retained_at(Report,"build/interop/native/masque-independent");
        <<"chromium">>->interop_browser_retained_at(Report,"build/interop/native/chromium","build/interop/browser/chromium");
        <<"firefox">>->interop_browser_retained_at(Report,"build/interop/native/firefox","build/interop/browser/firefox");
        _->ok
    end.

interop_audit_native_manifest(Peer, Report, Manifest) ->
    interop_keys(Manifest, [<<"schema">>, <<"package">>, <<"source_sha256">>,
        <<"source_files">>, <<"artifact_sha256">>, <<"artifact_files">>,
        <<"toolchain">>, <<"build_nonce">>, <<"prebuild_profile_state">>]),
    interop_ensure(maps:get(<<"schema">>, Manifest) =:= 3,
                   invalid_native_manifest),
    Target = maps:get(<<"build_target">>, Peer),
    interop_ensure(maps:get(<<"package">>, Manifest) =:= Target, wrong_native_package),
    Sources = fresh_source_paths(fresh_packages(binary_to_list(Target))),
    interop_ensure(maps:get(<<"source_sha256">>, Manifest) =:= fresh_digest(Sources)
        andalso maps:get(<<"source_files">>, Manifest) =:= length(Sources),
        stale_native_manifest_source),
    interop_ensure(maps:get(<<"artifact_sha256">>, Manifest) =:=
        maps:get(<<"artifact_sha256">>, maps:get(<<"build">>, Report)), wrong_native_artifacts),
    interop_integer(maps:get(<<"artifact_files">>, Manifest), 1, 1000000),
    interop_text(maps:get(<<"build_nonce">>, Manifest),
                 <<"^[0-9a-f]{32}$">>),
    interop_ensure(maps:get(<<"prebuild_profile_state">>, Manifest) =:=
        <<"absent">>, unverified_native_prebuild_state),
    Tools = maps:get(<<"toolchain">>, Manifest),
    interop_keys(Tools, [<<"runtime">>, <<"gleam">>, <<"rebar3">>]),
    Runtime = maps:get(<<"runtime">>, Tools),
    {Os, Major} = interop_audit_execution_runtime(Runtime),
    RecordedRuntime = maps:get(<<"runtime">>, Report),
    interop_ensure(Os =:= maps:get(<<"os">>, RecordedRuntime), wrong_native_platform),
    interop_ensure(Major =:= maps:get(<<"otp">>, RecordedRuntime), wrong_native_otp),
    Configuration = interop_read(".mise.toml"),
    lists:foreach(fun({Name, ToolName}) ->
        Pin = execution_tool_pin(ToolName, Configuration),
        Tool = maps:get(Name, Tools),
        interop_keys(Tool, [<<"declared_version">>, <<"executable_sha256">>]),
        interop_ensure(maps:get(<<"declared_version">>, Tool) =:= Pin, wrong_native_compiler),
        interop_digest(maps:get(<<"executable_sha256">>, Tool))
    end, [{<<"gleam">>, "gleam"}, {<<"rebar3">>, "rebar"}]),
    ok.

%% Receipts may be produced in a pinned Linux container and audited later on
%% a Windows or macOS host. Validate the recorded producer environment as a
%% closed, supported value; never replace it with the verifier environment.
interop_expected_otp_version(<<"28">>) -> <<"28.5.0.6">>;
interop_expected_otp_version(<<"29">>) ->
    execution_tool_pin("erlang", interop_read(".mise.toml")).

interop_audit_execution_runtime(Runtime) ->
    interop_keys(Runtime, [<<"otp_version">>, <<"erts_version">>, <<"os_family">>,
        <<"os_name">>, <<"system_architecture">>, <<"word_size">>]),
    Platform = {maps:get(<<"os_family">>, Runtime),
                maps:get(<<"os_name">>, Runtime)},
    interop_ensure(lists:member(Platform,
        [{<<"unix">>, <<"linux">>}, {<<"unix">>, <<"darwin">>},
         {<<"win32">>, <<"nt">>}]), invalid_execution_platform),
    Os = case Platform of
        {<<"unix">>, <<"linux">>} -> <<"linux">>;
        {<<"unix">>, <<"darwin">>} -> <<"darwin">>;
        {<<"win32">>, <<"nt">>} -> <<"win32">>
    end,
    Version = maps:get(<<"otp_version">>, Runtime),
    interop_text(Version, <<"^[0-9]+(?:\\.[0-9]+)*(?:[-+][A-Za-z0-9.]+)?$">>),
    [Major | _] = binary:split(Version, <<".">>, [global]),
    interop_ensure(lists:member(Major, [<<"28">>, <<"29">>]),
                   unsupported_execution_runtime),
    ExpectedVersion = interop_expected_otp_version(Major),
    interop_ensure(Version =:= ExpectedVersion,
                   unpinned_execution_runtime),
    interop_text(maps:get(<<"erts_version">>, Runtime),
                 <<"^[0-9]+(?:\\.[0-9]+){0,7}$">>),
    interop_text(maps:get(<<"system_architecture">>, Runtime),
                 <<"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$">>),
    interop_ensure(lists:member(maps:get(<<"word_size">>, Runtime), [4, 8]), invalid_native_word_size),
    {Os, Major}.

interop_read_peer_report(Path) ->
    %% Qualification inputs are finite even if a failed producer floods a file.
    evidence_json_decode(interop_read_bounded(Path, 1048576)).

interop_read_bounded(Path, Maximum) ->
    interop_ensure(is_integer(Maximum) andalso Maximum >= 0 andalso
                   Maximum =< 16777216, invalid_peer_report_limit),
    Initial = interop_regular_info(Path),
    Size = element(2, Initial),
    interop_ensure(is_integer(Size) andalso Size >= 0 andalso Size =< Maximum,
                   oversized_or_invalid_peer_report),
    interop_ensure(element(9, Initial) =:= 1,
                   peer_report_hardlink_rejected),
    File = case file:open(Path, [read, binary, raw]) of
        {ok, Handle} -> Handle;
        {error, _} -> erlang:error(unreadable_peer_report)
    end,
    {Bytes, Finished} = try
        Opened = interop_handle_info(File),
        interop_ensure(element(3, Opened) =:= regular andalso
                       element(9, Opened) =:= 1 andalso
                       interop_file_identity(Initial) =:=
                           interop_file_identity(Opened),
                       peer_report_changed_while_reading),
        Captured = interop_read_chunks(File, Size, []),
        FinalHandle = interop_handle_info(File),
        interop_ensure(interop_file_identity(Opened) =:=
                           interop_file_identity(FinalHandle) andalso
                       byte_size(Captured) =:= Size,
                       peer_report_changed_while_reading),
        {Captured, FinalHandle}
    after
        ok = file:close(File)
    end,
    FinalPath = interop_regular_info(Path),
    interop_ensure(interop_file_identity(Finished) =:=
                       interop_file_identity(FinalPath),
                   peer_report_changed_while_reading),
    Bytes.

interop_regular_info(Path) ->
    interop_regular_components(filename:split(filename:absname(Path)), "").

interop_regular_components([Name], Parent) ->
    Current = interop_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= regular -> Info;
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            erlang:error(peer_report_link_rejected);
        {ok, _} -> erlang:error(peer_report_special_file_rejected);
        {error, enoent} -> erlang:error(missing_peer_report);
        {error, _} -> erlang:error(unreadable_peer_report)
    end;
interop_regular_components([Name | Rest], Parent) ->
    Current = interop_join_component(Parent, Name),
    case file:read_link_info(Current) of
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= directory ->
            interop_regular_components(Rest, Current);
        {ok, Info} when element(1, Info) =:= file_info,
                        element(3, Info) =:= symlink ->
            erlang:error(peer_report_parent_link_rejected);
        {ok, _} -> erlang:error(peer_report_parent_rejected);
        {error, enoent} -> erlang:error(missing_peer_report);
        {error, _} -> erlang:error(unreadable_peer_report)
    end;
interop_regular_components([], _Parent) -> erlang:error(unsafe_peer_report_path).

interop_join_component("", Name) -> Name;
interop_join_component(Parent, Name) -> filename:join(Parent, Name).

interop_handle_info(File) ->
    case file:read_file_info(File) of
        {ok, Info} -> Info;
        {error, _} -> erlang:error(unreadable_peer_report)
    end.

interop_read_chunks(File, Remaining, Acc) when Remaining >= 0 ->
    Request = erlang:min(Remaining + 1, 65536),
    case file:read(File, Request) of
        eof -> iolist_to_binary(lists:reverse(Acc));
        {ok, Chunk} when byte_size(Chunk) > 0,
                         byte_size(Chunk) =< Remaining ->
            interop_read_chunks(File, Remaining - byte_size(Chunk),
                                [Chunk | Acc]);
        {ok, _} -> erlang:error(peer_report_changed_while_reading);
        {error, _} -> erlang:error(unreadable_peer_report)
    end.

interop_file_identity(Info) ->
    %% atime is excluded because verification itself may update it.
    {element(2, Info), element(3, Info), element(4, Info), element(6, Info),
     element(7, Info), element(8, Info), element(9, Info), element(10, Info),
     element(11, Info), element(12, Info)}.

interop_bytes_digest(Bytes) -> binary:encode_hex(crypto:hash(sha256, Bytes), lowercase).

interop_verify_report() ->
    Report = evidence_json_decode(interop_read("build/interop/report.json")),
    Identity = evidence_identity(),
    evidence_require_identity(Report, Identity),
    Peers = maps:get(<<"peers">>, interop_profile()),
    Source = interop_source_digest(),
    Rows = [interop_peer_row(Peer, Source) || Peer <- Peers],
    Expected = #{schema => 2, status => <<"Ready">>,
        baseline_date => <<"2026-08-30">>, source_sha256 => Source,
        peers => length(Peers), missing => [], runs => Rows},
    interop_ensure(lists:all(fun(Row) -> maps:get(status, Row) =:= <<"Ready">> end,
                     Rows), incomplete_peer_matrix),
    interop_ensure(Report =:= evidence_json_decode(iolist_to_binary(json:encode(
        evidence_complete(Expected, Identity)))),
           stale_or_incomplete_interop_report),
    io:put_chars("current-source interoperability evidence verified\n").

interop_source_digest() ->
    %% Peer runs and the final gate bind to exactly the same complete inputs.
    maps:get(<<"source_sha256">>, evidence_identity()).

interop_peer_path(Id) -> filename:join(["build", "interop", "peers", Id ++ ".json"]).

interop_profile() -> evidence_json_decode(interop_read("standards/interop-profile.json")).

interop_read(Path) ->
    case file:read_file(Path) of
        {ok, Bytes} -> Bytes;
        {error, Reason} -> erlang:error({cannot_read, Path, Reason})
    end.

interop_file_digest(Path) -> string:lowercase(interop_hex(crypto:hash(sha256, interop_read(Path)))).

interop_hex(Binary) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [Byte]) || <<Byte>> <= Binary]).

interop_ensure(true, _Reason) -> ok;
interop_ensure(false, Reason) -> erlang:error(Reason).
