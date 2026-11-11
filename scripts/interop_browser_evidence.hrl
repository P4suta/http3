%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0

-compile({nowarn_unused_function, [{interop_browser_retained_files, 0}]}).

interop_browser_scope(<<"h1 body status and abort">>)->{1,true};
interop_browser_scope(<<"h2 body status and abort">>)->{2,true};
interop_browser_scope(<<"h3 body status and abort">>)->{3,true};
interop_browser_scope(<<"h1 untrusted certificate refused">>)->{1,false};
interop_browser_scope(<<"h2 untrusted certificate refused">>)->{2,false};
interop_browser_scope(<<"h3 untrusted certificate refused">>)->{3,false}.

interop_browser_nonce(Report,Scenario)->
    binary:part(interop_bytes_digest([maps:get(<<"run_id">>,Report),<<0>>,Scenario]),0,32).

interop_browser_audit(Report,Invocation)->
    Scenario=maps:get(<<"scenario">>,Invocation),{Protocol,Trusted}=interop_browser_scope(Scenario),
    interop_ensure(maps:get(<<"role">>,Invocation)=:=<<"client">>,invalid_browser_role),
    Nonce=interop_browser_nonce(Report,Scenario),
    Browser=maps:get(<<"browser">>,Invocation),
    {Expected,Observed}=case maps:get(<<"peer">>,Report) of
        <<"chromium">>->{interop_browser_expected(Nonce,Protocol,Trusted),maps:remove(<<"ownership">>,Browser)};
        <<"firefox">>->
            interop_integer(maps:get(<<"thread_peak">>,Browser),1,512),
            {interop_firefox_expected(Nonce,Protocol,Trusted),maps:without([<<"ownership">>,<<"thread_peak">>],Browser)}
    end,
    interop_ensure(Observed=:=Expected,
        incomplete_or_private_browser_observation),
    Ownership=maps:get(<<"ownership">>,Browser),
    interop_keys(Ownership,[<<"children_observed">>,<<"children_joined">>]),
    Count=maps:get(<<"children_observed">>,Ownership),interop_integer(Count,1,256),
    interop_ensure(maps:get(<<"children_joined">>,Ownership)=:=Count,browser_children_not_joined),
    interop_browser_completion(maps:get(<<"completion">>,Invocation),65),
    Native=maps:get(<<"native">>,Invocation),
    interop_keys(Native,[<<"schema">>,<<"status">>,<<"protocol">>,<<"trusted">>,<<"timeout_seconds">>,
        <<"nonce">>,<<"fixture">>,<<"completion">>,<<"child">>,<<"run_id">>,<<"source_sha256">>]),
    interop_ensure(maps:get(<<"schema">>,Native)=:=1 andalso maps:get(<<"status">>,Native)=:=<<"Passed">>
        andalso maps:get(<<"protocol">>,Native)=:=Protocol andalso maps:get(<<"trusted">>,Native)=:=Trusted
        andalso maps:get(<<"nonce">>,Native)=:=Nonce andalso maps:get(<<"timeout_seconds">>,Native)=:=50,
        invalid_browser_native_scope),
    interop_ensure(maps:get(<<"run_id">>,Native)=:=maps:get(<<"run_id">>,Report)
        andalso maps:get(<<"source_sha256">>,Native)=:=maps:get(<<"source_sha256">>,Report),stale_browser_native),
    interop_ensure(maps:get(<<"child">>,Native)=:=interop_browser_native_expected(Nonce,Protocol,Trusted),
        incomplete_browser_native_work_or_cleanup),
    Fixture=maps:get(<<"fixture">>,Native),interop_keys(Fixture,[<<"source">>,<<"beam">>,<<"runtime">>]),
    lists:foreach(fun(Value)->
        interop_keys(Value,[<<"sha256">>,<<"bytes">>]),interop_digest(maps:get(<<"sha256">>,Value)),
        interop_integer(maps:get(<<"bytes">>,Value),1,268435456)
    end,maps:values(Fixture)),
    interop_ensure(maps:get(<<"sha256">>,maps:get(<<"source">>,Fixture))=:=
        interop_file_digest("test/interop/browser/http_browser_interop.erl"),stale_browser_native_fixture),
    interop_browser_completion(maps:get(<<"completion">>,Native),50).

interop_browser_completion(Completion,Timeout)->
    Expected=#{<<"outcome">>=><<"completed">>,<<"exit_status">>=>0,<<"exit_observed">>=>true,
        <<"controlled_shutdown">>=>false,<<"stdout_bytes">>=>0,<<"stderr_bytes">>=>0},
    interop_ensure(maps:remove(<<"elapsed_milliseconds">>,Completion)=:=Expected,
        incomplete_or_private_browser_process),
    interop_integer(maps:get(<<"elapsed_milliseconds">>,Completion),0,(Timeout+5)*1000).

interop_browser_expected(Nonce,Protocol,Trusted)->
    Observation=case Trusted of
        true->#{<<"status">>=>201,<<"bytes">>=>72250,<<"payload_valid">>=>true,
            <<"next_hop">>=>case Protocol of 1-><<"http/1.1">>;2-><<"h2">>;3-><<"h3">> end,
            <<"secure_context">>=>true,<<"aborted">>=>true,<<"abort_name">>=><<"AbortError">>};
        false->#{<<"certificate_rejected">>=>true,<<"net_error">>=>-202,<<"http_response_observed">>=>false}
    end,
    #{<<"schema">>=>1,<<"nonce">>=>Nonce,<<"protocol">>=>Protocol,<<"trusted">>=>Trusted,
      <<"observation">>=>Observation,<<"browser_sandbox">>=>false,<<"container_seccomp">>=>true,
      <<"non_root">>=>true,<<"network_loopback_only">>=>true,<<"tls_verification">>=>true}.

interop_browser_native_expected(Nonce,Protocol,Trusted)->
    #{<<"schema">>=>1,<<"nonce">>=>Nonce,<<"protocol">>=>Protocol,<<"stopped">>=>true,
      <<"document_requests">>=>case Trusted of true->1;false->0 end,
      <<"body_requests">>=>case Trusted of true->1;false->0 end,
      <<"body_bytes_pulled">>=>case Trusted of true->72250;false->0 end,
      <<"body_eof">>=>case Trusted of true->1;false->0 end,
      <<"body_cleanup">>=>case Trusted of true->1;false->0 end,
      <<"abort_requests">>=>case Trusted of true->1;false->0 end,
      <<"abort_source_entered">>=>case Trusted of true->1;false->0 end,
      <<"abort_source_cancelled">>=>case Trusted of true->1;false->0 end,
      <<"abort_pull_down">>=>Trusted}.

interop_firefox_expected(Nonce,Protocol,Trusted)->
    Common=interop_browser_expected(Nonce,Protocol,Trusted),
    Observation=case Trusted of
        true->maps:get(<<"observation">>,Common);
        false->#{<<"certificate_rejected">>=>true,<<"webdriver_error">>=><<"insecure certificate">>}
    end,
    Common#{<<"observation">>=>Observation,<<"browser_sandbox">>=><<"default">>,
        <<"maximum_threads">>=>512,<<"thread_limit_hits">>=>0,<<"oom_kills">>=>0,
        <<"h3_forced_mapping">>=>Protocol=:=3,<<"h3_private_root_policy">>=>Protocol=:=3}.

interop_firefox_policy()->
    #{<<"h3_route">>=><<"explicit-loopback-alt-svc">>,<<"private_roots_allow_h3">>=>true,
      <<"tls_verification">>=>true,<<"maximum_threads">>=>512,<<"sandbox">>=><<"default">>}.

interop_browser_identity(Peer,Identity)->
    Id=maps:get(<<"id">>,Peer),
    {Lock,Fixture}=case Id of
        <<"chromium">>->{"test/interop/browser/pins.json","test/interop/browser/browser_worker.py"};
        <<"firefox">>->
            interop_ensure(maps:get(<<"browser_policy">>,Peer)=:=interop_firefox_policy(),invalid_firefox_policy),
            {"test/interop/browser/firefox-pins.json","test/interop/browser/firefox_worker.py"}
    end,
    interop_ensure(maps:get(<<"lock">>,Peer)=:=list_to_binary(Lock)
        andalso maps:get(<<"fixture">>,Peer)=:=list_to_binary(Fixture),invalid_browser_profile),
    interop_ensure(interop_file_digest(Lock)=:=maps:get(<<"lock_sha256">>,Peer)
        andalso interop_file_digest(Fixture)=:=maps:get(<<"fixture_sha256">>,Identity),stale_browser_source),
    Pins=maps:get(Id,evidence_json_decode(interop_read_bounded(Lock,16384))),
    Version=maps:get(<<"version">>,Pins),Pin = <<Id/binary," ",Version/binary>>,
    interop_ensure(maps:get(<<"pin">>,Peer)=:=Pin andalso maps:get(<<"version">>,Identity)=:=Pin,
        wrong_browser_version),
    Dependencies=maps:get(<<"dependencies">>,Identity),
    lists:foreach(fun(Role)->
        Item=maps:get(Role,Pins),RoleVersion=maps:get(<<"version">>,Item,Version),
        lists:foreach(fun({Suffix,Hash,Files})->
            Name = <<Role/binary,Suffix/binary>>,
            Expected=#{<<"name">>=>Name,<<"version">>=>RoleVersion,<<"sha256">>=>Hash,<<"files">>=>Files},
            interop_ensure([D||D<-Dependencies,maps:get(<<"name">>,D)=:=Name]=:=[Expected],
                browser_distribution_not_pinned)
        end,[{<<>>,maps:get(<<"executable_sha256">>,Item),1},
             {<<"-archive">>,maps:get(<<"sha256">>,Item),1},
             {<<"-resources">>,maps:get(<<"resource_sha256">>,Item),maps:get(<<"resource_files">>,Item)}])
    end,[<<"browser">>,<<"driver">>]),
    [Python]=[D||D<-Dependencies,maps:get(<<"name">>,D)=:=<<"python">>],
    interop_ensure(maps:get(<<"sha256">>,Python)=:=maps:get(<<"sha256">>,maps:get(<<"executable">>,Identity))
        andalso maps:get(<<"files">>,Python)=:=1,browser_interpreter_not_executed),
    [Certutil]=[D||D<-Dependencies,maps:get(<<"name">>,D)=:=<<"nss-certutil">>],
    interop_ensure(maps:get(<<"version">>,Certutil)=:=<<"binary">>
        andalso maps:get(<<"files">>,Certutil)=:=1,missing_browser_trust_tool).

interop_browser_retained_at(Report,NativeDirectory,BrowserDirectory)->
    lists:foreach(fun(Invocation)->
        interop_browser_audit(Report,Invocation),
        Name=binary_to_list(interop_bytes_digest([<<"client">>,<<0>>,maps:get(<<"scenario">>,Invocation)]))++".json",
        Native=evidence_json_decode(interop_read_bounded(filename:join(NativeDirectory,Name),1048576)),
        Browser=evidence_json_decode(interop_read_bounded(filename:join(BrowserDirectory,Name),16384)),
        interop_ensure(Native=:=maps:get(<<"native">>,Invocation)
            andalso Browser=:=maps:get(<<"browser">>,Invocation),replaced_browser_receipt)
    end,maps:get(<<"invocations">>,Report)).

interop_browser_retained_files()->
    [Directory++"/"++binary_to_list(interop_bytes_digest([<<"client">>,<<0>>,Scenario]))++".json"
        ||Directory<-["build/interop/native/chromium","build/interop/browser/chromium",
                      "build/interop/native/firefox","build/interop/browser/firefox"],
          Scenario<-[<<"h1 body status and abort">>,<<"h2 body status and abort">>,<<"h3 body status and abort">>,
            <<"h1 untrusted certificate refused">>,<<"h2 untrusted certificate refused">>,
            <<"h3 untrusted certificate refused">>]].
