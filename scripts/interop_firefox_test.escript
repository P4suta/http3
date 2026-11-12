#!/usr/bin/env escript
%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-include("evidence_identity.hrl").
-include("interop_evidence.hrl").

main([])->
    try self_test() catch _:_ -> io:put_chars("Firefox evidence controls failed\n"),halt(1) end.

self_test()->
    Report=#{<<"peer">>=><<"firefox">>,<<"run_id">>=>binary:copy(<<"a">>,64),<<"source_sha256">>=>binary:copy(<<"b">>,64)},
    Rows=[fixture(Report,Scenario)||Scenario<-[<<"h1 body status and abort">>,<<"h2 body status and abort">>,
        <<"h3 body status and abort">>,<<"h1 untrusted certificate refused">>,
        <<"h2 untrusted certificate refused">>,<<"h3 untrusted certificate refused">>]],
    lists:foreach(fun(I)->ok=interop_browser_audit(Report,I) end,Rows),
    [Initial|_]=Rows,Browser=maps:get(<<"browser">>,Initial),Native=maps:get(<<"native">>,Initial),
    Child=maps:get(<<"child">>,Native),Completion=maps:get(<<"completion">>,Native),
    WrongBrowser=[maps:remove(K,Browser)||K<-maps:keys(Browser)]++
        [Browser#{<<"thread_peak">>=>0},Browser#{<<"thread_peak">>=>513},Browser#{<<"thread_peak">>=>true},Browser#{<<"thread_limit_hits">>=>1},Browser#{<<"oom_kills">>=>1},Browser#{<<"maximum_threads">>=>256},Browser#{<<"tls_verification">>=>false},Browser#{<<"browser_sandbox">>=>true},
         Browser#{<<"non_root">>=>false},Browser#{<<"network_loopback_only">>=>false},
         Browser#{<<"container_seccomp">>=>false},Browser#{<<"protocol">>=>2},
         Browser#{<<"nonce">>=>binary:copy(<<"c">>,32)},Browser#{<<"private">>=><<"private-browser-marker">>},
         Browser#{<<"ownership">>=>#{<<"children_observed">>=>0,<<"children_joined">>=>0}},
         Browser#{<<"ownership">>=>#{<<"children_observed">>=>8,<<"children_joined">>=>7}},
         Browser#{<<"ownership">>=>#{<<"children_observed">>=>257,<<"children_joined">>=>257}}],
    WrongNative=[Native#{<<"status">>=><<"Failed">>},Native#{<<"child">>=>null},
        Native#{<<"run_id">>=>binary:copy(<<"c">>,64)},Native#{<<"source_sha256">>=>binary:copy(<<"c">>,64)},
        Native#{<<"timeout_seconds">>=>120},Native#{<<"protocol">>=>2},Native#{<<"trusted">>=>false},
        Native#{<<"nonce">>=>binary:copy(<<"c">>,32)},
        Native#{<<"child">>=>Child#{<<"body_bytes_pulled">>=>0}},
        Native#{<<"child">>=>Child#{<<"abort_pull_down">>=>false}},
        Native#{<<"child">>=>Child#{<<"body_cleanup">>=>0}},
        Native#{<<"child">>=>Child#{<<"private">>=><<"private-native-marker">>}},
        Native#{<<"completion">>=>Completion#{<<"exit_status">>=>1}},
        Native#{<<"completion">>=>Completion#{<<"stdout_bytes">>=>1}},
        Native#{<<"completion">>=>Completion#{<<"exit_observed">>=>false}},
        Native#{<<"completion">>=>Completion#{<<"elapsed_milliseconds">>=>55001}},
        Native#{<<"private">>=><<"private-native-marker">>}],
    Bad=[Initial#{<<"browser">>=>B}||B<-WrongBrowser]++[Initial#{<<"native">>=>N}||N<-WrongNative],
    Rejected=length([ok||I<-Bad,rejected(fun()->interop_browser_audit(Report,I) end)]),
    case Rejected=:=length(Bad) of
        true->
            IdentityCases=identity_controls(Report,Initial),
            RetainedCases=retained_controls(Report,Rows),
            io:format("Firefox receipt controls: ~B rejected, 6 valid scopes, ~B identity and ~B retained controls~n",
                [Rejected,IdentityCases,RetainedCases]);
        false->io:format("Firefox receipt controls failed: rejected=~B required=~B~n",[Rejected,length(Bad)]),halt(1)
    end.

rejected(Fun)->try Fun(),false catch _:_ -> true end.

identity_controls(Report,Initial)->
    Pins=maps:get(<<"firefox">>,evidence_json_decode(interop_read("test/interop/browser/firefox-pins.json"))),
    Version=maps:get(<<"version">>,Pins),Pin = <<"firefox ",Version/binary>>,
    Hash=binary:copy(<<"d">>,64),Digest=#{<<"sha256">>=>Hash,<<"bytes">>=>1},
    Peer=#{<<"id">>=><<"firefox">>,<<"identity_kind">>=><<"browser">>,<<"pin">>=>Pin,
        <<"roles">>=>[<<"client">>],<<"browser_policy">>=>interop_firefox_policy(),
        <<"lock">>=><<"test/interop/browser/firefox-pins.json">>,
        <<"lock_sha256">>=>interop_file_digest("test/interop/browser/firefox-pins.json"),
        <<"fixture">>=><<"test/interop/browser/firefox_worker.py">>,
        <<"scenarios">>=>[maps:with([<<"role">>,<<"scenario">>],Initial)]},
    Dependencies=lists:append([begin
        Item=maps:get(Role,Pins),RoleVersion=maps:get(<<"version">>,Item),
        [#{<<"name">>=><<Role/binary,Suffix/binary>>,<<"version">>=>RoleVersion,
           <<"sha256">>=>Sha,<<"files">>=>Files}||{Suffix,Sha,Files}<-
            [{<<>>,maps:get(<<"executable_sha256">>,Item),1},
             {<<"-archive">>,maps:get(<<"sha256">>,Item),1},
             {<<"-resources">>,maps:get(<<"resource_sha256">>,Item),maps:get(<<"resource_files">>,Item)}]]
    end||Role<-[<<"browser">>,<<"driver">>]])++
        [#{<<"name">>=><<"python">>,<<"version">>=><<"3.12.3">>,<<"sha256">>=>Hash,<<"files">>=>1},
         #{<<"name">>=><<"nss-certutil">>,<<"version">>=><<"binary">>,<<"sha256">>=>Hash,<<"files">>=>1}],
    Identity=#{<<"kind">>=><<"browser">>,<<"executable">>=>Digest,<<"version">>=>Pin,
        <<"lock_sha256">>=>maps:get(<<"lock_sha256">>,Peer),
        <<"fixture_sha256">>=>interop_file_digest("test/interop/browser/firefox_worker.py"),
        <<"dependencies">>=>Dependencies},
    Invocation=Initial#{<<"identity">>=>Identity,<<"run_id">>=>maps:get(<<"run_id">>,Report),
        <<"source_sha256">>=>maps:get(<<"source_sha256">>,Report)},
    Check=fun(I)->interop_audit_invocation(Peer,Report,Invocation#{<<"identity">>=>I}) end,
    ok=Check(Identity),
    Bad=[Identity#{<<"version">>=><<"firefox 1">>},Identity#{<<"lock_sha256">>=>Hash},
        Identity#{<<"fixture_sha256">>=>Hash},Identity#{<<"dependencies">>=>[]},
        Identity#{<<"executable">>=>Digest#{<<"sha256">>=>binary:copy(<<"e">>,64)}}]++
        [Identity#{<<"dependencies">>=>lists:delete(D,Dependencies)}||D<-Dependencies]++
        [Identity#{<<"dependencies">>=>[D#{<<"sha256">>=>Hash}|lists:delete(D,Dependencies)]}
            ||D<-lists:sublist(Dependencies,6)],
    true=lists:all(fun(I)->rejected(fun()->Check(I) end) end,Bad),length(Bad).

retained_controls(Report,Rows)->
    Nonce=binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(16),lowercase)),
    Directory="build/interop-self-test/browser/"++Nonce,
    NativeDirectory=Directory++"/native",BrowserDirectory=Directory++"/browser",
    ok=filelib:ensure_dir(NativeDirectory++"/ignored"),ok=filelib:ensure_dir(BrowserDirectory++"/ignored"),
    Recorded=Report#{<<"invocations">>=>Rows},
    Check=fun()->interop_browser_retained_at(Recorded,NativeDirectory,BrowserDirectory) end,
    Name=fun(I)->binary_to_list(interop_bytes_digest([<<"client">>,<<0>>,maps:get(<<"scenario">>,I)]))++".json" end,
    true=rejected(Check),
    lists:foreach(fun(I)->
        ok=file:write_file(filename:join(NativeDirectory,Name(I)),json:encode(maps:get(<<"native">>,I))),
        ok=file:write_file(filename:join(BrowserDirectory,Name(I)),json:encode(maps:get(<<"browser">>,I)))
    end,Rows),
    ok=Check(),[First|_]=Rows,Path=filename:join(BrowserDirectory,Name(First)),
    {ok,Original}=file:read_file(Path),
    ok=file:write_file(Path,json:encode((maps:get(<<"browser">>,First))#{<<"private">>=><<"private-marker">>})),
    true=rejected(Check),
    <<"{",Rest/binary>>=Original,
    ok=file:write_file(Path,[<<"{\"schema\":1,">>,Rest]),true=rejected(Check),
    ok=file:write_file(Path,Original),ok=Check(),ok=file:delete(Path),true=rejected(Check),4.

fixture(Report,Scenario)->
    {Protocol,Trusted}=interop_browser_scope(Scenario),Nonce=interop_browser_nonce(Report,Scenario),
    Hash=binary:copy(<<"d">>,64),Digest=#{<<"sha256">>=>Hash,<<"bytes">>=>1},
    Completion=#{<<"outcome">>=><<"completed">>,<<"exit_status">>=>0,<<"exit_observed">>=>true,
        <<"controlled_shutdown">>=>false,<<"elapsed_milliseconds">>=>1,<<"stdout_bytes">>=>0,<<"stderr_bytes">>=>0},
    Browser=(interop_firefox_expected(Nonce,Protocol,Trusted))#{
        <<"thread_peak">>=>320,<<"ownership">>=>#{<<"children_observed">>=>8,<<"children_joined">>=>8}},
    Native=#{<<"schema">>=>1,<<"status">>=><<"Passed">>,<<"protocol">>=>Protocol,<<"trusted">>=>Trusted,
        <<"timeout_seconds">>=>50,<<"nonce">>=>Nonce,<<"run_id">>=>maps:get(<<"run_id">>,Report),
        <<"source_sha256">>=>maps:get(<<"source_sha256">>,Report),<<"completion">>=>Completion,
        <<"fixture">>=>#{<<"source">>=>Digest#{<<"sha256">>=>interop_file_digest("test/interop/browser/http_browser_interop.erl")},
            <<"beam">>=>Digest,<<"runtime">>=>Digest},
        <<"child">>=>interop_browser_native_expected(Nonce,Protocol,Trusted)},
    #{<<"role">>=><<"client">>,<<"scenario">>=>Scenario,<<"browser">>=>Browser,
      <<"native">>=>Native,<<"completion">>=>Completion}.
