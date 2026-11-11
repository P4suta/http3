%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(performance_comparison_host_test).
-include_lib("eunit/include/eunit.hrl").

bounded_cpu_ranges_expand_exactly_test()->
    ?assertEqual({ok,[0,1,2,5,7,8]},performance_comparison_host:parse_cpus(<<"0-2,5,7-8\n">>)),
    ?assertMatch({ok,[_|_]},performance_comparison_host:parse_cpus(<<"0-4095">>)),
    Invalid=[<<>>,<<"-1">>,<<"+1">>,<<"01">>,<<"1-0">>,<<"1-1">>,<<"0,0">>,
        <<"0-2,2-3">>,<<"2,1">>,<<"0-4096">>,<<"0-9999999999999999999">>,
        <<"1048576">>,<<"0,">>,binary:copy(<<"0">>,32769)],
    lists:foreach(fun(B)->?assertMatch({error,_},performance_comparison_host:parse_cpus(B)) end,Invalid).

cpu_model_is_observed_per_allowed_cpu_and_dynamic_frequency_is_ignored_test()->
    A=cpu(0,<<"private-model-marker">>,<<"1000.00">>),
    B=cpu(0,<<"private-model-marker">>,<<"4500.00">>),
    {ok,Hash}=performance_comparison_host:cpu_fingerprint(A,[0]),
    ?assertEqual({ok,Hash},performance_comparison_host:cpu_fingerprint(B,[0])),
    ?assertEqual(64,byte_size(Hash)),
    ?assertEqual(nomatch,binary:match(iolist_to_binary(json:encode(#{cpu_model_sha256=>Hash})),<<"private-model-marker">>)),
    ?assertNotEqual({ok,Hash},performance_comparison_host:cpu_fingerprint(cpu(0,<<"different">>,<<"1000">>),[0])),
    ?assertMatch({error,_},performance_comparison_host:cpu_fingerprint(A,[0,1])),
    ?assertMatch({error,_},performance_comparison_host:cpu_fingerprint(<<A/binary,A/binary>>,[0])),
    ?assertMatch({error,_},performance_comparison_host:cpu_fingerprint(binary:copy(<<"x">>,1048577),[0])).

limits_are_bounded_and_unlimited_is_explicit_test()->
    ?assertEqual({ok,<<"unlimited">>},performance_comparison_host:parse_limit(<<"max\n">>)),
    ?assertEqual({ok,0},performance_comparison_host:parse_limit(<<"0">>)),
    ?assertEqual({ok,9223372036854775807},performance_comparison_host:parse_limit(<<"9223372036854775807">>)),
    lists:foreach(fun(B)->?assertMatch({error,_},performance_comparison_host:parse_limit(B)) end,
        [<<"-1">>,<<"+1">>,<<"01">>,<<"9223372036854775808">>,<<"unknown">>,<<"max extra">>]),
    ?assertEqual({ok,{400000,100000}},performance_comparison_host:parse_cpu_max(<<"400000 100000\n">>)),
    ?assertEqual({ok,{<<"unlimited">>,100000}},performance_comparison_host:parse_cpu_max(<<"max 100000">>)),
    lists:foreach(fun(B)->?assertMatch({error,_},performance_comparison_host:parse_cpu_max(B)) end,
        [<<"0 100000">>,<<"400000 0">>,<<"max max">>,<<"max 1000000001">>,<<"max 1000 x">>]).

image_input_is_content_addressed_but_never_observed_test()->
    Image= <<"sha256:",(binary:copy(<<"a">>,64))/binary>>,
    ?assert(performance_comparison_host:validate_image(Image)),
    ?assertNot(performance_comparison_host:validate_image(<<"image:latest">>)),
    ?assertNot(performance_comparison_host:validate_image(<<"sha256:",(binary:copy(<<"A">>,64))/binary>>)),
    ?assertMatch({error,invalid_image_input},performance_comparison_host:capture(<<"image:latest">>)),
    {ok,Report}=performance_comparison_host:capture(Image),
    ?assert(performance_comparison_host:validate_capture(Report)),
    ?assertEqual(<<"declared">>,maps:get(image_provenance,Report)),
    ?assertEqual(<<"Blocked">>,maps:get(qualification_status,Report)),
    ?assertNot(performance_comparison_host:validate_capture(Report#{image_provenance:= <<"observed">>})).

actual_capture_is_strict_and_missing_conditions_cannot_qualify_test()->
    {ok,Report}=performance_comparison_host:capture(null),
    ?assert(performance_comparison_host:validate_capture(Report)),
    ?assert(performance_comparison_host:validate_capture(json:decode(iolist_to_binary(json:encode(Report))))),
    ?assertEqual(<<"Blocked">>,maps:get(qualification_status,Report)),
    ?assertNot(performance_comparison_host:validate_capture(Report#{qualification_status:= <<"Ready">>})),
    ?assertNot(performance_comparison_host:validate_capture(Report#{private=><<"hidden">>})),
    ?assertNot(performance_comparison_host:validate_capture(maps:remove(observations,Report))),
    ?assertNot(performance_comparison_host:validate_capture(Report#{observations:= []})),
    case maps:get(status,Report) of
        <<"Incomplete">>->?assertEqual(null,maps:get(host,Report));
        <<"Observed">>->?assert(performance_comparison:validate_host(maps:get(host,Report)))
    end.

cgroup_namespace_must_identify_the_actual_visible_root_test()->
    Mount= <<"29 23 0:26 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n">>,
    ?assert(performance_comparison_host:validate_cgroup_root(<<"0::/\n">>,Mount)),
    lists:foreach(fun(Membership)->
        ?assertNot(performance_comparison_host:validate_cgroup_root(Membership,Mount))
    end,[<<"0::/other">>,<<"0::/../other">>,<<"1:cpu:/\n0::/">>,<<"0::/\n0::/">>]),
    ?assertNot(performance_comparison_host:validate_cgroup_root(<<"0::/">>,<<Mount/binary,Mount/binary>>)),
    ?assertNot(performance_comparison_host:validate_cgroup_root(<<"0::/">>,
        binary:replace(Mount,<<" / /sys">>,<<" /ancestor /sys">>))),
    ?assertNot(performance_comparison_host:validate_cgroup_root(<<"0::/">>,
        binary:replace(Mount,<<"/sys/fs/cgroup">>,<<"/other/mount">>))).

cpu(Id,Model,Mhz)->iolist_to_binary(["processor : ",integer_to_list(Id),"\n",
    "vendor_id : GenuineIntel\ncpu family : 6\nmodel : 85\nmodel name : ",Model,
    "\nstepping : 7\nflags : fpu sse\ncpu MHz : ",Mhz,"\n\n"]).
