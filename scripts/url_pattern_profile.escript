#!/usr/bin/env escript
%%! +S 2:2 +SDcpu 1 +SDio 1 +A 1
-include("../test/url_pattern_profile.hrl").
main([]) ->
    case upp_inputs() of
        {ok,{P,F,C}} ->
            io:format("~s~n",[json:encode(#{scope=><<"Static URLPattern profile input validation; execution not certified">>,
                requirements=>length(maps:get(<<"requirements">>,P)),
                matrix_cases=>length(maps:get(<<"cases">>,C)),
                reference_cases=>length(maps:get(<<"cases">>,F)),qualification=>false})]);
        {error,invalid_urlpattern_profile} ->io:put_chars("URLPattern profile input invalid\n"),halt(1)
    end;
main(_)->halt(2).
