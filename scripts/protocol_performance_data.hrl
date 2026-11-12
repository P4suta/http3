%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PROTOCOL_PERFORMANCE_DATA_HRL).
-define(HTTP_PROTOCOL_PERFORMANCE_DATA_HRL, true).
pp_profile() -> #{protocols => [1,2,3], trials => 6, warmup_trials => 1,
    requests => 100, payload_bytes => 1024, child_timeout_ms => 270000,
    row_timeout_ms => 60000, sample_interval_ms => 10, max_samples => 4096,
    convergence_timeout_ms => 10000}.
%% Native callback terms are projected before crossing the worker boundary.
%% No arbitrary tuple, error text, endpoint, or exception payload is retained.
pp_sample({sample,P,100,1024,100,0,Accepted,Elapsed,Latencies}) ->
    try
        Safe=#{protocol=>P,requests=>100,payload_bytes=>1024,server_completed=>100,
            server_rejected=>0,accepted_connections=>pp_accepted(Accepted),
            elapsed_microseconds=>Elapsed,latencies=>pp_native_latencies(Latencies)},
        true=pp_sample_valid(Safe,P),{ok,Safe}
    catch _:_ -> error end;
pp_sample(_) -> error.

pp_accepted(none)->null;
pp_accepted({some,Count}) when is_integer(Count)->Count.
pp_native_latencies(Latencies) when is_list(Latencies),length(Latencies)=:=100 ->
    [case Latency of {latency,H,C}->#{headers_microseconds=>H,complete_microseconds=>C} end
     || Latency<-Latencies].
pp_sample_keys()->[protocol,requests,payload_bytes,server_completed,server_rejected,
    accepted_connections,elapsed_microseconds,latencies].
pp_sample_map(Value)->
    Normal=pp_map(Value,pp_sample_keys()),
    Rows=maps:get(latencies,Normal),true=is_list(Rows) andalso length(Rows)=:=100,
    Normal#{latencies:=[pp_map(Row,[headers_microseconds,complete_microseconds])||Row<-Rows]}.
pp_sample_valid(Value,P)->
    try
        Sample=pp_sample_map(Value),true=pp_int(P,1,3),P=maps:get(protocol,Sample),
        100=maps:get(requests,Sample),1024=maps:get(payload_bytes,Sample),
        100=maps:get(server_completed,Sample),0=maps:get(server_rejected,Sample),
        true=case {P,maps:get(accepted_connections,Sample)} of
            {3,null}->true;{1,1}->true;{2,1}->true;_->false end,
        Elapsed=maps:get(elapsed_microseconds,Sample),true=pp_int(Elapsed,1,60000000),
        true=lists:all(fun(Row)->H=maps:get(headers_microseconds,Row),C=maps:get(complete_microseconds,Row),
            pp_int(H,0,C) andalso pp_int(C,0,Elapsed) end,maps:get(latencies,Sample)),
        true=lists:sum([maps:get(complete_microseconds,Row)||Row<-maps:get(latencies,Sample)])=<Elapsed,
        true
    catch _:_ -> false end.

pp_failure(Value)->pp_failure(Value,0).
pp_failure(_,4)->pp_failure_leaf(<<"depth_limit">>);
pp_failure({cleanup_failed,Primary,Cleanup},Depth)->
    case Primary of
        none -> (pp_failure_leaf(<<"cleanup">>))#{cleanup:=pp_failure(Cleanup,Depth+1)};
        {some,Value}->(pp_failure_leaf(<<"cleanup">>))#{primary:=pp_failure(Value,Depth+1),
            cleanup:=pp_failure(Cleanup,Depth+1)};
        _->pp_failure_leaf(<<"invalid_result">>)
    end;
pp_failure({operation,Stage,{error_value,Kind}},_)->
    case {pp_int(Stage,0,255),pp_error(Kind)} of
        {true,Error} when Error=/=invalid -> (pp_failure_leaf(<<"operation">>))#{stage:=Stage,error:=Error};
        _->pp_failure_leaf(<<"invalid_result">>)
    end;
pp_failure({operation,Stage,{error_value,Kind,Evidence}},_)
        when Evidence=:=no_retry_evidence; Evidence=:=peer_guaranteed_unprocessed->
    case {pp_int(Stage,0,255),pp_error(Kind)} of
        {true,Error} when Error=/=invalid -> (pp_failure_leaf(<<"operation">>))#{stage:=Stage,error:=Error};
        _->pp_failure_leaf(<<"invalid_result">>)
    end;
pp_failure({invalid,Stage},_) when is_integer(Stage),Stage>=0,Stage=<255->
    (pp_failure_leaf(<<"invalid">>))#{stage:=Stage};
pp_failure({unexpected_response,Status,Phase},_)
        when is_integer(Status),Status>=100,Status=<599,is_integer(Phase),Phase>=0,Phase=<255->
    (pp_failure_leaf(<<"response">>))#{response_status:=Status,server_phase:=Phase};
pp_failure(_,_)->pp_failure_leaf(<<"invalid_result">>).

pp_failure_leaf(Kind)->#{kind=>Kind,stage=>0,error=><<"none">>,response_status=>0,
    server_phase=>0,primary=>null,cleanup=>null}.
pp_error(dns)-><<"dns">>;
pp_error(connect_failed)-><<"connect">>;
pp_error(tls)-><<"tls">>;
pp_error(cancelled)-><<"cancelled">>;
pp_error(service)-><<"service">>;
pp_error({timeout,Phase})->pp_choice(Phase,[{dns_lookup,<<"timeout_dns">>},{connect,<<"timeout_connect">>},
    {tls_handshake,<<"timeout_tls">>},{operation,<<"timeout_operation">>},{idle,<<"timeout_idle">>},{total,<<"timeout_total">>}]);
pp_error({protocol,Layer})->pp_choice(Layer,[{http1,<<"http1">>},{http2,<<"http2">>},{http3,<<"http3">>},{quic,<<"quic">>}]);
pp_error({policy,Kind})->pp_choice(Kind,[{redirect_policy,<<"policy_redirect">>},{retry_policy,<<"policy_retry">>},
    {security_policy,<<"policy_security">>},{proxy_policy,<<"policy_proxy">>},{cache_policy,<<"policy_cache">>}]);
pp_error({resource,Kind})->pp_choice(Kind,[{connections,<<"resource_connections">>},{streams,<<"resource_streams">>},
    {request_workers,<<"resource_workers">>},{memory,<<"resource_memory">>},{queue,<<"resource_queue">>},
    {buffered_body,<<"resource_body">>},{file_handles,<<"resource_files">>}]);
pp_error({body,{too_large,N}}) when is_integer(N),N>=0,N=<9007199254740991-><<"body_too_large">>;
pp_error({body,{length_mismatch,A,B}}) when is_integer(A),A>=0,A=<9007199254740991,
    is_integer(B),B>=0,B=<9007199254740991-><<"body_length">>;
pp_error({body,Kind})->pp_choice(Kind,[{invalid_limit,<<"body_limit">>},{read_failed,<<"body_read">>},
    {invalid_chunk,<<"body_chunk">>},{not_replayable,<<"body_replay">>}]);
pp_error(_)->invalid.
pp_choice(Value,Choices)->proplists:get_value(Value,Choices,invalid).
pp_error_values()->[<<"none">>,<<"error">>,<<"exit">>,<<"throw">>,<<"dns">>,<<"connect">>,<<"tls">>,
    <<"cancelled">>,<<"service">>,<<"timeout_dns">>,<<"timeout_connect">>,<<"timeout_tls">>,<<"timeout_operation">>,
    <<"timeout_idle">>,<<"timeout_total">>,<<"http1">>,<<"http2">>,<<"http3">>,<<"quic">>,
    <<"policy_redirect">>,<<"policy_retry">>,<<"policy_security">>,<<"policy_proxy">>,<<"policy_cache">>,
    <<"resource_connections">>,<<"resource_streams">>,<<"resource_workers">>,<<"resource_memory">>,
    <<"resource_queue">>,<<"resource_body">>,<<"resource_files">>,<<"body_too_large">>,<<"body_length">>,
    <<"body_limit">>,<<"body_read">>,<<"body_chunk">>,<<"body_replay">>].
pp_failure_map(null,_)->null;
pp_failure_map(Value,Depth) when Depth=<4->
    Normal=pp_map(Value,[kind,stage,error,response_status,server_phase,primary,cleanup]),
    Normal#{primary:=pp_failure_map(maps:get(primary,Normal),Depth+1),
        cleanup:=pp_failure_map(maps:get(cleanup,Normal),Depth+1)}.
pp_failure_valid(null)->true;
pp_failure_valid(Value)->
    try Safe=pp_failure_map(Value,0),pp_failure_tree_valid(Safe,0) catch _:_ ->false end.
pp_failure_tree_valid(null,_)->true;
pp_failure_tree_valid(Value,Depth) when Depth=<4->
    Kind=maps:get(kind,Value),Primary=maps:get(primary,Value),Cleanup=maps:get(cleanup,Value),
    lists:member(Kind,[<<"operation">>,<<"invalid">>,<<"response">>,<<"cleanup">>,<<"exception">>,
        <<"observer">>,<<"global_timeout">>,<<"preparation">>,<<"invalid_result">>,<<"depth_limit">>])
    andalso pp_int(maps:get(stage,Value),0,255)
    andalso pp_int(maps:get(response_status,Value),0,599)
    andalso pp_int(maps:get(server_phase,Value),0,255)
    andalso lists:member(maps:get(error,Value),pp_error_values())
    andalso (case Kind of
        <<"cleanup">>->Depth<4 andalso Cleanup=/=null;
        _->Primary=:=null andalso Cleanup=:=null end)
    andalso pp_failure_tree_valid(Primary,Depth+1) andalso pp_failure_tree_valid(Cleanup,Depth+1);
pp_failure_tree_valid(_,_)->false.

pp_child_keys()->[schema,status,nonce,protocol,configured_trials,completed_trials,requests,
    payload_bytes,elapsed_ms,global_timeout_ms,row_timeout_ms,rows,failure].
pp_child_map(Value)->
    Child=pp_map(Value,pp_child_keys()),Rows=maps:get(rows,Child),
    true=is_list(Rows) andalso length(Rows)=:=6,
    Child#{rows:=[pp_row_map(Row)||Row<-Rows],failure:=pp_failure_map(maps:get(failure,Child),0)}.
pp_row_map(Value)->
    Row=pp_map(Value,[trial,status,sample,failure,observation]),
    Sample=case maps:get(sample,Row) of null->null;S->pp_sample_map(S) end,
    Row#{sample:=Sample,failure:=pp_failure_map(maps:get(failure,Row),0)}.
pp_child_valid(Value,Protocol,Nonce)->
    try
        Child=pp_child_map(Value),true=pp_int(Protocol,1,3),Protocol=maps:get(protocol,Child),
        true=is_binary(Nonce) andalso byte_size(Nonce)=:=32,
        true=lists:all(fun(C)->(C>=$0 andalso C=<$9) orelse (C>=$a andalso C=<$f)
            orelse (C>=$A andalso C=<$F) end,binary_to_list(Nonce)),
        Nonce=maps:get(nonce,Child),1=maps:get(schema,Child),6=maps:get(configured_trials,Child),
        100=maps:get(requests,Child),1024=maps:get(payload_bytes,Child),
        270000=maps:get(global_timeout_ms,Child),60000=maps:get(row_timeout_ms,Child),
        true=pp_int(maps:get(elapsed_ms,Child),0,270000),
        Rows=maps:get(rows,Child),[0,1,2,3,4,5]=[maps:get(trial,Row)||Row<-Rows],
        true=maps:get(completed_trials,Child)=:=length([Row||Row<-Rows,pp_row_completed(Row)]),
        true=lists:sum([pp_get(work_elapsed_us,O)||Row<-Rows,O<-[maps:get(observation,Row)],O=/=null])
            =<maps:get(elapsed_ms,Child)*1000+1000,
        true=lists:all(fun(Row)->pp_row_valid(Row,Protocol) end,Rows),
        true=pp_failure_valid(maps:get(failure,Child)),
        true=maps:get(status,Child)=:=pp_status(maps:get(failure,Child)=:=null andalso
            maps:get(completed_trials,Child)=:=6 andalso
            lists:all(fun(Row)->maps:get(status,Row)=:=<<"Passed">> end,Rows)),true
    catch _:_ ->false end.
pp_row_valid(Row,P)->
    Sample=maps:get(sample,Row),Failure=maps:get(failure,Row),Observation=maps:get(observation,Row),
    (Sample=:=null orelse pp_sample_valid(Sample,P)) andalso pp_failure_valid(Failure)
    andalso (case Observation of
        null->Sample=:=null andalso Failure=/=null;
        _->http_protocol_observer:valid_report(Observation)
            andalso pp_get(clock_mode,Observation)=:=<<"runtime">>
            andalso pp_get(sampler_mode,Observation)=:=<<"runtime">>
            andalso pp_get(max_samples,Observation)=:=4096
            andalso pp_get(sample_interval_ms,Observation)=:=10
            andalso (pp_get(status,Observation)=/=<<"ok">>
                orelse pp_get(work_elapsed_us,Observation)=<60000000)
            andalso (Sample=:=null orelse maps:get(elapsed_microseconds,Sample)
                =<pp_get(work_elapsed_us,Observation)) end)
    andalso maps:get(status,Row)=:=pp_status(Sample=/=null andalso Failure=:=null
        andalso Observation=/=null andalso pp_get(status,Observation)=:=<<"ok">>).
pp_row_completed(Row)->case maps:get(observation,Row) of
    null->false;O->pp_get(work_started,O) andalso pp_get(work_finished,O) end.
pp_child_passed(Value)->
    try Child=pp_child_map(Value),pp_child_valid(Child,maps:get(protocol,Child),maps:get(nonce,Child))
        andalso maps:get(status,Child)=:=<<"Passed">> catch _:_ ->false end.
pp_status(true)-><<"Passed">>;pp_status(false)-><<"Failed">>.

%% Warmup is retained as trial0, excluded from all pooled statistics. Latency
%% percentiles use nearest rank over all500 requests, never per-trial means.
pp_summary(Children) when is_list(Children),length(Children)=<3 ->
    [pp_protocol_summary(P,Children)||P<-[1,2,3]];
pp_summary(_)->[pp_empty_summary(P)||P<-[1,2,3]].
pp_protocol_summary(P,Children)->
    try
        [Child]=[C||C<-Children,pp_get(protocol,C)=:=P],true=pp_child_passed(Child),
        Normal=pp_child_map(Child),[_Warmup|Rows]=maps:get(rows,Normal),
        Samples=[maps:get(sample,Row)||Row<-Rows],
        Rates=lists:sort([100000000/maps:get(elapsed_microseconds,S)||S<-Samples]),
        Elapsed=lists:sum([maps:get(elapsed_microseconds,S)||S<-Samples]),
        Latencies=lists:append([maps:get(latencies,S)||S<-Samples]),
        Headers=lists:sort([maps:get(headers_microseconds,L)||L<-Latencies]),
        Complete=lists:sort([maps:get(complete_microseconds,L)||L<-Latencies]),
        Peak=lists:foldl(fun(Row,Acc)->pp_peak(Acc,pp_get(peak,maps:get(observation,Row))) end,null,Rows),
        (pp_empty_summary(P))#{status:=<<"Passed">>,measured_trials:=5,requests:=500,
            elapsed_microseconds:=Elapsed,requests_per_second:=500000000/Elapsed,
            median_trial_requests_per_second:=lists:nth(3,Rates),
            headers_p50_microseconds:=pp_rank(Headers,50),headers_p95_microseconds:=pp_rank(Headers,95),
            headers_p99_microseconds:=pp_rank(Headers,99),complete_p50_microseconds:=pp_rank(Complete,50),
            complete_p95_microseconds:=pp_rank(Complete,95),complete_p99_microseconds:=pp_rank(Complete,99),
            resource_sampled_peak:=Peak}
    catch _:_ ->pp_empty_summary(P) end.
pp_empty_summary(P)->#{protocol=>P,status=><<"Failed">>,measured_trials=>0,requests=>0,payload_bytes=>1024,
    elapsed_microseconds=>0,requests_per_second=>0,median_trial_requests_per_second=>0,
    headers_p50_microseconds=>0,headers_p95_microseconds=>0,
    headers_p99_microseconds=>0,complete_p50_microseconds=>0,complete_p95_microseconds=>0,
    complete_p99_microseconds=>0,resource_peak_kind=><<"sampled">>,resource_sampled_peak=>null}.
pp_rank(Values,Percent)->lists:nth((length(Values)*Percent+99) div 100,Values).
pp_peak(null,Next)->pp_map(Next,[processes,project_processes,queued_messages,project_queued_messages,
    largest_mailbox,project_largest_mailbox,memory_bytes,ports,tcp_ports,udp_ports,sockets]);
pp_peak(Acc,Next)->maps:map(fun(Key,Value)->max(Value,pp_get(Key,Next)) end,Acc).

pp_int(Value,Min,Max)->is_integer(Value) andalso is_integer(Max) andalso Value>=Min andalso Value=<Max.
pp_get(Key,Value) when is_map(Value)->case maps:find(Key,Value) of
    {ok,Found}->Found;error->maps:get(atom_to_binary(Key),Value) end.
pp_map(Value,Keys) when is_map(Value)->
    true=map_size(Value)=:=length(Keys),
    SortedKeys=lists:sort(Keys),
    case lists:sort(maps:keys(Value)) of
        SortedKeys->Value;
        _->BinaryKeys=[atom_to_binary(Key)||Key<-Keys],
            true=lists:sort(maps:keys(Value))=:=lists:sort(BinaryKeys),
            maps:from_list([{Key,maps:get(atom_to_binary(Key),Value)}||Key<-Keys])
    end.
-endif.
