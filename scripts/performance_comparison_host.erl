%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(performance_comparison_host).
-export([capture/1,validate_capture/1,parse_cpus/1,cpu_fingerprint/2,
    parse_limit/1,parse_cpu_max/1,validate_image/1,validate_cgroup_root/2]).

%% This is an observation helper, never a qualification issuer. In particular,
%% a container cannot attest its own image or unseen ancestor cgroup limits.
capture(Image) when Image=:=null;is_binary(Image)->
    case Image=:=null orelse validate_image(Image) of
        false->{error,invalid_image_input};
        true->
            Platform=case os:type() of {unix,linux}-> <<"linux-cgroup-v2">>;_-> <<"unsupported">> end,
            Runtime=observed(<<"runtime">>,#{schedulers_online=>erlang:system_info(schedulers_online),
                dirty_cpu_schedulers_online=>erlang:system_info(dirty_cpu_schedulers_online)}),
            Groups=case Platform of
                <<"unsupported">>->[unavailable(G,<<"unsupported_platform">>)||G<-groups(),G=/= <<"runtime">>];
                _->linux_groups()
            end,
            Observations=Groups++[Runtime],Host=host(Platform,Observations),
            {ok,#{schema=>1,status=>case Host of null-> <<"Incomplete">>;_-> <<"Observed">> end,
                platform=>Platform,observations=>Observations,host=>Host,image_digest=>Image,
                image_provenance=>case Image of null-> <<"unavailable">>;_-> <<"declared">> end,
                qualification_status=> <<"Blocked">>}}
    end;
capture(_)->{error,invalid_image_input}.

linux_groups()->
    Kernel=probe(<<"kernel">>,fun()->#{kernel_sha256=>hash(nonempty(read("/proc/sys/kernel/osrelease",256)))} end),
    Affinity=probe(<<"affinity">>,fun()->
        Status=read("/proc/self/status",1048576),
        [Allowed]=[trim(V)||Line<-binary:split(Status,<<"\n">>,[global]),
            [<<"Cpus_allowed_list">>,V]<-[binary:split(Line,<<":">>)]],
        {ok,Cpus}=parse_cpus(Allowed),#{affinity_cpus=>Cpus}
    end),
    {Cpu,Governor}=case Affinity of
        #{status:= <<"Observed">>,values:=#{affinity_cpus:=AllowedCpus}}->
            {probe(<<"cpu_model">>,fun()->
                {ok,H}=cpu_fingerprint(read("/proc/cpuinfo",1048576),AllowedCpus),#{cpu_model_sha256=>H}
            end),probe(<<"governor">>,fun()->
                Values=[{CpuId,nonempty(read("/sys/devices/system/cpu/cpu"++integer_to_list(CpuId)++
                    "/cpufreq/scaling_governor",256))}||CpuId<-AllowedCpus],
                #{governor_sha256=>hash(term_to_binary(Values,[deterministic]))}
            end)};
        _->{unavailable(<<"cpu_model">>,<<"missing_precondition">>),
            unavailable(<<"governor">>,<<"missing_precondition">>)}
    end,
    [Kernel,Affinity,Cpu,Governor,probe(<<"cgroup">>,fun cgroup/0)].

cgroup()->
    %% First supported topology is the visible unified namespace root. Do not
    %% accidentally read a parent's or sibling's limits in another topology.
    true=validate_cgroup_root(read("/proc/self/cgroup",32768),read("/proc/self/mountinfo",1048576)),
    _=nonempty(read("/sys/fs/cgroup/cgroup.controllers",4096)),
    {ok,Cpuset}=parse_cpus(read("/sys/fs/cgroup/cpuset.cpus.effective",32768)),
    {ok,{Quota,Period}}=parse_cpu_max(read("/sys/fs/cgroup/cpu.max",256)),
    {ok,Memory}=parse_limit(read("/sys/fs/cgroup/memory.max",256)),
    {ok,Swap}=parse_limit(read("/sys/fs/cgroup/memory.swap.max",256)),
    {ok,Pids}=parse_limit(read("/sys/fs/cgroup/pids.max",256)),
    #{cpuset_cpus=>Cpuset,cpu_quota_us=>Quota,cpu_period_us=>Period,
        memory_limit_bytes=>Memory,memory_swap_limit_bytes=>Swap,pids_limit=>Pids}.

parse_cpus(B) when is_binary(B),byte_size(B)=<32768->
    try
        Parts=binary:split(trim(B),<<",">>,[global]),
        {_,Reversed}=lists:foldl(fun(Part,{Count,Acc})->
            {First,Last}=case binary:split(Part,<<"-">>,[global]) of
                [One]->N=integer(One,0,1048575),{N,N};
                [Start,End]->A=integer(Start,0,1048575),Z=integer(End,0,1048575),true=A<Z,{A,Z}
            end,
            Next=Count+Last-First+1,true=Next=<4096,
            {Next,lists:reverse(lists:seq(First,Last),Acc)}
        end,{0,[]},Parts),
        Cpus=lists:reverse(Reversed),true=valid_cpus(Cpus),{ok,Cpus}
    catch _:_->{error,invalid_cpu_list} end;
parse_cpus(_)->{error,invalid_cpu_list}.

cpu_fingerprint(B,Cpus) when is_binary(B),byte_size(B)=<1048576->
    try
        true=valid_cpus(Cpus),Records=[R||R<-binary:split(B,<<"\n\n">>,[global]),trim(R)=/= <<>>],
        true=length(Records)=<4096,
        Parsed=[cpu_record(R)||R<-Records],Ids=[Id||{Id,_}<-Parsed],true=length(Ids)=:=length(lists:usort(Ids)),
        ById=maps:from_list(Parsed),Selected=[{Cpu,maps:get(Cpu,ById)}||Cpu<-Cpus],
        {ok,hash(term_to_binary(Selected,[deterministic]))}
    catch _:_->{error,invalid_cpu_description} end;
cpu_fingerprint(_,_)->{error,invalid_cpu_description}.
cpu_record(Record)->
    Keys=[<<"vendor_id">>,<<"cpu family">>,<<"model">>,<<"model name">>,<<"stepping">>,<<"flags">>],
    Fields=[{trim(K),trim(V)}||Line<-binary:split(Record,<<"\n">>,[global]),
        [K,V]<-[binary:split(Line,<<":">>)],lists:member(trim(K),[<<"processor">>|Keys])],
    true=length(Fields)=:=length(Keys)+1,Map=maps:from_list(Fields),true=map_size(Map)=:=length(Fields),
    Id=integer(maps:get(<<"processor">>,Map),0,1048575),
    Values=[{K,nonempty(maps:get(K,Map))}||K<-Keys],
    true=lists:all(fun({_,V})->byte_size(V)=<16384 end,Values),{Id,Values}.

parse_limit(B) when is_binary(B),byte_size(B)=<256->
    try case trim(B) of <<"max">>->{ok,<<"unlimited">>};V->{ok,integer(V,0,9223372036854775807)} end
    catch _:_->{error,invalid_limit} end;
parse_limit(_)->{error,invalid_limit}.
parse_cpu_max(B) when is_binary(B),byte_size(B)=<256->
    try
        [Q,P]=binary:split(trim(B),<<" ">>,[global]),{ok,Quota}=parse_limit(Q),
        true=Quota=:= <<"unlimited">> orelse Quota>0,{ok,{Quota,integer(P,1,1000000000)}}
    catch _:_->{error,invalid_cpu_limit} end;
parse_cpu_max(_)->{error,invalid_cpu_limit}.
validate_image(<<"sha256:",Hash/binary>>)->digest(Hash);
validate_image(_)->false.

validate_capture(Value)->
    try
        R=fields(Value,[schema,status,platform,observations,host,image_digest,image_provenance,qualification_status]),
        1=maps:get(schema,R),<<"Blocked">>=maps:get(qualification_status,R),
        Platform=maps:get(platform,R),true=lists:member(Platform,[<<"linux-cgroup-v2">>,<<"unsupported">>]),
        Image=maps:get(image_digest,R),Provenance=case Image of null-> <<"unavailable">>;_->true=validate_image(Image),<<"declared">> end,
        Provenance=maps:get(image_provenance,R),
        Observations=maps:get(observations,R),true=is_list(Observations) andalso length(Observations)=:=6,
        Normalized=[validate_observation(O)||O<-Observations],groups_match(Normalized),
        true=Platform=/= <<"unsupported">> orelse lists:all(fun(O)->
            maps:get(group,O)=:= <<"runtime">> orelse maps:get(status,O)=:= <<"Unavailable">> end,Normalized),
        ExpectedHost=host(Platform,Normalized),ExpectedStatus=case ExpectedHost of null-> <<"Incomplete">>;_-> <<"Observed">> end,
        ExpectedStatus=maps:get(status,R),
        case ExpectedHost of
            null->null=maps:get(host,R);
            _->ok=performance_comparison:compare_hosts(ExpectedHost,maps:get(host,R))
        end,true
    catch _:_ ->false end.
validate_cgroup_root(Membership,MountInfo) when is_binary(Membership),byte_size(Membership)=<32768,
        is_binary(MountInfo),byte_size(MountInfo)=<1048576->
    try
        <<"0::/">>=trim(Membership),
        Mounts=binary:split(MountInfo,<<"\n">>,[global]),
        [Mount]=[Line||Line<-Mounts,binary:match(Line,<<" - cgroup2 ">>)=/=nomatch],
        [_,_,_,<<"/">>,<<"/sys/fs/cgroup">>|_]=binary:split(Mount,<<" ">>,[global]),true
    catch _:_ ->false end;
validate_cgroup_root(_,_)->false.
validate_observation(O)->
    case maps:get(status,O,maps:get(<<"status">>,O,undefined)) of
        <<"Unavailable">>->N=fields(O,[group,status,reason]),
            true=lists:member(maps:get(group,N),groups()),
            true=lists:member(maps:get(reason,N),[<<"unsupported_platform">>,<<"read_unavailable">>,
                <<"probe_too_large">>,<<"invalid_probe">>,<<"missing_precondition">>]),N;
        <<"Observed">>->N=fields(O,[group,status,values]),G=maps:get(group,N),
            Values=fields(maps:get(values,N),value_keys(G)),true=valid_values(G,Values),N#{values:=Values}
    end.
valid_values(<<"kernel">>,V)->digest(maps:get(kernel_sha256,V));
valid_values(<<"cpu_model">>,V)->digest(maps:get(cpu_model_sha256,V));
valid_values(<<"governor">>,V)->digest(maps:get(governor_sha256,V));
valid_values(<<"affinity">>,V)->valid_cpus(maps:get(affinity_cpus,V));
valid_values(<<"runtime">>,V)->lists:all(fun(N)->is_integer(N) andalso N>0 andalso N=<4096 end,maps:values(V));
valid_values(<<"cgroup">>,V)->valid_cpus(maps:get(cpuset_cpus,V))
    andalso valid_limit(maps:get(cpu_quota_us,V),1)
    andalso is_integer(maps:get(cpu_period_us,V)) andalso maps:get(cpu_period_us,V)>0 andalso maps:get(cpu_period_us,V)=<1000000000
    andalso lists:all(fun(K)->valid_limit(maps:get(K,V),0) end,[memory_limit_bytes,memory_swap_limit_bytes,pids_limit]).
value_keys(<<"kernel">>)->[kernel_sha256];
value_keys(<<"cpu_model">>)->[cpu_model_sha256];
value_keys(<<"governor">>)->[governor_sha256];
value_keys(<<"affinity">>)->[affinity_cpus];
value_keys(<<"runtime">>)->[schedulers_online,dirty_cpu_schedulers_online];
value_keys(<<"cgroup">>)->[cpuset_cpus,cpu_quota_us,cpu_period_us,memory_limit_bytes,memory_swap_limit_bytes,pids_limit].
groups()->[<<"kernel">>,<<"affinity">>,<<"cpu_model">>,<<"governor">>,<<"cgroup">>,<<"runtime">>].
groups_match(Observations)->true=[maps:get(group,O)||O<-Observations]=:=groups().
host(Platform,Observations)->
    case Platform=:= <<"linux-cgroup-v2">> andalso lists:all(fun(O)->maps:get(status,O)=:= <<"Observed">> end,Observations) of
        false->null;
        true->H=lists:foldl(fun(O,A)->maps:merge(A,maps:get(values,O)) end,
            #{schema=>1,provenance=> <<"runtime_probe">>,platform=>Platform},Observations),
            case performance_comparison:validate_host(H) of true->H;false->null end
    end.
probe(Group,Read)->
    try Values=Read(),true=valid_values(Group,Values),observed(Group,Values)
    catch throw:{probe_error,Reason}->unavailable(Group,Reason);_:_->unavailable(Group,<<"invalid_probe">>) end.
observed(Group,Values)->#{group=>Group,status=> <<"Observed">>,values=>Values}.
unavailable(Group,Reason)->#{group=>Group,status=> <<"Unavailable">>,reason=>Reason}.
read(Path,Maximum)->
    case file:open(Path,[read,binary,raw]) of
        {ok,File}->try case file:read(File,Maximum+1) of
            {ok,B} when byte_size(B)=<Maximum->B;
            {ok,_}->throw({probe_error,<<"probe_too_large">>});
            eof-> <<>>;
            {error,_}->throw({probe_error,<<"read_unavailable">>})
        end after file:close(File) end;
        {error,_}->throw({probe_error,<<"read_unavailable">>})
    end.
fields(Value,Keys) when is_map(Value),map_size(Value)=:=length(Keys)->
    Sorted=lists:sort(Keys),case lists:sort(maps:keys(Value)) of
        Sorted->Value;
        _->Expected=lists:sort([atom_to_binary(K)||K<-Keys]),Expected=lists:sort(maps:keys(Value)),
            maps:from_list([{K,maps:get(atom_to_binary(K),Value)}||K<-Keys])
    end.
integer(B,Min,Max) when is_binary(B),byte_size(B)>0,byte_size(B)=<20->
    true=lists:all(fun(C)->C>=$0 andalso C=<$9 end,binary_to_list(B)),
    N=binary_to_integer(B),B=integer_to_binary(N),true=N>=Min andalso N=<Max,N.
valid_cpus(C)->is_list(C) andalso length(C)>0 andalso length(C)=<4096 andalso C=:=lists:usort(C)
    andalso lists:all(fun(N)->is_integer(N) andalso N>=0 andalso N=<1048575 end,C).
valid_limit(<<"unlimited">>,_)->true;
valid_limit(N,Min)->is_integer(N) andalso N>=Min andalso N=<9223372036854775807.
digest(B) when is_binary(B),byte_size(B)=:=64->
    lists:all(fun(C)->C>=$0 andalso C=<$9 orelse C>=$a andalso C=<$f end,binary_to_list(B));
digest(_)->false.
hash(B)->binary:encode_hex(crypto:hash(sha256,B),lowercase).
trim(B)->string:trim(B).
nonempty(B)->V=trim(B),true=byte_size(V)>0,V.
