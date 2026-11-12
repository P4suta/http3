%% Closed, bounded authored-fixture validation. This does not certify execution.
-include("url_pattern_profile_policy.hrl").

upp_valid(Profile, Reference, Cases) ->
    try
        Policy=upp_policy(),
        true=is_map(Profile) andalso is_map(Reference) andalso is_map(Cases),
        true=maps:remove(<<"requirements">>,Profile)=:=maps:get(<<"profile">>,Policy),
        true=maps:remove(<<"cases">>,Reference)=:=maps:get(<<"reference">>,Policy),
        true=lists:sort(maps:keys(Cases))=:=[<<"cases">>,<<"schema">>],
        1=maps:get(<<"schema">>,Cases),
        Matrix=maps:get(<<"cases">>,Cases),
        true=is_list(Matrix) andalso length(Matrix)=:=maps:get(<<"case_count">>,Profile),
        true=length(Matrix)>0 andalso length(Matrix)=<1000,
        Ids=[maps:get(<<"id">>,Row)||Row<-Matrix],
        true=length(Ids)=:=length(lists:usort(Ids)),
        true=lists:all(fun upp_identifier/1,Ids),
        Rows=maps:get(<<"requirements">>,Profile),
        true=is_list(Rows) andalso length(Rows)=:=23,
        true=[maps:remove(<<"checks">>,R)||R<-Rows]=:=maps:get(<<"requirements">>,Policy),
        lists:foreach(fun(R)->
            Id=maps:get(<<"id">>,R),
            Required=[maps:get(<<"id">>,C)||C<-Matrix,lists:member(Id,maps:get(<<"requirements">>,C))],
            true=maps:get(<<"checks">>,R)=:=Required,
            case maps:get(<<"coverage">>,R) of
                <<"matrix">>->
                    true=Required=/=[],
                    lists:foreach(fun(S)->
                        true=lists:any(fun(C)->lists:member(Id,maps:get(<<"requirements">>,C)) andalso
                                                lists:member(S,maps:get(<<"steps">>,C)) end,Matrix)
                    end,maps:get(<<"steps">>,R));
                _->true=Required=:=[]
            end
        end,Rows),
        AllSteps=lists:usort(lists:append([maps:get(<<"steps">>,R)||R<-Rows])),
        AllRequirements=[maps:get(<<"id">>,R)||R<-Rows],
        lists:foreach(fun(C)->
            true=lists:all(fun(X)->lists:member(X,AllRequirements) end,maps:get(<<"requirements">>,C)),
            true=lists:all(fun(X)->lists:member(X,AllSteps) end,maps:get(<<"steps">>,C))
        end,Matrix),
        true=upp_digest(Cases)=:=maps:get(<<"matrix_sha256">>,Policy),
        Full=maps:get(<<"cases">>,Reference),
        true=is_list(Full) andalso length(Full)=:=517,
        true=[maps:get(<<"id">>,R)||R<-Full]=:=lists:seq(0,516),
        true=upp_digest(Full)=:=maps:get(<<"reference_cases_sha256">>,Policy),
        true
    catch _:_ -> false end.

upp_inputs() ->
    try
        P=upp_read("test/fixtures/urlpattern-profile.json"),
        F=upp_read("test/fixtures/urlpattern-full-independent.json"),
        C=upp_read("test/fixtures/urlpattern-profile-cases.json"),
        true=upp_valid(P,F,C),
        maps:foreach(fun(Path,Hash)->
            true=upp_file_digest(binary_to_list(Path))=:=Hash
        end,maps:get(<<"source_hashes">>,P)),
        true=upp_file_digest("scripts/urlpattern_full_reference.py")=:=maps:get(<<"generator_sha256">>,F),
        {ok,{P,F,C}}
    catch _:_ -> {error,invalid_urlpattern_profile} end.

upp_read(Path) ->
    {ok,F}=file:open(Path,[read,binary,raw]),
    try
        {ok,B}=file:read(F,1048577),true=byte_size(B)=<1048576,
        eof=file:read(F,1),upp_json_decode(B)
    after file:close(F) end.

upp_file_digest(Path) ->
    {ok,F}=file:open(Path,[read,binary,raw]),
    try
        {ok,B}=file:read(F,2097153),true=byte_size(B)=<2097152,
        eof=file:read(F,1),string:lowercase(binary:encode_hex(crypto:hash(sha256,B)))
    after file:close(F) end.

upp_identifier(B) when is_binary(B),byte_size(B)>0,byte_size(B)=<100 ->
    lists:all(fun(C)->(C>=$a andalso C=<$z) orelse
                      (C>=$0 andalso C=<$9) orelse lists:member(C,"-?+*") end,binary_to_list(B));
upp_identifier(_)->false.
upp_digest(V)->string:lowercase(binary:encode_hex(crypto:hash(sha256,upp_canonical(V)))).
upp_canonical(M) when is_map(M)->[${,lists:join($,,[[json:encode(K),$:,upp_canonical(maps:get(K,M))]||K<-lists:sort(maps:keys(M))]),$}];
upp_canonical(L) when is_list(L)->[$[,lists:join($,,[upp_canonical(V)||V<-L]),$]];
upp_canonical(V)->json:encode(V).

upp_json_decode(Bytes) when is_binary(Bytes),byte_size(Bytes)=<1048576 ->
    try
        Object=fun(Acc)->upp_json_start(Acc,#{}) end,
        Array=fun(Acc)->upp_json_start(Acc,[]) end,
        PushObject=fun(K,V,{D,N,M})->false=maps:is_key(K,M),true=N<100000,{D,N+1,M#{K=>V}} end,
        PushArray=fun(V,{D,N,L})->true=N<100000,{D,N+1,[V|L]} end,
        FinishObject=fun({_,N,M},{D,_,O})->{M,{D,N,O}} end,
        FinishArray=fun({_,N,L},{D,_,O})->{lists:reverse(L),{D,N,O}} end,
        {V,{0,_,none},Rest}=json:decode(Bytes,{0,0,none},
            #{object_start=>Object,array_start=>Array,object_push=>PushObject,array_push=>PushArray,
              object_finish=>FinishObject,array_finish=>FinishArray}),
        true=lists:all(fun(C)->lists:member(C,[32,9,10,13]) end,binary_to_list(Rest)),V
    catch _:_ ->erlang:error(invalid_urlpattern_profile_json) end;
upp_json_decode(_)->erlang:error(invalid_urlpattern_profile_json).
upp_json_start({D,N,_},C)->true=D<32 andalso N<100000,{D+1,N+1,C}.
