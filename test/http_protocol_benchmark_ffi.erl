-module(http_protocol_benchmark_ffi).
-export([counter/0,record/2,counts/1,payload/1,valid_payload/1,now/0,finally/2]).

counter() -> atomics:new(3,[{signed,false}]).
record(Counter,Phase) when is_integer(Phase),Phase>=0,Phase=<32 ->
    Index=case Phase of 0->1;_->2 end,
    case Phase of 0->ok;_->atomics:compare_exchange(Counter,3,0,Phase) end,
    increment(Counter,Index,32),nil.
increment(_,_,0) -> erlang:error(benchmark_counter_contention);
increment(Counter,Index,Attempts) ->
    Old=atomics:get(Counter,Index),
    case Old < 1000 of
        false->erlang:error(benchmark_counter_limit);
        true->case atomics:compare_exchange(Counter,Index,Old,Old+1) of
            ok->ok;_->increment(Counter,Index,Attempts-1)
        end
    end.
counts(Counter)->{atomics:get(Counter,1),atomics:get(Counter,2),atomics:get(Counter,3)}.
payload(Bytes) when is_integer(Bytes), Bytes>=0,Bytes=<1048576 -> binary:copy(<<90>>,Bytes).
valid_payload(Bytes) when is_binary(Bytes), byte_size(Bytes)=<8192 ->
    Bytes =:= binary:copy(<<90>>,byte_size(Bytes));
valid_payload(_)->false.
now()->erlang:monotonic_time(microsecond).
finally(Work,Cleanup)->
    %% Each callback is invoked exactly once. Project exception values before
    %% they can reach a report; retain the original failure if cleanup fails too.
    Outcome=try Work() of
        {ok,_}=Success->Success;
        {error,_}=Failure->Failure;
        _->{error,{invalid,22}}
    catch _:_ ->{error,{invalid,20}} end,
    Released=try Cleanup() of
        {ok,nil}->ok;
        {error,Cause}->{error,Cause};
        _->{error,{invalid,23}}
    catch _:_ ->{error,{invalid,21}} end,
    case {Outcome,Released} of
        {_,ok}->Outcome;
        {{ok,_},{error,CleanupCause}}->{error,{cleanup_failed,none,CleanupCause}};
        {{error,Primary},{error,CleanupCause}}->
            {error,{cleanup_failed,{some,Primary},CleanupCause}}
    end.
