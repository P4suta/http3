%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-ifndef(HTTP_PERFORMANCE_FAILURE_HRL).
-define(HTTP_PERFORMANCE_FAILURE_HRL, true).
%% The benchmark may attach responses, sockets or exception values to a
%% failure. Only recognized operation codes and checked scalar counts survive.
performance_failure({http3_benchmark_failed, {<<"runtime resources did not converge">>, Before, After}}) ->
    #{phase => 3, results => [], counters => performance_resource_counts([Before, After])};
performance_failure({benchmark_cleanup_resource_limit, Counts}) when is_map(Counts) ->
    Values = [maps:get(K, Counts, invalid) || K <- [maximum_processes, observed_processes,
        maximum_ports, observed_ports, maximum_network_ports, observed_network_ports,
        maximum_sockets, observed_sockets]],
    #{phase => 3, results => [], counters => performance_scalar_counts(Values)};
performance_failure({http3_benchmark_failed, {<<"primed network baseline retained sockets">>, Ports, Sockets}}) ->
    #{phase => 2, results => [], counters => performance_scalar_counts([Ports, Sockets])};
performance_failure({benchmark_priming_cleanup_limit, Counts}) when is_list(Counts),length(Counts)=:=3 ->
    #{phase => 2, results => [], counters => performance_scalar_counts(Counts)};
performance_failure({http3_benchmark_failed, {<<"workload cleanup">>, Server, Clients, Stop}}) ->
    #{phase => 4, results => [performance_result_code(Server), performance_result_code(Clients), performance_result_code(Stop)], counters => []};
performance_failure({http3_benchmark_failed, {Operation, Result}}) ->
    #{phase => performance_operation(Operation), results => [performance_result_code({error, Result})], counters => []};
performance_failure(benchmark_worker_timeout) -> #{phase => 5, results => [1], counters => []};
performance_failure({benchmark_worker_stopped, _}) -> #{phase => 6, results => [99], counters => []};
performance_failure(undef) -> #{phase => 7, results => [], counters => []};
performance_failure(_) -> #{phase => 0, results => [], counters => []}.
performance_operation(<<"start priming listener">>) -> 10;
performance_operation(<<"read priming listener port">>) -> 11;
performance_operation(<<"stop priming listener">>) -> 12;
performance_operation(<<"close priming connection">>) -> 13;
performance_operation(<<"start listener">>) -> 14;
performance_operation(<<"read listener port">>) -> 15;
performance_operation(<<"prime client runtime">>) -> 16;
performance_operation(_) -> 0.
performance_result_code({ok, _}) -> 0;
performance_result_code({error, timeout}) -> 1;
performance_result_code({error, {timeout, _}}) -> 1;
performance_result_code({error, closed}) -> 2;
performance_result_code({error, connection_closed}) -> 2;
performance_result_code({error, stream_finished}) -> 3;
performance_result_code({error, response_already_finished}) -> 4;
performance_result_code({error, {peer_closed, _}}) -> 5;
performance_result_code({error, {peer_reset, _}}) -> 6;
performance_result_code({error, {resource_limit_exceeded, _}}) -> 7;
performance_result_code({error, invalid_input}) -> 8;
performance_result_code({error, client_completion_latch_failed}) -> 9;
performance_result_code(_) -> 99.
performance_resource_counts([A, B]) when is_tuple(A), tuple_size(A) =:= 4,
                                        is_tuple(B), tuple_size(B) =:= 4 ->
    performance_scalar_counts(tuple_to_list(A) ++ tuple_to_list(B));
performance_resource_counts(_) -> [].
performance_scalar_counts(Values) ->
    case lists:all(fun(V) -> is_integer(V) andalso V >= 0 andalso V =< 9223372036854775807 end, Values) of
        true -> Values;
        false -> []
    end.
performance_stack_lines(Stack) ->
    [case [diagnostic_line(proplists:get_value(line, lists:sublist(Info, 16), 0))
           || {M, F, A, Info} <- lists:sublist(Stack, 16), M =:= Module,
              is_atom(F), is_integer(A), is_list(Info), diagnostic_known_function(M, F, A)] of
        [Line | _] -> Line;
        [] -> 0
    end || Module <- [http3_benchmark, http3_benchmark_ffi]].
-endif.
