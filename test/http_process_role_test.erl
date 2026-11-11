%% SPDX-FileCopyrightText: 2026 the http contributors
%% SPDX-License-Identifier: MIT OR Apache-2.0
-module(http_process_role_test).
-export([http3_response_family_labelled/1]).
-include_lib("eunit/include/eunit.hrl").

http3_response_family_labelled(Producer) ->
    case process_info(Producer, links) of
        {links, Links} when length(Links) =< 8 ->
            proc_lib:get_label(Producer) =:= <<"http.http3_response_work">> andalso
            lists:any(fun(Supervisor) ->
                case is_pid(Supervisor) andalso process_info(Supervisor, links) of
                    {links, Children} when length(Children) =< 8 ->
                        proc_lib:get_label(Supervisor) =:= <<"http.http3_response_supervisor">> andalso
                        lists:any(fun(Child) -> is_pid(Child) andalso
                            proc_lib:get_label(Child) =:= <<"http.http3_response_terminal">>
                        end, Children);
                    _ -> false
                end
            end, Links);
        _ -> false
    end.

owner_handles_publish_only_after_fixed_role_is_visible_test() ->
    Lifecycle = http_client_ffi:new_lifecycle(2, 1, 1000),
    Pool = http_client_ffi:new_http2_pool(2, 1, 1000),
    Policy = http_client_ffi:new_policy_store(2, 1024),
    Handles = [Lifecycle, Pool, Policy],
    Owners = [maps:get(owner, Handle) || Handle <- Handles],
    Monitors = [monitor(process, Owner) || Owner <- Owners],
    Labels = [proc_lib:get_label(Owner) || Owner <- Owners],
    _ = http_client_ffi:close(Lifecycle),
    _ = http_client_ffi:close_http2_pool(Pool),
    _ = http_client_ffi:close_policy_store(Policy),
    Stopped = [receive {'DOWN', Ref, process, Owner, _} -> true
               after 1000 -> false end || {Owner, Ref} <- lists:zip(Owners, Monitors)],
    ?assertEqual([<<"http.client_lifecycle">>, <<"http.http2_pool">>,
                  <<"http.policy_store">>], Labels),
    ?assertEqual([true, true, true], Stopped).

body_cleanup_callback_has_a_fixed_role_before_user_code_test() ->
    Parent = self(), Ref = make_ref(),
    Handle = http_body_ffi:new_cancel_handle(),
    Outcome = http_body_ffi:cancel_once(Handle, {some, fun() ->
        Parent ! {Ref, proc_lib:get_label(self())}
    end}, none, 1000),
    Label = receive {Ref, Value} -> Value after 1000 -> missing end,
    ?assertEqual({ok, nil}, Outcome),
    ?assertEqual(<<"http.body_callback">>, Label).
