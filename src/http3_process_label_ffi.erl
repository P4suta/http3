-module(http3_process_label_ffi).

-export([current/0, set_role/1]).

-spec set_role(1..3) -> nil.
set_role(1) -> set_label(<<"http3.client">>);
set_role(2) -> set_label(<<"http3.listener">>);
set_role(3) -> set_label(<<"http3.connect_candidate">>).

-spec current() -> binary().
current() ->
    case erlang:get('$process_label') of
        Label when is_binary(Label) -> Label;
        _Unset -> <<>>
    end.

set_label(Label) ->
    ok = proc_lib:set_label(Label),
    nil.
