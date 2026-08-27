-module(gleam_quic_process_label_ffi).

-export([current/0, set_role/1]).

-spec set_role(1..8) -> nil.
set_role(1) -> set_label(<<"gleam_quic.client">>);
set_role(2) -> set_label(<<"gleam_quic.listener">>);
set_role(3) -> set_label(<<"gleam_quic.connect_candidate">>);
set_role(4) -> set_label(<<"gleam_quic.dns_resolver">>);
set_role(5) -> set_label(<<"gleam_quic.udp_relay">>);
set_role(6) -> set_label(<<"gleam_quic.replay_guard">>);
set_role(7) -> set_label(<<"gleam_quic.qlog_writer">>);
set_role(8) -> set_label(<<"gleam_quic.connection">>).

-spec current() -> binary().
current() ->
    case erlang:get('$process_label') of
        Label when is_binary(Label) -> Label;
        _Unset -> <<>>
    end.

set_label(Label) ->
    ok = proc_lib:set_label(Label),
    nil.
