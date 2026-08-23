-module(http3_internal_transport_ffi).

-export([client_connection/1, client_stream/1, server_stream/1, ticket_handle/1]).

-spec client_connection(term()) -> tuple().
client_connection(Handle) ->
    {connection, Handle}.

-spec client_stream(term()) -> tuple().
client_stream(Handle) ->
    {client_stream, Handle}.

-spec server_stream(term()) -> tuple().
server_stream(Handle) ->
    {server_stream, Handle}.

-spec ticket_handle(tuple()) -> term().
ticket_handle({resumption_ticket, Handle}) ->
    Handle.
