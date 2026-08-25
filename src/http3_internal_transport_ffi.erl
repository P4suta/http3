-module(http3_internal_transport_ffi).

-export([client_connection/1, client_stream/1, server_stream/1, ticket_handle/1]).

-type connection_handle() :: {connection, term()}.
-type client_stream_handle() :: {client_stream, term()}.
-type server_stream_handle() :: {server_stream, term()}.
-type ticket() :: {resumption_ticket, term()}.

-spec client_connection(term()) -> connection_handle().
client_connection(Handle) ->
    {connection, Handle}.

-spec client_stream(term()) -> client_stream_handle().
client_stream(Handle) ->
    {client_stream, Handle}.

-spec server_stream(term()) -> server_stream_handle().
server_stream(Handle) ->
    {server_stream, Handle}.

-spec ticket_handle(ticket()) -> term().
ticket_handle({resumption_ticket, Handle}) ->
    Handle.
