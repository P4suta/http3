"""Independent aioquic peer for the advanced transport phase gate."""

import asyncio

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, DatagramReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted


SESSION_TICKETS = {}
SERVER_RESPONSE_DELAY_SECONDS = 0.05


class DelayedServerResponseProxy(asyncio.DatagramProtocol):
    """Keep one stable origin while delaying server handshake packets."""

    def __init__(self, server_address):
        self.server_address = server_address
        self.transport = None
        self.client_address = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if address == self.server_address:
            if self.client_address is None:
                return
            target = self.client_address
            asyncio.get_running_loop().call_later(
                SERVER_RESPONSE_DELAY_SECONDS,
                self.transport.sendto,
                data,
                target,
            )
        else:
            self.client_address = address
            self.transport.sendto(data, self.server_address)


class AdvancedProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic, enable_webtransport=True)
        self.requests = {}
        self.handshake_completed = False

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake_completed = True
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                request = self.requests.setdefault(
                    http_event.stream_id,
                    {
                        "path": b"",
                        "ended": False,
                        "datagram": False,
                        "early": not self.handshake_completed,
                    },
                )
                request["path"] = dict(http_event.headers).get(b":path", b"")
                request["ended"] = http_event.stream_ended
                self.maybe_respond(http_event.stream_id)
            elif isinstance(http_event, DataReceived):
                request = self.requests.setdefault(
                    http_event.stream_id,
                    {
                        "path": b"",
                        "ended": False,
                        "datagram": False,
                        "early": not self.handshake_completed,
                    },
                )
                request["ended"] = http_event.stream_ended
                self.maybe_respond(http_event.stream_id)
            elif isinstance(http_event, DatagramReceived):
                assert http_event.data == b"gleam-ping", http_event.data
                request = self.requests[http_event.stream_id]
                request["datagram"] = True
                self.http.send_datagram(http_event.stream_id, b"aioquic-pong")
                self.transmit()
                print("OBSERVED_HTTP_DATAGRAM", flush=True)
                self.maybe_respond(http_event.stream_id)

    def maybe_respond(self, stream_id):
        request = self.requests[stream_id]
        path = request["path"]
        if not request["ended"]:
            return
        if path == b"/advanced" and not request["datagram"]:
            return
        if path == b"/advanced":
            body = b"aioquic-advanced"
        elif path == b"/after-migration":
            body = b"aioquic-migrated"
            print("OBSERVED_POST_MIGRATION_REQUEST", flush=True)
        elif path == b"/ticket":
            body = b"aioquic-ticket"
        elif path == b"/early":
            body = b"aioquic-resumed"
            if request["early"]:
                print("OBSERVED_0RTT_REQUEST", flush=True)
        else:
            raise AssertionError(path)
        self.http.send_headers(
            stream_id,
            [
                (b":status", b"200"),
                (b"content-type", b"application/octet-stream"),
                (b"x-interop-peer", b"aioquic-1.3.0"),
            ],
        )
        self.http.send_data(stream_id, body, end_stream=True)
        self.transmit()
        del self.requests[stream_id]


async def main():
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["h3"],
        max_datagram_frame_size=65535,
    )
    configuration.load_cert_chain(
        "test/fixtures/server.pem",
        "test/fixtures/server-key.pem",
    )
    server = await serve(
        "127.0.0.1",
        0,
        configuration=configuration,
        create_protocol=AdvancedProtocol,
        session_ticket_fetcher=lambda label: SESSION_TICKETS.get(label),
        session_ticket_handler=lambda ticket: SESSION_TICKETS.__setitem__(
            ticket.ticket, ticket
        ),
    )
    port = server._transport.get_extra_info("sockname")[1]
    proxy_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: DelayedServerResponseProxy(("127.0.0.1", port)),
        local_addr=("127.0.0.1", 0),
    )
    resumption_port = proxy_transport.get_extra_info("sockname")[1]
    print(f"PORT={port}", flush=True)
    print(f"RESUMPTION_PORT={resumption_port}", flush=True)
    await asyncio.Event().wait()


try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
