"""Independent aioquic peer for the advanced transport phase gate."""

import asyncio
import os

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, DatagramReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.packet import QuicProtocolVersion


SESSION_TICKETS = {}
SERVER_RESPONSE_DELAY_SECONDS = 0.05
REQUIRED_OBSERVATIONS = {
    "OBSERVED_HTTP_DATAGRAM",
    "OBSERVED_POST_MIGRATION_REQUEST",
    "OBSERVED_0RTT_REQUEST",
    "OBSERVED_QUIC_V2",
}
OBSERVATIONS = set()
COMPLETION_EVENT = None


def observe(name):
    """Record a required wire observation and wake the bounded runner."""

    print(name, flush=True)
    OBSERVATIONS.add(name)
    if COMPLETION_EVENT is not None and REQUIRED_OBSERVATIONS <= OBSERVATIONS:
        COMPLETION_EVENT.set()


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
            if self._quic._version == QuicProtocolVersion.VERSION_2:
                observe("OBSERVED_QUIC_V2")
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                request = self.requests.setdefault(
                    http_event.stream_id,
                    {
                        "path": b"",
                        "ended": False,
                        "datagram": False,
                        "response_started": False,
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
                        "response_started": False,
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
                observe("OBSERVED_HTTP_DATAGRAM")
                self.maybe_respond(http_event.stream_id)

    def maybe_respond(self, stream_id):
        request = self.requests[stream_id]
        path = request["path"]
        if path == b"/advanced" and not request["response_started"]:
            self.http.send_headers(
                stream_id,
                [
                    (b":status", b"200"),
                    (b"content-type", b"application/octet-stream"),
                    (b"x-interop-peer", b"aioquic-1.3.0"),
                ],
            )
            request["response_started"] = True
            self.transmit()
        if not request["ended"]:
            return
        if path == b"/advanced" and not request["datagram"]:
            return
        if path == b"/advanced":
            body = b"aioquic-advanced"
        elif path == b"/after-migration":
            body = b"aioquic-migrated"
            observe("OBSERVED_POST_MIGRATION_REQUEST")
        elif path == b"/ticket":
            body = b"aioquic-ticket"
        elif path == b"/early":
            body = b"aioquic-resumed"
            if request["early"]:
                observe("OBSERVED_0RTT_REQUEST")
        else:
            raise AssertionError(path)
        if not request["response_started"]:
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
    global COMPLETION_EVENT

    COMPLETION_EVENT = asyncio.Event()
    qlog_directory = os.environ.get("HTTP3_INTEROP_QLOG")
    idle_timeout = float(os.environ.get("HTTP3_INTEROP_IDLE_TIMEOUT", "60"))
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["h3"],
        idle_timeout=idle_timeout,
        max_datagram_frame_size=65535,
        quic_logger=QuicFileLogger(qlog_directory) if qlog_directory else None,
        supported_versions=[QuicProtocolVersion.VERSION_2],
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
    if os.environ.get("HTTP3_INTEROP_EXIT_ON_COMPLETE") == "1":
        await asyncio.wait_for(COMPLETION_EVENT.wait(), timeout=idle_timeout)
        await asyncio.sleep(0.25)
        protocols = set(server._protocols.values())
        server.close()
        await asyncio.wait_for(
            asyncio.gather(*(protocol.wait_closed() for protocol in protocols)),
            timeout=5,
        )
        proxy_transport.close()
    else:
        await asyncio.Event().wait()


try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
