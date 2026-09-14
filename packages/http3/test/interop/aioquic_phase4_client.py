"""Independent aioquic client for the native HTTP/3 server phase gate."""

import argparse
import asyncio
import os

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicFileLogger


class HttpClientProtocol(QuicConnectionProtocol):
    """Send one bounded request and collect its bounded response."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.responses = {}

    async def request(self, port):
        stream_id = self._quic.get_next_available_stream_id()
        completion = asyncio.get_running_loop().create_future()
        self.responses[stream_id] = {
            "headers": None,
            "body": bytearray(),
            "completion": completion,
        }
        body = b"aioquic-request"
        self.http.send_headers(
            stream_id,
            [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", f"localhost:{port}".encode()),
                (b":path", b"/aioquic"),
                (b"content-length", str(len(body)).encode()),
            ],
        )
        self.http.send_data(stream_id, body, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(completion, timeout=10)

    def quic_event_received(self, event):
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                response = self.responses[http_event.stream_id]
                response["headers"] = http_event.headers
                self._complete_if_finished(response, http_event.stream_ended)
            elif isinstance(http_event, DataReceived):
                response = self.responses[http_event.stream_id]
                response["body"].extend(http_event.data)
                if len(response["body"]) > 1024:
                    response["completion"].set_exception(
                        AssertionError("response body exceeded 1024 bytes")
                    )
                else:
                    self._complete_if_finished(response, http_event.stream_ended)

    @staticmethod
    def _complete_if_finished(response, stream_ended):
        completion = response["completion"]
        if stream_ended and not completion.done():
            completion.set_result(
                (response["headers"], bytes(response["body"]))
            )


async def run(port):
    qlog_directory = os.environ.get("HTTP3_INTEROP_QLOG")
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
        cafile="test/fixtures/ca.pem",
        server_name="localhost",
        idle_timeout=10,
        quic_logger=QuicFileLogger(qlog_directory) if qlog_directory else None,
    )
    async with connect(
        "127.0.0.1",
        port,
        configuration=configuration,
        create_protocol=HttpClientProtocol,
    ) as protocol:
        headers, body = await protocol.request(port)

    header_map = dict(headers)
    assert header_map[b":status"] == b"202", headers
    assert header_map[b"x-interop-peer"] == b"gleam-native", headers
    assert body == b"native-aioquic-response", body
    print("aioquic client to native server interop ok", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    arguments = parser.parse_args()
    if not 1 <= arguments.port <= 65535:
        parser.error("port must be from 1 through 65535")
    asyncio.run(run(arguments.port))


if __name__ == "__main__":
    main()
