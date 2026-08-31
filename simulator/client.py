from __future__ import annotations
import ssl
import json
import time
import asyncio
import logging

import websockets

from .signal_generator import SignalGenerator, FileSignalGenerator
from .command_generator import CommandGenerator

logger = logging.getLogger(__name__)


async def run_client(
    device_id: str,
    host: str,
    port: int,
    sampling_rate: int = 250,
    cert: str | None = None,
    key: str | None = None,
    ca_cert: str | None = None,
    no_tls: bool = False,
    eeg_file: str | None = None,
):
    if eeg_file:
        sig_gen = FileSignalGenerator(eeg_file, sampling_rate=sampling_rate)
        logger.info("Streaming recorded EEG from %s", eeg_file)
    else:
        sig_gen = SignalGenerator(sampling_rate=sampling_rate)
    cmd_gen = CommandGenerator()
    seq = 0
    interval = 1.0 / sampling_rate

    scheme = "ws" if no_tls else "wss"
    uri = f"{scheme}://{host}:{port}"

    ssl_ctx = None
    if not no_tls:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if ca_cert:
            ssl_ctx.load_verify_locations(ca_cert)
        if cert and key:
            ssl_ctx.load_cert_chain(certfile=cert, keyfile=key)

    logger.info("Connecting to %s as %s ...", uri, device_id)

    async with websockets.connect(uri, ssl=ssl_ctx) as ws:
        logger.info("Connected.")
        loop = asyncio.get_event_loop()
        next_send = time.perf_counter()
        try:
            while True:
                packet = {
                    "device_id": device_id,
                    "timestamp": int(time.time() * 1000),
                    "seq": seq,
                    "channels": sig_gen.next_sample(),
                    "command": cmd_gen.current_command(),
                }
                await ws.send(json.dumps(packet))
                seq += 1

                next_send += interval
                delay = next_send - time.perf_counter()
                if delay > 0:
                    await loop.run_in_executor(None, time.sleep, delay)
        except websockets.ConnectionClosed:
            logger.info("Connection closed.")
        except KeyboardInterrupt:
            logger.info("Interrupted.")
