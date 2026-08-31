from __future__ import annotations
import asyncio
import logging

import websockets

logger = logging.getLogger(__name__)

dashboard_clients: set[websockets.WebSocketServerProtocol] = set()


async def dashboard_handler(ws: websockets.WebSocketServerProtocol):
    dashboard_clients.add(ws)
    logger.info("Dashboard client connected (%d total).", len(dashboard_clients))
    try:
        async for _ in ws:
            pass
    except websockets.ConnectionClosed:
        pass
    finally:
        dashboard_clients.discard(ws)
        logger.info("Dashboard client disconnected (%d total).", len(dashboard_clients))


async def broadcast(message: str):
    if not dashboard_clients:
        return
    await asyncio.gather(
        *(client.send(message) for client in dashboard_clients.copy()),
        return_exceptions=True,
    )
