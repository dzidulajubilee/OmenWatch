"""
The live channel: every open dashboard's WebSocket, and broadcast() to
push a message to all of them (new items, sources changed). The socket
endpoint is in api/routes/live.py; the news worker and the source routes
broadcast through here.
"""
from fastapi import WebSocket

active_ws: list[WebSocket] = []


async def broadcast(message: dict):
    dead = []
    for ws in active_ws:
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(ws)
    for d in dead:
        if d in active_ws:
            active_ws.remove(d)
