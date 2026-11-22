"""
The live WebSocket: new items pushed to every open dashboard.
"""

from fastapi import WebSocket, WebSocketDisconnect

from omenwatch.api.dependencies import auth_router
from omenwatch.auth import sign_in
from omenwatch.database.sqlite import get_db

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


@auth_router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    if not sign_in.open_dashboard():
        db = await get_db()
        try:
            session = await sign_in.validate(db, websocket.cookies.get(sign_in.COOKIE_NAME))
        finally:
            await db.close()
        if not session:
            await websocket.close(code=4401)  # the page shows the sign-in screen on this code
            return
    active_ws.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in active_ws:
            active_ws.remove(websocket)
