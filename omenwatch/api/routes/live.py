"""
The live WebSocket endpoint. Who is connected, and broadcasting to them, is
in core/live.py.
"""

from fastapi import WebSocket, WebSocketDisconnect

from omenwatch.api.dependencies import auth_router
from omenwatch.auth import sign_in
from omenwatch.core.live import active_ws
from omenwatch.database.sqlite import get_db


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
