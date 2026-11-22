"""
HTTP security that applies to every response.
"""
from fastapi import FastAPI, Request

# On every response. Other sites can't frame the dashboard (clickjacking
# the Settings buttons), browsers never guess a type other than the one
# sent, and links out to articles don't tell publishers this server's
# address.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Content-Security-Policy": "frame-ancestors 'self'; object-src 'none'; base-uri 'self'",
    "Referrer-Policy": "same-origin",
}


def add_security_headers(app: FastAPI) -> None:
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response
