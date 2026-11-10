"""In-process sliding-window rate limiter (per client IP, /api/* routes).

Single-process MVP limit; Redis-backed distributed limiting is a later upgrade.
The proxy-header trust flag defaults to False so a caller cannot spoof
X-Forwarded-For to rotate buckets unless TrustLens is explicitly deployed
behind a trusted reverse proxy.
"""
from __future__ import annotations

import asyncio
import math
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit_per_minute: int, trust_proxy: bool = False):
        super().__init__(app)
        self._limit = max(1, limit_per_minute)
        self._window_seconds = 60.0
        self._trust_proxy = trust_proxy
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()
        # Audit L6: buckets of idle clients were never removed, so the dict
        # grew without bound on deployments seeing many unique IPs. A sweep
        # (at most once per window) drops buckets with no recent hits.
        self._last_sweep = time.monotonic()

    def _client_ip(self, request: Request) -> str:
        if self._trust_proxy:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                # RIGHTMOST entry, not leftmost: a trusted proxy APPENDS the
                # real client address, so the leftmost entry is whatever the
                # client itself supplied — keying on it would let clients
                # rotate buckets per request and void the limit exactly in
                # the proxy deployment mode (audit M-E).
                return forwarded.split(",")[-1].strip()
        return request.client.host if request.client else "unknown"

    def _evict_idle(self, now: float) -> None:
        """Drop buckets whose newest hit is older than the window (idle clients).

        Must be called while holding self._lock. Safe: removing a bucket only
        means the next request from that IP starts a fresh one."""
        cutoff = now - self._window_seconds
        for key in [k for k, bucket in self._hits.items() if not bucket or bucket[-1] < cutoff]:
            del self._hits[key]

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        key = self._client_ip(request)
        now = time.monotonic()
        async with self._lock:
            if now - self._last_sweep >= self._window_seconds:
                self._evict_idle(now)
                self._last_sweep = now
            bucket = self._hits[key]
            cutoff = now - self._window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self._limit:
                retry_after = max(1, math.ceil(bucket[0] + self._window_seconds - now))
                return JSONResponse(
                    status_code=429,
                    content={"error": {"code": "rate_limited",
                                       "message": f"Rate limit of {self._limit} requests/minute exceeded for /api routes."}},
                    headers={"Retry-After": str(retry_after)},
                )
            bucket.append(now)
        return await call_next(request)
