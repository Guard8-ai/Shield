"""
RT2-7: the FastAPI encryption middleware must not copy the original (pre-
encryption) Content-Length onto the larger encrypted response body. A stale
Content-Length truncates/desyncs the response and can be a smuggling primitive.
"""

import asyncio
import json
import types

import pytest

pytest.importorskip("fastapi")

from starlette.datastructures import Headers  # noqa: E402

from shield.integrations.fastapi import ShieldMiddleware  # noqa: E402


def _make_response(body: bytes):
    async def gen():
        yield body

    resp = types.SimpleNamespace()
    resp.status_code = 200
    # A deliberately WRONG content-length copied from the plaintext response.
    resp.headers = Headers(
        {"content-type": "application/json", "content-length": "999999"}
    )
    resp.body_iterator = gen()
    return resp


def test_encrypted_response_has_correct_content_length():
    middleware = ShieldMiddleware(
        app=lambda scope, receive, send: None,
        password="a-high-entropy-test-password",
        service="fastapi.test",
    )

    plaintext = json.dumps({"secret": "value"}).encode()

    async def call_next(_request):
        return _make_response(plaintext)

    request = types.SimpleNamespace(url=types.SimpleNamespace(path="/api/data"))
    result = asyncio.run(middleware.dispatch(request, call_next))

    advertised = result.headers["content-length"]
    assert advertised != "999999", "stale Content-Length must not be propagated"
    assert advertised == str(len(result.body)), "Content-Length must match the encrypted body"
