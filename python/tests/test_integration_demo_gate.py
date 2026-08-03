"""
Tests for the fail-closed gate on the insecure demo FastAPI routers.

`shield.integrations.fido2_api` and `shield.integrations.pgvector_api` are
demonstration scaffolding that perform NO real WebAuthn / token / vector
verification (see RT2-1, RT2-2, RT2-3). They must refuse to instantiate unless
the developer explicitly opts into an insecure demo, so that a developer wiring
them per the README cannot accidentally deploy an authentication bypass.
"""

import pytest

pytest.importorskip("fastapi")


# --- FIDO2 demo router ---------------------------------------------------


def test_fido2_router_refuses_without_demo_flag():
    from shield.integrations.fido2_api import Fido2Router

    with pytest.raises(RuntimeError, match="(?i)insecure|demo"):
        Fido2Router(password="pw", service="svc")


def test_fido2_router_constructs_with_demo_flag_and_warns():
    from shield.integrations.fido2_api import Fido2Router

    with pytest.warns(UserWarning, match="(?i)insecure|demo|not.*production"):
        router = Fido2Router(password="pw", service="svc", allow_insecure_demo=True)
    assert router.router is not None


def test_create_fido2_app_refuses_without_demo_flag():
    from shield.integrations.fido2_api import create_fido2_app

    with pytest.raises(RuntimeError, match="(?i)insecure|demo"):
        create_fido2_app(password="pw", service="svc")


def test_create_fido2_app_constructs_with_demo_flag():
    from shield.integrations.fido2_api import create_fido2_app

    with pytest.warns(UserWarning):
        router = create_fido2_app(password="pw", service="svc", allow_insecure_demo=True)
    assert router is not None


# --- pgvector demo router ------------------------------------------------


def test_pgvector_router_refuses_without_demo_flag():
    from shield.integrations.pgvector_api import PgVectorRouter

    with pytest.raises(RuntimeError, match="(?i)insecure|demo"):
        PgVectorRouter(shield=object(), dimension=8)


def test_pgvector_router_constructs_with_demo_flag_and_warns():
    from shield.integrations.pgvector_api import PgVectorRouter

    with pytest.warns(UserWarning, match="(?i)insecure|demo|not.*production"):
        router = PgVectorRouter(shield=object(), dimension=8, allow_insecure_demo=True)
    assert router.router is not None


def test_create_pgvector_app_refuses_without_demo_flag():
    from shield.integrations.pgvector_api import create_pgvector_app

    with pytest.raises(RuntimeError, match="(?i)insecure|demo"):
        create_pgvector_app(shield=object(), dimension=8)
