"""Live checks against real keyless sources. Run with: MAKKADI_LIVE_TESTS=1 pytest -m live"""

import asyncio
import os

import pytest

from app.connectors.osint.base import ProviderContext
from app.connectors.osint.internetdb import InternetDbProvider
from app.connectors.osint.rdap import RdapProvider
from app.connectors.osint.ripestat import RipeStatProvider

pytestmark = [pytest.mark.live, pytest.mark.skipif(os.environ.get("MAKKADI_LIVE_TESTS") != "1", reason="tests réseau désactivés")]
IP = "154.73.112.25"


@pytest.fixture(autouse=True)
def _real_network():
    from app.connectors.http import set_transport
    from app.security.ssrf import set_resolver

    set_transport(None)
    set_resolver(None)


@pytest.mark.parametrize("cls", [RdapProvider, RipeStatProvider, InternetDbProvider])
def test_live_provider_answers(cls):
    r = asyncio.run(cls(ProviderContext({}, {})).lookup("ipv4", IP))
    assert r.status in ("ok", "no_data"), r.error_message
    assert not r.is_synthetic and r.queried_at
