import sys

import pytest

from app.core.config import Settings
from app.security import dpapi
from app.security.keys import jwt_secret, master_key


def test_keys_are_stable_and_never_in_clear_on_windows(tmp_path):
    s = Settings(data_dir=tmp_path)
    k1, j1 = master_key(s), jwt_secret(s)
    assert master_key(s) == k1 and jwt_secret(s) == j1
    if sys.platform == "win32":
        assert (tmp_path / "master.key.dpapi").exists() and not (tmp_path / "master.key").exists()
        assert k1.encode() not in (tmp_path / "master.key.dpapi").read_bytes()
    else:
        assert (tmp_path / "master.key").stat().st_mode & 0o077 == 0


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI : Windows uniquement")
def test_dpapi_roundtrip_and_migration(tmp_path):
    assert dpapi.unprotect(dpapi.protect(b"secret")) == b"secret"
    (tmp_path / "master.key").write_text("legacy-clear-key")
    assert master_key(Settings(data_dir=tmp_path)) == "legacy-clear-key"
    assert not (tmp_path / "master.key").exists() and (tmp_path / "master.key.dpapi").exists()


def test_env_key_takes_precedence(tmp_path):
    assert master_key(Settings(data_dir=tmp_path, master_key="from-env")) == "from-env"
