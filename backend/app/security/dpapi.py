"""Windows DPAPI (CryptProtectData) via ctypes — binds key material to the Windows user account.

Only available on Windows; other platforms keep 0600-permission key files.
"""

from __future__ import annotations

import ctypes
import sys

ENTROPY = b"MAKKADi-key-material-v1"
_CRYPTPROTECT_UI_FORBIDDEN = 0x01


def available() -> bool:
    return sys.platform == "win32"


if available():  # pragma: no cover - exercised on the Windows CI runner
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def _blob(data: bytes) -> tuple[_Blob, ctypes.Array]:
        buf = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _call(fn, data: bytes) -> bytes:  # noqa: ANN001
        src, _keep = _blob(data)
        ent, _keep2 = _blob(ENTROPY)
        out = _Blob()
        if not fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
            raise OSError(ctypes.get_last_error(), "Échec DPAPI")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)

    def protect(data: bytes) -> bytes:
        return _call(lambda s, d, e, r, p, f, o: _crypt32.CryptProtectData(s, "MAKKADi", e, r, p, f, o), data)

    def unprotect(data: bytes) -> bytes:
        return _call(lambda s, d, e, r, p, f, o: _crypt32.CryptUnprotectData(s, None, e, r, p, f, o), data)

else:

    def protect(data: bytes) -> bytes:
        raise OSError("DPAPI indisponible hors Windows")

    def unprotect(data: bytes) -> bytes:
        raise OSError("DPAPI indisponible hors Windows")
