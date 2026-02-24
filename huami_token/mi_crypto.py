"""Xiaomi Mi Fitness API encryption/decryption.

Encryption scheme: RC4-drop[1024]
Key derivation:    SHA256(base64Decode(ssecurity) || base64Decode(nonce))
Signing:           SHA1 (for rc4_hash__) + HMAC-SHA256 (for non-encrypted mode)

Two request modes:
  - Encrypted (i42.c): RC4-encrypted params + SHA1 signature
  - Signed (i42.d): Cleartext params + HMAC-SHA256 signature

URL path for signing:
  The signing path is NOT the full URL path. CloudInterceptor.subpath() strips
  the service's pathPrefix from the URL before signing.

  Known pathPrefix values (from @Secret annotations on service interfaces):
    ""                       DeviceApiService, GlobalConfigService
    "healthapp/"             SettingItemService, PrivacyService, RegionService
    "app/v1/"                ScaleService
    "cgi-op/api/v1/miwear/"  SportsRecordApiService, BannerService, HabitService
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import secrets
import struct
import time


class RC4:
    """RC4 stream cipher."""

    def __init__(self, key: bytes) -> None:
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) & 0xFF
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def crypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for idx, b in enumerate(data):
            self.i = (self.i + 1) & 0xFF
            self.j = (self.j + self.S[self.i]) & 0xFF
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            out[idx] = b ^ self.S[(self.S[self.i] + self.S[self.j]) & 0xFF]
        return bytes(out)


def _make_rc4(key_b64: str) -> RC4:
    """Create RC4 cipher from base64 key, dropping first 1024 bytes."""
    key_bytes = base64.b64decode(key_b64)
    rc4 = RC4(key_bytes)
    rc4.crypt(b"\x00" * 1024)
    return rc4


def derive_rc4_key(ssecurity_b64: str, nonce_b64: str) -> str:
    """Derive RC4 key: base64(SHA256(ssecurity_bytes || nonce_bytes))."""
    combined = base64.b64decode(ssecurity_b64) + base64.b64decode(nonce_b64)
    return base64.b64encode(hashlib.sha256(combined).digest()).decode()


def generate_nonce(time_diff_ms: int = 0) -> str:
    """Generate nonce: base64(random_8_bytes || int32_be((now_ms + timeDiff) / 60000))."""
    random_part = secrets.token_bytes(8)
    time_minutes = int((int(time.time() * 1000) + time_diff_ms) / 60000)
    time_part = struct.pack(">i", time_minutes)
    return base64.b64encode(random_part + time_part).decode()


def compute_signing_path(full_path: str, path_prefix: str = "") -> str:
    """Strip pathPrefix from full URL path (CloudInterceptor.subpath logic).

    If pathPrefix is empty: returns full_path unchanged.
    If pathPrefix is found in full_path: strips it and prepends "/" if needed.
    """
    if not path_prefix:
        idx = full_path.find("/")
        return full_path[idx:] if idx >= 0 else full_path

    idx = full_path.find(path_prefix)
    if idx < 0:
        return full_path

    result = full_path[idx + len(path_prefix) :]
    if not result.startswith("/"):
        result = "/" + result
    return result


def _sha1_sign(method: str, url_path: str, params: dict[str, str], rc4_key_b64: str) -> str:
    """SHA1 signing: base64(SHA1("METHOD&path&k1=v1&k2=v2&rc4_key"))."""
    parts: list[str] = []
    if method:
        parts.append(method.upper())
    if url_path:
        parts.append(url_path)
    if params:
        for k in sorted(params.keys()):
            parts.append(f"{k}={params[k]}")
    parts.append(rc4_key_b64)

    signing_string = "&".join(parts)
    digest = hashlib.sha1(signing_string.encode("utf-8")).digest()
    return base64.b64encode(digest).decode()


def _hmac_sign(message: str, rc4_key_b64: str) -> str:
    """HMAC-SHA256(rc4_key_bytes, message_bytes) -> base64."""
    key_bytes = base64.b64decode(rc4_key_b64)
    sig = hmac_mod.new(key_bytes, message.encode(), hashlib.sha256).digest()
    return base64.b64encode(sig).decode()


def mi_encrypt_params(
    method: str,
    signing_path: str,
    params: dict[str, str],
    nonce_b64: str,
    ssecurity_b64: str,
) -> dict[str, str]:
    """Encrypt request parameters (i42.c mode).

    Args:
        method:        HTTP method ("GET" or "POST")
        signing_path:  URL path after pathPrefix stripping (use compute_signing_path).
        params:        Dict of plaintext params (e.g. {"data": '{"key":"val"}'}).
        nonce_b64:     Base64-encoded nonce.
        ssecurity_b64: Base64-encoded ssecurity.

    Returns:
        Dict with encrypted params + signature + _nonce.
    """
    rc4_key_b64 = derive_rc4_key(ssecurity_b64, nonce_b64)

    plaintext_sorted = dict(sorted(params.items()))
    rc4_hash = _sha1_sign(method, signing_path, plaintext_sorted, rc4_key_b64)

    plaintext_sorted["rc4_hash__"] = rc4_hash
    plaintext_sorted = dict(sorted(plaintext_sorted.items()))

    rc4 = _make_rc4(rc4_key_b64)
    encrypted_sorted: dict[str, str] = {}
    for k in sorted(plaintext_sorted.keys()):
        encrypted_bytes = rc4.crypt(plaintext_sorted[k].encode("utf-8"))
        encrypted_sorted[k] = base64.b64encode(encrypted_bytes).decode()

    signature = _sha1_sign(method, signing_path, encrypted_sorted, rc4_key_b64)

    output = dict(encrypted_sorted)
    output["signature"] = signature
    output["_nonce"] = nonce_b64
    return output


def mi_sign_params(
    signing_path: str,
    params: dict[str, str],
    nonce_b64: str,
    ssecurity_b64: str,
) -> dict[str, str]:
    """Sign request parameters without encryption (i42.d mode).

    Uses HMAC-SHA256. Signing string: path&rc4_key&nonce&k1=v1&k2=v2
    """
    rc4_key_b64 = derive_rc4_key(ssecurity_b64, nonce_b64)

    parts: list[str] = []
    if signing_path:
        parts.append(signing_path)
    parts.append(rc4_key_b64)
    parts.append(nonce_b64)

    sorted_params = dict(sorted(params.items())) if params else {}
    if sorted_params:
        for k, v in sorted_params.items():
            parts.append(f"{k}={v}")
    else:
        parts.append("data=")

    message = "&".join(parts)
    signature = _hmac_sign(message, rc4_key_b64)

    output: dict[str, str] = {"signature": signature, "_nonce": nonce_b64}
    if params:
        output.update(params)
    return output


def mi_decrypt_response(body_b64: str, nonce_b64: str, ssecurity_b64: str) -> str:
    """Decrypt a base64-encoded RC4-encrypted response body."""
    rc4_key_b64 = derive_rc4_key(ssecurity_b64, nonce_b64)
    rc4 = _make_rc4(rc4_key_b64)
    return rc4.crypt(base64.b64decode(body_b64)).decode("utf-8")


def mi_decrypt_params(
    encrypted_params: dict[str, str], nonce_b64: str, ssecurity_b64: str
) -> dict[str, str]:
    """Decrypt RC4-encrypted request parameters."""
    rc4_key_b64 = derive_rc4_key(ssecurity_b64, nonce_b64)
    rc4 = _make_rc4(rc4_key_b64)
    result: dict[str, str] = {}
    for k in sorted(encrypted_params.keys()):
        if k in ("signature", "_nonce"):
            continue
        pt = rc4.crypt(base64.b64decode(encrypted_params[k]))
        result[k] = pt.decode("utf-8")
    return result
