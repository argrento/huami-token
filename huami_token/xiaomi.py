from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
from typing import Any

import requests
from loguru import logger

from .constants import XIAOMI_HEADERS, XIAOMI_URLS
from .errors import AuthenticationError
from .mi_crypto import (
    compute_signing_path,
    generate_nonce,
    mi_decrypt_response,
    mi_encrypt_params,
)


def _parse_xiaomi_json(text: str) -> dict[str, Any]:
    """Parse Xiaomi JSON response, stripping the '&&&START&&&' prefix if present."""
    prefix = "&&&START&&&"
    if text.startswith(prefix):
        text = text[len(prefix) :]
    return json.loads(text)


def _generate_device_id(seed: str) -> str:
    """Generate a device ID in the format 'an_<md5_hex>' from a seed string."""
    return "an_" + hashlib.md5(seed.encode()).hexdigest()


class XiaomiSession:
    """Xiaomi Mi Account authentication session.

    Implements the 3-step login flow:
    1. GET serviceLogin — obtain _sign, qs, callback
    2. POST serviceLoginAuth2 — authenticate, get ssecurity, nonce, location
    3. GET location — follow redirect to obtain serviceToken cookie
    """

    def __init__(self, username: str, password: str) -> None:
        self.username: str = username
        self.password: str = password
        self.device_id: str = _generate_device_id(username)

        self._ssecurity: str | None = None
        self._service_token: str | None = None
        self._user_id: str | None = None
        self._c_user_id: str | None = None
        self._nonce: int | None = None
        self._time_diff: int = 0

    @property
    def ssecurity(self) -> str:
        if self._ssecurity is None:
            raise AuthenticationError(message="Not logged in — no ssecurity available")
        return self._ssecurity

    @property
    def service_token(self) -> str:
        if self._service_token is None:
            raise AuthenticationError(message="Not logged in — no service_token available")
        return self._service_token

    @property
    def user_id(self) -> str:
        if self._user_id is None:
            raise AuthenticationError(message="Not logged in — no user_id available")
        return self._user_id

    @property
    def c_user_id(self) -> str:
        if self._c_user_id is None:
            raise AuthenticationError(message="Not logged in — no c_user_id available")
        return self._c_user_id

    def login(self) -> None:
        logger.info("Logging in to Xiaomi...")
        sign, qs, callback = self._get_login_page_params()
        self._authenticate(sign, qs, callback)
        self._get_service_token()
        logger.info(f"Logged in! User id: {self._user_id}")

    def _get_login_page_params(self) -> tuple[str, str, str]:
        """Step 1: GET serviceLogin to obtain _sign, qs, and callback parameters."""
        params = {
            "_json": "true",
            "sid": "miothealth",
            "_locale": "en_US",
        }
        cookies = {
            "userId": self.username,
            "deviceId": self.device_id,
        }
        response = requests.get(
            XIAOMI_URLS.SERVICE_LOGIN.value,
            params=params,
            headers=XIAOMI_HEADERS.SERVICE_LOGIN.value,
            cookies=cookies,
        )
        if response.status_code != 200:
            raise AuthenticationError(
                code="service-login-failed",
                message=f"serviceLogin request failed with status {response.status_code}",
            )

        data = _parse_xiaomi_json(response.text)
        sign = data.get("_sign")
        qs = data.get("qs")
        callback = data.get("callback")
        if not sign or not qs or not callback:
            raise AuthenticationError(
                code="missing-login-params",
                message=f"Missing _sign/qs/callback in serviceLogin response: {list(data.keys())}",
            )
        logger.debug(f"Got login page params: qs={qs}")
        return sign, qs, callback

    def _authenticate(self, sign: str, qs: str, callback: str) -> None:
        """Step 2: POST serviceLoginAuth2 with credentials."""
        password_hash = hashlib.md5(self.password.encode()).hexdigest().upper()

        payload = {
            "qs": qs,
            "callback": callback,
            "_json": "true",
            "_sign": sign,
            "user": self.username,
            "hash": password_hash,
            "sid": "miothealth",
            "_locale": "en_US",
        }
        cookies = {
            "deviceId": self.device_id,
        }
        response = requests.post(
            XIAOMI_URLS.SERVICE_LOGIN_AUTH2.value,
            data=payload,
            headers=XIAOMI_HEADERS.SERVICE_LOGIN_AUTH2.value,
            cookies=cookies,
        )
        if response.status_code != 200:
            raise AuthenticationError(
                code="auth-request-failed",
                message=f"serviceLoginAuth2 failed with status {response.status_code}",
            )

        data = _parse_xiaomi_json(response.text)
        if data.get("code") != 0:
            raise AuthenticationError(
                code="auth-failed",
                message=f"Authentication failed: {data.get('description', data.get('code'))}",
            )

        self._ssecurity = data.get("ssecurity")
        self._nonce = data.get("nonce")
        self._user_id = str(data.get("userId", ""))
        self._c_user_id = data.get("cUserId")
        location = data.get("location")

        if not self._ssecurity or not location:
            raise AuthenticationError(
                code="missing-auth-data",
                message="Missing ssecurity or location in auth response",
            )
        logger.debug(f"Authenticated, userId={self._user_id}")

        self._location = location

    def _get_service_token(self) -> None:
        """Step 3: Follow location URL to obtain serviceToken from cookies."""
        nonce = self._nonce
        if nonce is None:
            raise AuthenticationError(
                code="missing-nonce",
                message="No nonce from authentication step",
            )

        # Compute clientSign: base64(SHA1("nonce=" + nonce + "&" + ssecurity))
        nonce_str = str(nonce)
        sign_input = f"nonce={nonce_str}&{self._ssecurity}"
        client_sign = base64.b64encode(
            hashlib.sha1(sign_input.encode()).digest()
        ).decode()

        url = self._location + "&clientSign=" + urllib.parse.quote(client_sign)

        response = requests.get(url, allow_redirects=False)
        # The server may respond with a redirect or 200; either way, cookies are set
        service_token = response.cookies.get("serviceToken")
        if not service_token:
            # Try following redirects
            response = requests.get(url)
            service_token = response.cookies.get("serviceToken")

        if not service_token:
            raise AuthenticationError(
                code="no-service-token",
                message="serviceToken not found in response cookies",
            )
        self._service_token = service_token
        logger.debug("Got service token")


class XiaomiClient:
    """Client for making authenticated API requests to Xiaomi health servers."""

    def __init__(self, session: XiaomiSession, region: str = "ru") -> None:
        self.session = session
        self.region = region

    def request(
        self,
        method: str,
        url: str,
        params: dict[str, str] | None = None,
        path_prefix: str = "",
        extra_query: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Make an encrypted API request.

        Args:
            method: HTTP method ("GET" or "POST").
            url: Full URL (e.g. "https://ru.hlth.io.mi.com/healthapp/...").
            params: Dict of plaintext parameters to encrypt.
            path_prefix: The pathPrefix for signing path computation.
            extra_query: Unencrypted params added alongside encrypted ones
                         (filterSignatureKeys like locale).
        """
        parsed = urllib.parse.urlparse(url)
        full_path = parsed.path
        signing_path = compute_signing_path(full_path, path_prefix)

        nonce_b64 = generate_nonce(self.session._time_diff)

        encrypted = mi_encrypt_params(
            method=method,
            signing_path=signing_path,
            params=params or {},
            nonce_b64=nonce_b64,
            ssecurity_b64=self.session.ssecurity,
        )

        if extra_query:
            encrypted = {**extra_query, **encrypted}

        cookies = self._build_cookies()
        headers = self._build_headers()

        if method.upper() == "GET":
            response = requests.get(url, params=encrypted, cookies=cookies, headers=headers)
        else:
            response = requests.post(url, data=encrypted, cookies=cookies, headers=headers)

        body = response.text
        decrypted = mi_decrypt_response(body, nonce_b64, self.session.ssecurity)
        return json.loads(decrypted)

    def get_config_info_by_category(
        self,
        category: str = "wearable,other_device,equipment",
        app_version: str = "9.8.348i",
    ) -> dict[str, Any]:
        """Fetch product config info by category (device catalog with BT keys, etc.)."""
        url = f"https://{self.region}.hlth.io.mi.com/app/v1/product/get_config_info_by_category"
        data = json.dumps(
            {
                "category": category,
                "app_platform": 0,
                "app_version": app_version,
                "last_modify_time": 0,
            },
            separators=(",", ":"),
        )
        return self.request(
            "GET", url,
            params={"data": data},
            path_prefix="",
            extra_query={"locale": "en_us"},
        )

    def get_source_list(self, page_size: int = 50, status: int = 1) -> dict[str, Any]:
        """Fetch bound device list (contains auth_key, mac, etc.).

        Status values:
            1 — bound wearable devices (with auth_key in detail)
            2 — active sources (phone, app, manual entry)

        Note: Device data lives on the base domain (hlth.io.mi.com),
        not on regional subdomains.
        """
        url = "https://hlth.io.mi.com/app/v1/source/get_source_list"
        data = json.dumps(
            {"page_size": page_size, "status": status},
            separators=(",", ":"),
        )
        return self.request(
            "POST", url,
            params={"data": data},
            path_prefix="",
        )

    def _build_cookies(self) -> dict[str, str]:
        return {
            "cUserId": self.session.c_user_id,
            "serviceToken": self.session.service_token,
            "locale": "en_us",
        }

    def _build_headers(self) -> dict[str, str]:
        return {
            "User-Agent": (
                "Android-12-9.8.348i-google-Pixel 4"
            ),
            "Accept-Encoding": "gzip",
            "region_tag": self.region,
        }
