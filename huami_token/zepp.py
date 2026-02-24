# Copyright (c) 2025 Kirill Snezhko

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import annotations

import secrets
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

import requests
from loguru import logger

from .constants import HEADERS, PAYLOADS, URL_PARAMS, URLS, ZEPP_ENCRYPTION_PARAMS
from .errors import AuthenticationError, DeviceError, LogoutError
from .helpers import zepp_encrypt_payload
from .models import Device


class ZeppSession:
    def __init__(self, username: str, password: str) -> None:
        self.username: str = username
        self.password: str = password

        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._login_token: str | None = None
        self._app_token: str | None = None
        self._user_id: str | None = None

    @property
    def app_token(self) -> str:
        if self._app_token is None:
            raise AuthenticationError(message="Not logged in — no app_token available")
        return self._app_token

    @property
    def user_id(self) -> str:
        if self._user_id is None:
            raise AuthenticationError(message="Not logged in — no user_id available")
        return self._user_id

    @property
    def login_token(self) -> str:
        if self._login_token is None:
            raise AuthenticationError(message="Not logged in — no login_token available")
        return self._login_token

    def login(self) -> None:
        logger.info("Logging in...")
        self._get_refresh_and_access_tokens()
        self._login()
        logger.info(f"Logged in! User id: {self._user_id}")

    def _get_refresh_and_access_tokens(self) -> None:
        """Get refresh and access tokens via encrypted credential exchange.

        If login and password are correct, the server responds with a 303 redirect
        to a URL containing the tokens in the query parameters.
        """
        payload = PAYLOADS.ZEPP_TOKENS.value.copy()
        payload["emailOrPhone"] = self.username
        payload["password"] = self.password
        encoded_payload = urllib.parse.urlencode(payload, doseq=True).encode()
        logger.debug(f"{encoded_payload=}")
        encrypted_payload = zepp_encrypt_payload(
            encoded_payload,
            key=ZEPP_ENCRYPTION_PARAMS.KEY.value,
            iv=ZEPP_ENCRYPTION_PARAMS.IV.value,
        )
        response = requests.post(
            URLS.ZEPP_TOKENS.value,
            data=encrypted_payload,
            headers=HEADERS.ZEPP_TOKENS.value,
            allow_redirects=False,
        )
        if response.status_code != 303:
            raise AuthenticationError(
                code="no-redirect",
                message=f"No redirect after token request, status code is {response.status_code} instead of 303",
            )

        redirect_location = response.headers.get("Location")
        if not redirect_location:
            raise AuthenticationError(
                code="no-location",
                message="No redirect location found in the response headers",
            )
        logger.debug(f"Redirect location: {redirect_location}")

        parsed_redirect_url = urllib.parse.urlparse(redirect_location)
        query_params = urllib.parse.parse_qs(parsed_redirect_url.query)

        self._refresh_token = query_params.get("refresh", [None])[0]
        logger.debug(f"Refresh token: {self._refresh_token}")
        self._access_token = query_params.get("access", [None])[0]
        logger.debug(f"Access token: {self._access_token}")
        if not self._refresh_token or not self._access_token:
            raise AuthenticationError(
                code="no-tokens",
                message="No refresh or access token found in the redirect URL",
            )
        logger.info("Received access and refresh tokens successfully")

    def _login(self) -> None:
        """Perform login to get login_token and app_token using access_token."""
        payload = PAYLOADS.ZEPP_LOGIN.value.copy()
        payload["code"] = self._access_token
        payload["device_id"] = str(uuid.uuid4())

        response = requests.post(
            URLS.ZEPP_LOGIN.value,
            data=payload,
            headers=HEADERS.ZEPP_LOGIN.value,
        )
        if response.status_code != 200:
            raise AuthenticationError(
                code="login-failed",
                message=f"Login request failed with status code {response.status_code}",
            )
        response_data = response.json()

        token_info = response_data.get("token_info", {})
        self._login_token = token_info.get("login_token")
        logger.debug(f"Login token: {self._login_token}")
        self._app_token = token_info.get("app_token")
        logger.debug(f"App token: {self._app_token}")
        if not self._login_token or not self._app_token:
            raise AuthenticationError(
                code="no-login-tokens",
                message="No login_token or app_token found in the login response",
            )

        self._user_id = token_info.get("user_id")
        if not self._user_id:
            raise AuthenticationError(
                code="no-user-id",
                message="No user_id found in the login response",
            )

    def logout(self) -> None:
        """Logout from Zepp account. Raises LogoutError on failure."""
        payload = {"login_token": self.login_token, "os_verison": "vnull"}
        response = requests.post(
            URLS.ZEPP_LOGOUT.value,
            data=payload,
            headers=HEADERS.ZEPP_LOGOUT.value,
        )
        if response.status_code != 200:
            raise LogoutError(
                code="logout-failed",
                message=f"Logout request failed with status code {response.status_code}",
            )

        response_data = response.json()
        if response_data.get("result") != "ok":
            raise LogoutError(
                code="logout-error",
                message=f"Logout failed with response: {response_data}",
            )
        logger.info("Logged out.")


class ZeppClient:
    def __init__(self, session: ZeppSession) -> None:
        self.session = session

    def get_devices(self) -> list[Device]:
        """Get the list of devices associated with the account."""
        logger.info("Getting linked devices...")

        params: dict[str, Any] = URL_PARAMS.ZEPP_DEVICES.value.copy()
        params["r"] = [str(uuid.uuid4())] * 2
        params["userid"] = self.session.user_id
        params["appid"] = str(secrets.randbits(64))

        headers = HEADERS.ZEPP_DEVICES.value.copy()
        headers["x-request-id"] = str(uuid.uuid4())
        headers["apptoken"] = self.session.app_token

        response = requests.get(
            URLS.ZEPP_DEVICES.value.format(user_id=self.session.user_id),
            params=params,
            headers=headers,
        )
        if response.status_code != 200:
            raise DeviceError(
                code="get-devices-failed",
                message=f"Get devices request failed with status code {response.status_code}",
            )
        response_data = response.json()
        items = response_data.get("items", [])
        if not items:
            raise DeviceError(
                code="no-devices",
                message="No devices found in the response",
            )

        return [Device.from_api_response(item) for item in items]

    def download_gps_data(self, output_dir: Path) -> None:
        """Download GPS data files to output_dir."""
        logger.info("Downloading GPS data...")
        output_dir.mkdir(parents=True, exist_ok=True)

        params: dict[str, Any] = URL_PARAMS.ZEPP_GPS.value.copy()
        params["r"] = [str(uuid.uuid4())] * 2
        params["userid"] = self.session.user_id
        params["appid"] = str(secrets.randbits(64))

        headers = HEADERS.ZEPP_DEVICES.value.copy()
        headers["x-request-id"] = str(uuid.uuid4())
        headers["apptoken"] = self.session.app_token

        for file_type in ["AGPS_ALM", "AGPSZIP", "LLE", "AGPS", "EPO", "LTO"]:
            response = requests.get(
                URLS.ZEPP_GPS.value.format(file_type=file_type),
                params=params,
                headers=headers,
            )
            if response.status_code != 200:
                raise DeviceError(
                    code="get-gps-failed",
                    message=f"Get GPS data failed with status code {response.status_code}",
                )
            response_data = response.json()
            if file_url := response_data[0].get("fileUrl"):
                file_name = file_url.split("/")[-1]

                with requests.get(
                    file_url, stream=True, timeout=10, headers=headers
                ) as file_download_response:
                    file_download_response.raise_for_status()
                    dest = output_dir / file_name
                    with open(dest, "wb") as gps_file:
                        logger.info(f"Downloading {file_type} to {dest}...")
                        for chunk in file_download_response.iter_content(8192):
                            if chunk:
                                gps_file.write(chunk)
