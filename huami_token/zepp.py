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

import json
import secrets
import urllib.parse
import uuid

import requests
from loguru import logger

from .constants import HEADERS, PAYLOADS, URL_PARAMS, URLS, ZEPP_ENCRYPTION_PARAMS
from .errors import AuthenticationError, DeviceError, HuamiTokenError, LogoutError
from .helpers import zepp_encrypt_payload


class Zepp:
    def __init__(self, username: str, password: str) -> None:
        self.username: str = username
        self.password: str = password

        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.login_token: str | None = None
        self.app_token: str | None = None

        self.user_id: str | None = None

    def login(self) -> None:
        try:
            logger.info("Logging in...")
            self._get_refresh_and_access_tokens()
            self._login()
            logger.info(f"Logged in! User id: {self.user_id}")
        except HuamiTokenError as e:
            logger.exception(f"Authentication error occurred: {e}")

    def _get_refresh_and_access_tokens(self) -> None:
        """
        Get the first pair of tokens: refresh and access. If login and password are correct,
        the server responds with a 303 redirect to a URL containing the tokens in the query parameters.

        Do not follow the redirect, just extract the tokens from the "Location" URL.
        """

        # Prepare payload
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
        else:
            logger.debug(f"Redirect location: {redirect_location}")

        parsed_redirect_url = urllib.parse.urlparse(redirect_location)
        query_params = urllib.parse.parse_qs(parsed_redirect_url.query)

        # Check for refresh and access tokens in the redirect URL
        self.refresh_token = query_params.get("refresh", [None])[0]
        logger.debug(f"Refresh token: {self.refresh_token}")
        self.access_token = query_params.get("access", [None])[0]
        logger.debug(f"Access token: {self.access_token}")
        if not self.refresh_token or not self.access_token:
            raise AuthenticationError(
                code="no-tokens",
                message="No refresh or access token found in the redirect URL",
            )
        logger.info(f"Received access and refresh tokens successfully")

    def _login(self):
        """Perform login to get login_token and app_token using access_token"""
        payload = PAYLOADS.ZEPP_LOGIN.value.copy()
        payload["code"] = self.access_token
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

        # Extract login_token and app_token from the response
        token_info = response_data.get("token_info", {})
        self.login_token = token_info.get("login_token")
        logger.debug(f"Login token: {self.login_token}")
        self.app_token = token_info.get("app_token")
        logger.debug(f"App token: {self.app_token}")
        if not self.login_token or not self.app_token:
            raise AuthenticationError(
                code="no-login-tokens",
                message="No login_token or app_token found in the login response",
            )

        # Extract user id
        self.user_id = token_info.get("user_id")
        if not self.user_id:
            raise AuthenticationError(
                code="no-user-id",
                message="No user_id found in the login response",
            )

    def get_devices(self):
        """Get the list of devices associated with the account"""
        logger.info("Getting linked devices...")
        if not self.user_id or not self.app_token:
            raise DeviceError("Cannot get devices without user_id and app_token")

        params = URL_PARAMS.ZEPP_DEVICES.value.copy()
        params["r"] = [str(uuid.uuid4())] * 2  # yes, twice
        params["userid"] = self.user_id
        params["appid"] = secrets.randbits(64)  # random 64-bit integer

        headers = HEADERS.ZEPP_DEVICES.value.copy()
        headers["x-request-id"] = str(uuid.uuid4())
        headers["apptoken"] = self.app_token

        response = requests.get(
            URLS.ZEPP_DEVICES.value.format(user_id=self.user_id),
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

        for item_id, item in enumerate(items):
            mac = item.get("macAddress", "??:??:??:??:??:??")
            active = "Yes" if item.get("activeStatus", 0) else "No"
            additional_info_str = item.get("additionalInfo", {})
            additional_info = (
                json.loads(additional_info_str) if additional_info_str else {}
            )
            auth_key = additional_info.get("auth_key", "??")
            logger.info(f"Device {item_id}:")
            logger.info(f"MAC: {mac}, Active: {active}")
            logger.info(f"Key: 0x{auth_key}")

    def download_gps_data(self) -> str:
        logger.info("Downloading GPS data...")
        if not self.user_id or not self.app_token:
            raise DeviceError("Cannot download GPS data without user_id and app_token")

        params = URL_PARAMS.ZEPP_GPS.value.copy()
        params["r"] = [str(uuid.uuid4())] * 2  # yes, twice again
        params["userid"] = self.user_id
        params["appid"] = secrets.randbits(64)  # random 64-bit integer again

        headers = HEADERS.ZEPP_DEVICES.value.copy()
        headers["x-request-id"] = str(uuid.uuid4())
        headers["apptoken"] = self.app_token

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
                    with open(file_name, "wb") as gps_file:
                        logger.info(f"Downloading {file_type} to {file_name}...")
                        for chunk in file_download_response.iter_content(8192):
                            if chunk:
                                gps_file.write(chunk)

    def logout(self) -> str:
        """Logout from Zepp account"""
        if not self.login_token:
            logger.warning("No login token, cannot logout")
            return "Error"

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
        return response_data["result"]


if __name__ == "__main__":
    pass
