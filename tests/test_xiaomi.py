from unittest.mock import MagicMock, patch

import pytest

from huami_token.errors import AuthenticationError
from huami_token.xiaomi import XiaomiSession, _generate_device_id, _parse_xiaomi_json


class TestParseXiaomiJson:
    def test_strips_prefix(self) -> None:
        text = '&&&START&&&{"code":0,"ssecurity":"abc"}'
        result = _parse_xiaomi_json(text)
        assert result == {"code": 0, "ssecurity": "abc"}

    def test_no_prefix(self) -> None:
        text = '{"code":0,"result":"ok"}'
        result = _parse_xiaomi_json(text)
        assert result == {"code": 0, "result": "ok"}

    def test_invalid_json(self) -> None:
        with pytest.raises(Exception):
            _parse_xiaomi_json("&&&START&&&not json")


class TestGenerateDeviceId:
    def test_format(self) -> None:
        device_id = _generate_device_id("test@example.com")
        assert device_id.startswith("an_")
        assert len(device_id) == 3 + 32  # "an_" + 32 hex chars

    def test_deterministic(self) -> None:
        assert _generate_device_id("user@x.com") == _generate_device_id("user@x.com")

    def test_different_seeds(self) -> None:
        assert _generate_device_id("a@b.com") != _generate_device_id("c@d.com")


def _make_service_login_response(
    sign: str = "test_sign", qs: str = "test_qs", callback: str = "https://cb.example.com"
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = (
        f'{{"_sign":"{sign}","qs":"{qs}","callback":"{callback}","sid":"miothealth"}}'
    )
    return resp


def _make_service_login_response_with_prefix() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '&&&START&&&{"_sign":"s","qs":"q","callback":"https://cb.example.com"}'
    return resp


def _make_auth_response(
    ssecurity: str = "YrTdzxpoL2f5MVGlER9E8w==",
    nonce: int = 123456,
    location: str = "https://account.xiaomi.com/sts?ticket=ST-abc",
    user_id: int = 9876543,
    c_user_id: str = "encryptedUserId",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = (
        f'{{"code":0,"ssecurity":"{ssecurity}","nonce":{nonce},'
        f'"location":"{location}","userId":{user_id},'
        f'"cUserId":"{c_user_id}","passToken":"pt_abc"}}'
    )
    return resp


def _make_auth_failure_response() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '&&&START&&&{"code":70016,"description":"Invalid credentials"}'
    return resp


def _make_service_token_response(service_token: str = "svc_token_xyz") -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.cookies = {"serviceToken": service_token}
    return resp


class TestXiaomiSessionLogin:
    @patch("huami_token.xiaomi.requests.get")
    @patch("huami_token.xiaomi.requests.post")
    def test_login_success(self, mock_post: MagicMock, mock_get: MagicMock) -> None:
        # Step 1: GET serviceLogin, Step 3: GET location
        mock_get.side_effect = [
            _make_service_login_response(),
            _make_service_token_response(),
        ]
        # Step 2: POST serviceLoginAuth2
        mock_post.return_value = _make_auth_response()

        session = XiaomiSession(username="test@test.com", password="pass123")
        session.login()

        assert session.ssecurity == "YrTdzxpoL2f5MVGlER9E8w=="
        assert session.service_token == "svc_token_xyz"
        assert session.user_id == "9876543"
        assert session.c_user_id == "encryptedUserId"

    @patch("huami_token.xiaomi.requests.get")
    @patch("huami_token.xiaomi.requests.post")
    def test_login_with_prefix_response(
        self, mock_post: MagicMock, mock_get: MagicMock
    ) -> None:
        mock_get.side_effect = [
            _make_service_login_response_with_prefix(),
            _make_service_token_response(),
        ]
        mock_post.return_value = _make_auth_response()

        session = XiaomiSession(username="test@test.com", password="pass123")
        session.login()

        assert session.ssecurity == "YrTdzxpoL2f5MVGlER9E8w=="

    @patch("huami_token.xiaomi.requests.get")
    def test_login_page_http_error(self, mock_get: MagicMock) -> None:
        resp = MagicMock()
        resp.status_code = 500
        mock_get.return_value = resp

        session = XiaomiSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="serviceLogin request failed"):
            session.login()

    @patch("huami_token.xiaomi.requests.get")
    def test_login_page_missing_params(self, mock_get: MagicMock) -> None:
        resp = MagicMock()
        resp.status_code = 200
        resp.text = '{"sid":"miothealth"}'
        mock_get.return_value = resp

        session = XiaomiSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="Missing _sign/qs/callback"):
            session.login()

    @patch("huami_token.xiaomi.requests.get")
    @patch("huami_token.xiaomi.requests.post")
    def test_auth_invalid_credentials(
        self, mock_post: MagicMock, mock_get: MagicMock
    ) -> None:
        mock_get.return_value = _make_service_login_response()
        mock_post.return_value = _make_auth_failure_response()

        session = XiaomiSession(username="test@test.com", password="wrong")
        with pytest.raises(AuthenticationError, match="Authentication failed"):
            session.login()

    @patch("huami_token.xiaomi.requests.get")
    @patch("huami_token.xiaomi.requests.post")
    def test_no_service_token_in_cookies(
        self, mock_post: MagicMock, mock_get: MagicMock
    ) -> None:
        mock_get.side_effect = [
            _make_service_login_response(),
            # Step 3 redirect response without serviceToken (allow_redirects=False)
            MagicMock(status_code=302, cookies={}),
            # Step 3 follow-up response also without serviceToken
            MagicMock(status_code=200, cookies={}),
        ]
        mock_post.return_value = _make_auth_response()

        session = XiaomiSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="serviceToken not found"):
            session.login()


class TestXiaomiSessionProperties:
    def test_ssecurity_before_login(self) -> None:
        session = XiaomiSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="ssecurity"):
            _ = session.ssecurity

    def test_service_token_before_login(self) -> None:
        session = XiaomiSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="service_token"):
            _ = session.service_token

    def test_user_id_before_login(self) -> None:
        session = XiaomiSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="user_id"):
            _ = session.user_id

    def test_c_user_id_before_login(self) -> None:
        session = XiaomiSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="c_user_id"):
            _ = session.c_user_id
