from unittest.mock import MagicMock, patch

import pytest

from huami_token.errors import AuthenticationError, LogoutError
from huami_token.zepp import ZeppSession


def _make_redirect_response(access: str = "acc123", refresh: str = "ref456") -> MagicMock:
    resp = MagicMock()
    resp.status_code = 303
    resp.headers = {
        "Location": f"https://example.com/callback?access={access}&refresh={refresh}"
    }
    return resp


def _make_login_response(
    login_token: str = "lt_abc",
    app_token: str = "at_xyz",
    user_id: str = "12345",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "token_info": {
            "login_token": login_token,
            "app_token": app_token,
            "user_id": user_id,
        }
    }
    return resp


class TestLogin:
    @patch("huami_token.zepp.requests.post")
    def test_login_success(self, mock_post: MagicMock) -> None:
        mock_post.side_effect = [_make_redirect_response(), _make_login_response()]

        session = ZeppSession(username="test@test.com", password="pass123")
        session.login()

        assert session.app_token == "at_xyz"
        assert session.user_id == "12345"
        assert session.login_token == "lt_abc"

    @patch("huami_token.zepp.requests.post")
    def test_login_bad_status(self, mock_post: MagicMock) -> None:
        resp = MagicMock()
        resp.status_code = 401
        mock_post.return_value = resp

        session = ZeppSession(username="test@test.com", password="wrong")
        with pytest.raises(AuthenticationError, match="No redirect after token request"):
            session.login()

    @patch("huami_token.zepp.requests.post")
    def test_login_missing_tokens(self, mock_post: MagicMock) -> None:
        resp = MagicMock()
        resp.status_code = 303
        resp.headers = {"Location": "https://example.com/callback?other=value"}
        mock_post.return_value = resp

        session = ZeppSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="No refresh or access token"):
            session.login()


class TestLogout:
    @patch("huami_token.zepp.requests.post")
    def test_logout_success(self, mock_post: MagicMock) -> None:
        # First set up a logged-in session
        mock_post.side_effect = [
            _make_redirect_response(),
            _make_login_response(),
            MagicMock(status_code=200, json=MagicMock(return_value={"result": "ok"})),
        ]

        session = ZeppSession(username="test@test.com", password="pass")
        session.login()
        session.logout()  # should not raise

    @patch("huami_token.zepp.requests.post")
    def test_logout_failure(self, mock_post: MagicMock) -> None:
        mock_post.side_effect = [
            _make_redirect_response(),
            _make_login_response(),
            MagicMock(status_code=200, json=MagicMock(return_value={"result": "error"})),
        ]

        session = ZeppSession(username="test@test.com", password="pass")
        session.login()
        with pytest.raises(LogoutError):
            session.logout()


class TestProperties:
    def test_app_token_before_login(self) -> None:
        session = ZeppSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="app_token"):
            _ = session.app_token

    def test_user_id_before_login(self) -> None:
        session = ZeppSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="user_id"):
            _ = session.user_id

    def test_login_token_before_login(self) -> None:
        session = ZeppSession(username="test@test.com", password="pass")
        with pytest.raises(AuthenticationError, match="login_token"):
            _ = session.login_token
