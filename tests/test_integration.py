import pytest

from huami_token.zepp import ZeppClient, ZeppSession


@pytest.mark.integration
class TestIntegration:
    def test_login_get_devices_logout(self, zepp_email: str, zepp_password: str) -> None:
        session = ZeppSession(username=zepp_email, password=zepp_password)
        session.login()

        assert session.user_id
        assert session.app_token

        client = ZeppClient(session)
        devices = client.get_devices()
        assert len(devices) > 0

        session.logout()
