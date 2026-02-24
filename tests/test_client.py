import json
from unittest.mock import MagicMock, patch

import pytest

from huami_token.errors import DeviceError
from huami_token.models import Device
from huami_token.zepp import ZeppClient, ZeppSession


def _make_logged_in_session() -> ZeppSession:
    session = ZeppSession(username="test@test.com", password="pass")
    session._access_token = "acc"
    session._refresh_token = "ref"
    session._login_token = "lt"
    session._app_token = "at"
    session._user_id = "12345"
    return session


class TestGetDevices:
    @patch("huami_token.zepp.requests.get")
    def test_get_devices(self, mock_get: MagicMock) -> None:
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "items": [
                {
                    "macAddress": "AA:BB:CC:DD:EE:FF",
                    "activeStatus": 1,
                    "additionalInfo": json.dumps({"auth_key": "deadbeef"}),
                },
                {
                    "macAddress": "11:22:33:44:55:66",
                    "activeStatus": 0,
                    "additionalInfo": json.dumps({"auth_key": "cafebabe"}),
                },
            ]
        }
        mock_get.return_value = resp

        client = ZeppClient(_make_logged_in_session())
        devices = client.get_devices()

        assert len(devices) == 2
        assert isinstance(devices[0], Device)
        assert devices[0].mac == "AA:BB:CC:DD:EE:FF"
        assert devices[0].active is True
        assert devices[0].auth_key == "deadbeef"
        assert devices[1].active is False

    @patch("huami_token.zepp.requests.get")
    def test_get_devices_empty(self, mock_get: MagicMock) -> None:
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"items": []}
        mock_get.return_value = resp

        client = ZeppClient(_make_logged_in_session())
        with pytest.raises(DeviceError, match="No devices found"):
            client.get_devices()


class TestDownloadGps:
    @patch("huami_token.zepp.requests.get")
    def test_download_gps(self, mock_get: MagicMock, tmp_path: MagicMock) -> None:
        # Mock the metadata response for each file type
        meta_resp = MagicMock()
        meta_resp.status_code = 200
        meta_resp.json.return_value = [{"fileUrl": "https://cdn.example.com/gps_data.zip"}]

        # Mock the file download response
        download_resp = MagicMock()
        download_resp.__enter__ = MagicMock(return_value=download_resp)
        download_resp.__exit__ = MagicMock(return_value=False)
        download_resp.raise_for_status = MagicMock()
        download_resp.iter_content = MagicMock(return_value=[b"fake-gps-data"])

        mock_get.side_effect = [meta_resp, download_resp] * 6  # 6 file types

        client = ZeppClient(_make_logged_in_session())
        client.download_gps_data(tmp_path)

        assert (tmp_path / "gps_data.zip").exists()
        assert (tmp_path / "gps_data.zip").read_bytes() == b"fake-gps-data"
