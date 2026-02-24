from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class Device:
    mac: str
    active: bool
    auth_key: str

    @classmethod
    def from_api_response(cls, data: dict) -> Device:
        mac = data.get("macAddress", "??:??:??:??:??:??")
        active = bool(data.get("activeStatus", 0))
        additional_info_str = data.get("additionalInfo", "{}")
        additional_info = json.loads(additional_info_str) if additional_info_str else {}
        auth_key = additional_info.get("auth_key", "??")
        return cls(mac=mac, active=active, auth_key=auth_key)
