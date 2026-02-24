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

from enum import Enum


class ZEPP_ENCRYPTION_PARAMS(bytes, Enum):
    KEY = b"xeNtBVqzDc6tuNTh"
    IV = b"MAAAYAAAAAAAAABg"


class MAGIC(str, Enum):
    ZEPP_CHANNEL = "a100900101016"


class URLS(str, Enum):
    ZEPP_TOKENS = "https://api-user-us2.zepp.com/v2/registrations/tokens"
    ZEPP_LOGIN = "https://api-mifit-us2.zepp.com/v2/client/login"
    ZEPP_LOGOUT = "https://api-mifit-us2.zepp.com/v1/client/logout"
    ZEPP_DEVICES = "https://api-mifit.zepp.com/users/{user_id}/devices"
    ZEPP_GPS = "https://api-mifit-us2.zepp.com/apps/com.xiaomi.hm.health/fileTypes/{file_type}/files"


class PAYLOADS(dict, Enum):  # type: ignore[misc]
    ZEPP_TOKENS = {
        "emailOrPhone": None,
        "state": "REDIRECTION",
        "client_id": "HuaMi",
        "password": None,
        "redirect_uri": "https://s3-us-west-2.amazonaws.com/hm-registration/successsignin.html",
        "region": "us-west-2",
        "token": ["access", "refresh"],
        "country_code": "US",
    }
    ZEPP_LOGIN = {
        "code": None,
        "device_id": None,
        "device_model": "android_phone",
        "app_version": "9.12.5",
        "dn": "api-mifit.zepp.com,api-user.zepp.com,api-mifit.zepp.com,api-watch.zepp.com,app-analytics.zepp.com,auth.zepp.com,api-analytics.zepp.com",
        "third_name": "huami",
        "source": "com.huami.watch.hmwatchmanager:9.12.5:151689",
        "app_name": "com.huami.midong",
        "country_code": "US",
        "grant_type": "access_token",
        "allow_registration": "false",
        "lang": "en",
        "countryState": "US-NY",
    }


class HEADERS(dict, Enum):  # type: ignore[misc]
    ZEPP_TOKENS = {
        "app_name": "com.huami.midong",
        "appname": "com.huami.midong",
        "cv": "151689_9.12.5",
        "v": "2.0",
        "appplatform": "android_phone",
        "vb": "202509151347",
        "vn": "9.12.5",
        "user-agent": "Zepp/9.12.5 (Pixel 4; Android 12; Density/2.75)",
        "x-hm-ekv": "1",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "accept-encoding": "gzip",
    }

    ZEPP_LOGIN = {
        "app_name": "com.huami.webapp",
        "appname": "com.huami.webapp",
        "origin": "https://user.zepp.com",
        "referer": "https://user.zepp.com/",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "accept": "application/json, text/plain, */*",
        "accept-language": "en-US,en;q=0.5",
    }

    ZEPP_DEVICES = {
        "hm-privacy-diagnostics": "false",
        "country": "US",
        "appplatform": "android_phone",
        "hm-privacy-ceip": "true",
        "x-request-id": None,
        "timezone": "Europe/London",
        "channel": MAGIC.ZEPP_CHANNEL.value,
        "vb": "202509151347",
        "cv": "151689_9.12.5",
        "appname": "com.huami.midong",
        "v": "2.0",
        "vn": "9.12.5",
        "apptoken": None,
        "lang": "en_US",
        "user-agent": "Zepp/9.12.5 (Pixel 4; Android 12; Density/2.75)",
        "accept-encoding": "gzip",
    }

    ZEPP_GPS = {
        "hm-privacy-diagnostics": "false",
        "country": "US",
        "appplatform": "android_phone",
        "hm-privacy-ceip": "false",
        "x-request-id": None,
        "timezone": "Europe/London",
        "channel": MAGIC.ZEPP_CHANNEL.value,
        "vb": "202509151347",
        "cv": "151689_9.12.5",
        "appname": "com.huami.midong",
        "v": "2.0",
        "vn": "9.12.5",
        "apptoken": None,
        "lang": "en_US",
        "user-agent": "Zepp/9.12.5 (Pixel 4; Android 12; Density/2.75)",
        "accept-encoding": "gzip",
    }

    ZEPP_LOGOUT = {
        "app_name": "com.huami.midong",
        "hm-privacy-ceip": "false",
        "accept-language": "en-US",
        "appname": "com.huami.midong",
        "cv": "151689_9.12.5",
        "v": "2.0",
        "appplatform": "android_phone",
        "vb": "202509151347",
        "vn": "9.12.5",
        "user-agent": "Zepp/9.12.5 (Pixel 4; Android 12; Density/2.75)",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    }


class XIAOMI_URLS(str, Enum):
    SERVICE_LOGIN = "https://account.xiaomi.com/pass/serviceLogin"
    SERVICE_LOGIN_AUTH2 = "https://account.xiaomi.com/pass/serviceLoginAuth2"


class XIAOMI_HEADERS(dict, Enum):  # type: ignore[misc]
    SERVICE_LOGIN = {
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 12; Pixel 4 Build/SP1A.210812.016.C1;"
            " wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0"
            " Chrome/131.0.6778.200 Mobile Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    SERVICE_LOGIN_AUTH2 = {
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 12; Pixel 4 Build/SP1A.210812.016.C1;"
            " wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0"
            " Chrome/131.0.6778.200 Mobile Safari/537.36"
        ),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }


class URL_PARAMS(dict, Enum):  # type: ignore[misc]
    ZEPP_DEVICES = {
        "r": None,  # yes, twice
        "enableMultiDeviceOnMultiType": ["true", "true"],
        "userid": None,
        "appid": None,
        "channel": MAGIC.ZEPP_CHANNEL.value,
        "country": "US",
        "cv": "151689_9.12.5",
        "device": "android_32",
        "device_type": "android_phone",
        "enableMultiDevice": "true",
        "lang": "en_US",
        "timezone": "Europe/London",
        "v": "2.0",
    }

    ZEPP_GPS = {
        "r": None,  # yes, twice again
        "userid": None,
        "appid": None,
        "channel": MAGIC.ZEPP_CHANNEL.value,
        "country": "US",
        "cv": "151689_9.12.5",
        "device": "android_32",
        "device_type": "android_phone",
        "lang": "en_US",
        "timezone": "Europe/Berlin",
        "v": "2.0",
    }
