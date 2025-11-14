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


class PAYLOADS(dict, Enum):
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


class HEADERS(dict, Enum):
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


class URL_PARAMS(dict, Enum):
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
