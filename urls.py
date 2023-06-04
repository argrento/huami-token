# Copyright (c) 2020-2023 Kirill Snezhko

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

"""Module for storin urls and payloads fro different requests"""

from typing import Dict

from fake_useragent import UserAgent # type: ignore
ua = UserAgent()

URLS = {
    'login_xiaomi': 'https://account.xiaomi.com/oauth2/authorize?skip_confirm=false&'
                    'client_id=2882303761517383915&pt=0&scope=1+6000+16001+20000&'
                    'redirect_uri=https%3A%2F%2Fhm.xiaomi.com%2Fwatch.do&'
                    '_locale=en_US&response_type=code',
    'tokens_amazfit': 'https://api-user.huami.com/registrations/{user_email}/tokens',
    'login_amazfit': 'https://account.huami.com/v2/client/login',
    'devices': 'https://api-mifit-us2.huami.com/users/{user_id}/devices',
    'agps': 'https://api-mifit-us2.huami.com/apps/com.huami.midong/fileTypes/{pack_name}/files',
    'data_short': 'https://api-mifit-us2.huami.com/users/{user_id}/deviceTypes/4/data',
    'logout': 'https://account-us2.huami.com/v1/client/logout',
    'fw_updates': 'https://api-mifit-us2.huami.com/devices/ALL/hasNewVersion',
    'login_mi_fitness': 'https://account.xiaomi.com/pass/serviceLogin',
    'auth2_mi_fitness': 'https://account.xiaomi.com/pass/serviceLoginAuth2',
    'privacy_mi_fitness': 'https://data.sec.miui.com/privacy/agree/v1'
}

PAYLOADS: Dict[str, Dict[str, str]] = {
    'login_xiaomi': {},
    'tokens_amazfit': {
        'state':        'REDIRECTION',
        'client_id':    'HuaMi',
        'password':     "",
        'redirect_uri': 'https://s3-us-west-2.amazonws.com/hm-registration/successsignin.html',
        'region':       'us-west-2',
        'token':        'access',
        'country_code': 'US'
    },
    'login_amazfit': {
        'dn':                 'account.huami.com,api-user.huami.com,app-analytics.huami.com,'
                              'api-watch.huami.com,'
                              'api-analytics.huami.com,api-mifit.huami.com',
        'app_version':        '5.9.2-play_100355',
        'source':             'com.huami.watch.hmwatchmanager',
        'country_code':       "",
        'device_id':          "",
        'third_name':         "",
        'lang':               'en',
        'device_model':       'android_phone',
        'allow_registration': 'false',
        'app_name':           'com.huami.midong',
        'code':               "",
        'grant_type':         ""
    },
    'devices': {
        'apptoken': "",
        # 'enableMultiDevice': 'true'
    },
    'agps': {
        'apptoken': ""
    },
    'data_short': {
        'apptoken': "",
        'startDay': "",
        'endDay': ""
    },
    'logout': {
        'login_token': ""
    },
    'fw_updates': {
        'productionSource': "",
        'deviceSource': "",
        'fontVersion': '0',
        'fontFlag': '0',
        'appVersion': '5.9.2-play_100355',
        'firmwareVersion': "",
        'hardwareVersion': "",
        'support8Bytes': 'true'
    },
    'initial_login_mi_fitness': {
        "User-Agent": ua.random,
        "Cookie": "userId={userId}; deviceId={deviceId}"
    },
    'auth2_mi_fitness': {
        "User-Agent": ua.random,
        "Cookie": "deviceId={deviceId}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip"
    },
    'privacy_mi_fitness': {
        "sign": "",
        "timestamp": "",
        "source": "sdk",
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": ua.random,
        "Host": "data.sec.miui.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    },
    'login_mi_fitness': {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": ua.random,
        "Cookie": "passToken={passToken}; userId={userId}; deviceId={deviceId}",
        "Host": "account.xiaomi.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }
}
