#!/usr/bin/env python3

import argparse
import requests
import urllib
import random
import uuid
import json
import shutil


class HuamiAmazfit:
    def __init__(self, method="amazfit", email=None, password=None):

        if method == 'amazfit' and (not email or not password):
            raise ValueError("For Amazfit method E-Mail and Password can not be null.")
        self.method = method
        self.email = email
        self.password = password
        self.access_token = None
        self.country_code = None

        self.app_token = None
        self.login_token = None
        self.user_id = None

        self.r = str(uuid.uuid4())

        # IMEI or something unique
        self.device_id = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                      random.randint(0, 255),
                                                      random.randint(0, 255))

    def get_access_token(self):
        print(f"Getting access token with {self.method} login method...")

        if self.method == 'xiaomi':
            login_url = "https://account.xiaomi.com/oauth2/authorize?skip_confirm=false&" \
                        "client_id=2882303761517383915&pt=0&scope=1+6000+16001+20000&" \
                        "redirect_uri=https%3A%2F%2Fhm.xiaomi.com%2Fwatch.do&_locale=en_US&response_type=code"

            print(f"Copy this URL to web-browser \n\n{login_url}\n\nand login to your Mi account.")

            token_url = input("\nPaste URL after redirection here.\n")

            parsed_token_url = urllib.parse.urlparse(token_url)
            token_url_parameters = urllib.parse.parse_qs(parsed_token_url.query)

            if 'code' not in token_url_parameters:
                raise ValueError("No 'code' parameter in login url.")

            self.access_token = token_url_parameters['code']
            self.country_code = 'US'

        elif self.method == 'amazfit':

            auth_url = f"https://api-user.huami.com/registrations/{urllib.parse.quote(self.email)}/tokens"
            data = {
                'state':        'REDIRECTION',
                'client_id':    'HuaMi',
                'password':     self.password,
                'redirect_uri': 'https://s3-us-west-2.amazonws.com/hm-registration/successsignin.html',
                'region':       'us-west-2',
                'token':        'access',
                'country_code': 'US'

            }
            response = requests.post(auth_url, data=data, allow_redirects=False)
            response.raise_for_status()

            # 'Location' parameter contains url with login status
            redirect_url = urllib.parse.urlparse(response.headers.get('Location'))
            redirect_url_parameters = urllib.parse.parse_qs(redirect_url.query)

            if 'error' in redirect_url_parameters:
                raise ValueError(f"Wrong E-mail or Password. Error: {redirect_url_parameters['error']}")

            if 'access' not in redirect_url_parameters:
                raise ValueError("No 'access' parameter in login url.")

            if 'country_code' not in redirect_url_parameters:
                raise ValueError("No 'country_code' parameter in login url.")

            self.access_token = redirect_url_parameters['access']
            self.country_code = redirect_url_parameters['country_code']

        print("Token: {}".format(self.access_token))
        return self.access_token

    def login(self, external_token=None):
        print("Logging in...")
        if external_token:
            self.access_token = external_token

        login_url = 'https://account.huami.com/v2/client/login'
        data = {
            'dn':                 'account.huami.com,api-user.huami.com,app-analytics.huami.com,api-watch.huami.com,'
                                  'api-analytics.huami.com,api-mifit.huami.com',
            'app_version':        '4.3.0-play',
            'source':             'com.huami.watch.hmwatchmanager:4.3.0-play:100152',
            'country_code':       self.country_code,
            'device_id':          self.device_id,
            'third_name':         'huami' if self.method == 'amazfit' else 'mi-watch',
            'lang':               'en',
            'device_model':       'android_phone',
            'allow_registration': 'false',
            'app_name':           'com.huami.midong',
            'code':               self.access_token,
            'grant_type':         'access_token' if self.method == 'amazfit' else 'request_token'
        }
        response = requests.post(login_url, data=data, allow_redirects=False)
        response.raise_for_status()
        login_result = response.json()

        if 'error_code' in login_result:
            raise ValueError(f"Login error. Error: {login_result['error_code']}")

        if 'token_info' not in login_result:
            raise ValueError("No 'token_info' parameter in login data.")
        else:
            token_info = login_result['token_info']
            if 'app_token' not in token_info:
                raise ValueError("No 'app_token' parameter in login data.")
            self.app_token = token_info['app_token']

            if 'login_token' not in token_info:
                raise ValueError("No 'login_token' parameter in login data.")
            self.login_token = token_info['login_token']

            if 'user_id' not in token_info:
                raise ValueError("No 'user_id' parameter in login data.")
            self.user_id = token_info['user_id']
        print("Logged in! User id: {}".format(self.user_id))

    def get_wearable_auth_keys(self):
        print("Getting linked wearables...\n")

        devices_url = f"https://api-mifit-us2.huami.com/users/{urllib.parse.quote(self.user_id)}/devices"
        headers = {
            'apptoken': self.app_token
        }

        response = requests.get(devices_url, headers=headers)
        response.raise_for_status()
        device_request = response.json()
        if 'items' not in device_request:
            raise ValueError("No 'items' parameter in devices data.")
        devices = device_request['items']

        for idx, wearable in enumerate(devices):
            if 'macAddress' not in wearable:
                raise ValueError("No 'macAddress' parameter in device data.")
            mac_address = wearable['macAddress']

            if 'additionalInfo' not in wearable:
                raise ValueError("No 'additionalInfo' parameter in device data.")
            device_info = json.loads(wearable['additionalInfo'])

            if 'auth_key' not in device_info:
                raise ValueError("No 'auth_key' parameter in device data.")
            key_str = device_info['auth_key']
            auth_key = '0x' + (key_str if key_str != '' else '0')

            print(f"Device {idx+1}. Mac = {mac_address}, auth_key = {auth_key}")

    def get_gps_data(self):
        agps_packs = ["AGPS_ALM", "AGPSZIP"]
        agps_file_names = ["cep_alm_pak.zip", "cep_7days.zip"]
        agps_link = "https://api-mifit-us2.huami.com/apps/com.huami.midong/fileTypes/{}/files"

        headers = {
            'apptoken': self.app_token,
        }

        for idx, agps_pack_name in enumerate(agps_packs):
            print("Downloading {}...".format(agps_pack_name))
            response = requests.get(agps_link.format(agps_pack_name), headers=headers)
            response.raise_for_status()
            agps_result = response.json()[0]
            if 'fileUrl' not in agps_result:
                raise ValueError("No 'fileUrl' parameter in files request.")
            with requests.get(agps_result['fileUrl'], stream=True) as r:
                with open(agps_file_names[idx], 'wb') as f:
                    shutil.copyfileobj(r.raw, f)

    def logout(self):
        logout_url = "https://account-us2.huami.com/v1/client/logout"
        data = {
            'login_token': self.login_token
        }
        response = requests.post(logout_url, data=data)
        logout_result = response.json()

        print(logout_result)
        if logout_result['result'] == 'ok':
            print("\nLogged out.")
        else:
            print("\nError logging out.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Obtain Bluetooth Auth key from Amazfit "
                                                 "servers and download AGPS data.")
    parser.add_argument("-m",
                        "--method",
                        choices=["amazfit", "xiaomi"],
                        default="amazfit",
                        required=True,
                        help="Login method ")
    parser.add_argument("-e",
                        "--email",
                        required=False,
                        help="Account e-mail address")
    parser.add_argument("-p",
                        "--password",
                        required=False,
                        help="Account Password")
    args = parser.parse_args()

    device = HuamiAmazfit(method=args.method,
                          email=args.email,
                          password=args.password)
    device.get_access_token()
    device.login()
    device.get_wearable_auth_keys()
    device.get_gps_data()
    device.logout()
