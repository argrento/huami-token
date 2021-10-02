#!/usr/bin/env python3
# pylint: disable=too-many-instance-attributes
# pylint: disable=invalid-name

# Copyright (c) 2020 Kirill Snezhko

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

"""Main module"""

import argparse
import getpass
import json
import random
import shutil
import urllib
import uuid

import requests
from rich import box
from rich.console import Console
from rich.table import Table

import urls


class HuamiAmazfit:
    """Base class for logging in and receiving auth keys and GPS packs"""
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

    def get_access_token(self) -> str:
        """Get access token for log in"""
        print(f"Getting access token with {self.method} login method...")

        if self.method == 'xiaomi':
            login_url = urls.URLS["login_xiaomi"]

            print(f"Copy this URL to web-browser \n\n{login_url}\n\nand login to your Mi account.")

            token_url = input("\nPaste URL after redirection here.\n")

            parsed_token_url = urllib.parse.urlparse(token_url)
            token_url_parameters = urllib.parse.parse_qs(parsed_token_url.query)

            if 'code' not in token_url_parameters:
                raise ValueError("No 'code' parameter in login url.")

            self.access_token = token_url_parameters['code']
            self.country_code = 'US'

        elif self.method == 'amazfit':

            auth_url = urls.URLS['tokens_amazfit'].format(user_email=urllib.parse.quote(self.email))

            data = urls.PAYLOADS['tokens_amazfit']
            data['password'] = self.password

            response = requests.post(auth_url, data=data, allow_redirects=False)
            response.raise_for_status()

            # 'Location' parameter contains url with login status
            redirect_url = urllib.parse.urlparse(response.headers.get('Location'))
            redirect_url_parameters = urllib.parse.parse_qs(redirect_url.query)

            if 'error' in redirect_url_parameters:
                raise ValueError(f"Wrong E-mail or Password." \
                                 f"Error: {redirect_url_parameters['error']}")

            if 'access' not in redirect_url_parameters:
                raise ValueError("No 'access' parameter in login url.")

            if 'country_code' not in redirect_url_parameters:
                # Sometimes for no reason server does not return country_code
                # In this case we extract country_code from region, because it looks
                # like this: 'eu-central-1'
                region = redirect_url_parameters['region'][0]
                self.country_code = region[0:2].upper()

            else:
                self.country_code = redirect_url_parameters['country_code']

            self.access_token = redirect_url_parameters['access']

        print("Token: {}".format(self.access_token))
        return self.access_token

    def login(self, external_token=None) -> None:
        """Perform login and get app and login tokens"""
        print("Logging in...")
        if external_token:
            self.access_token = external_token

        login_url = urls.URLS['login_amazfit']

        data = urls.PAYLOADS['login_amazfit']
        data['country_code'] = self.country_code
        data['device_id'] = self.device_id
        data['third_name'] = 'huami' if self.method == 'amazfit' else 'mi-watch'
        data['code'] = self.access_token
        data['grant_type'] = 'access_token' if self.method == 'amazfit' else 'request_token'

        response = requests.post(login_url, data=data, allow_redirects=False)
        response.raise_for_status()
        login_result = response.json()

        if 'error_code' in login_result:
            raise ValueError(f"Login error. Error: {login_result['error_code']}")

        if 'token_info' not in login_result:
            raise ValueError("No 'token_info' parameter in login data.")
        # else
        # Do not need else, because raise breaks control flow
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

    def get_wearables(self) -> dict:
        """Request a list of linked devices"""
        print("Getting linked wearables...")

        devices_url = urls.URLS['devices'].format(user_id=urllib.parse.quote(self.user_id))

        headers = urls.PAYLOADS['devices']
        headers['apptoken'] = self.app_token
        params = {'enableMultiDevice': 'true'}

        response = requests.get(devices_url, params=params, headers=headers)
        response.raise_for_status()
        device_request = response.json()
        if 'items' not in device_request:
            raise ValueError("No 'items' parameter in devices data.")
        devices = device_request['items']

        _wearables = []

        for _wearable in devices:
            if 'macAddress' not in _wearable:
                raise ValueError("No 'macAddress' parameter in device data.")
            mac_address = _wearable['macAddress']

            if 'additionalInfo' not in _wearable:
                raise ValueError("No 'additionalInfo' parameter in device data.")
            device_info = json.loads(_wearable['additionalInfo'])

            key_str = device_info.get('auth_key', '')
            auth_key = '0x' + (key_str if key_str != '' else '00')

            _wearables.append(
                {
                    'active_status': str(_wearable.get('activeStatus', '-1')),
                    'mac_address': mac_address,
                    'auth_key': auth_key,
                    'device_source': str(_wearable.get('deviceSource', 0)),
                    'firmware_version': _wearable.get('firmwareVersion', 'v-1'),
                    'hardware_version': device_info.get('hardwareVersion', 'v-1'),
                    'production_source': device_info.get('productVersion', '0')
                }
            )

        return _wearables

    @staticmethod
    def get_firmware(_wearable: dict) -> None:
        """Check and download updates for the furmware and fonts"""
        fw_url = urls.URLS["fw_updates"]
        params = urls.PAYLOADS["fw_updates"]
        params['deviceSource'] = _wearable['device_source']
        params['firmwareVersion'] = _wearable['firmware_version']
        params['hardwareVersion'] = _wearable['hardware_version']
        params['productionSource'] = _wearable['production_source']
        headers = {
           'appplatform': 'android_phone',
            'appname': 'com.huami.midong',
            'lang': 'en_US'
        }
        response = requests.get(fw_url, params=params, headers=headers)
        response.raise_for_status()
        fw_response = response.json()
        links = []
        hashes = []

        if 'firmwareUrl' in fw_response:
            links.append(fw_response['firmwareUrl'])
            hashes.append(fw_response['firmwareMd5'])
        if 'fontUrl' in fw_response:
            links.append(fw_response['fontUrl'])
            hashes.append(fw_response['fontMd5'])

        if not links:
            print("No updates found!")
        else:
            for link, hash_sum in zip(links, hashes):
                file_name = link.split('/')[-1]
                print(f"Downloading {file_name} with MD5-hash {hash_sum}...")
                with requests.get(link, stream=True) as r:
                    with open(file_name, 'wb') as f:
                        shutil.copyfileobj(r.raw, f)

    def get_gps_data(self) -> None:
        """Download GPS packs: almanac and AGPS"""
        agps_packs = ["AGPS_ALM", "AGPSZIP", "LLE", "AGPS"]
        agps_file_names = ["cep_1week.zip", "cep_7days.zip", "lle_1week.zip", "cep_pak.bin"]
        agps_link = urls.URLS['agps']

        headers = urls.PAYLOADS['agps']
        headers['apptoken'] = self.app_token

        for pack_idx, agps_pack_name in enumerate(agps_packs):
            print(f"Downloading {agps_pack_name}...")
            response = requests.get(agps_link.format(pack_name=agps_pack_name), headers=headers)
            response.raise_for_status()
            agps_result = response.json()[0]
            if 'fileUrl' not in agps_result:
                raise ValueError("No 'fileUrl' parameter in files request.")
            with requests.get(agps_result['fileUrl'], stream=True) as request:
                with open(agps_file_names[pack_idx], 'wb') as gps_file:
                    shutil.copyfileobj(request.raw, gps_file)

    def logout(self) -> None:
        """Log out from the current account"""
        logout_url = urls.URLS['logout']

        data = urls.PAYLOADS['logout']
        data['login_token'] = self.login_token

        response = requests.post(logout_url, data=data)
        logout_result = response.json()

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

    parser.add_argument("-b",
                        "--bt_keys",
                        required=False,
                        action='store_true',
                        help="Get bluetooth tokens of paired devices")

    parser.add_argument("-g",
                        "--gps",
                        required=False,
                        action='store_true',
                        help="Download A-GPS files")

    parser.add_argument("-f",
                        "--firmware",
                        required=False,
                        action='store_true',
                        help='Request firmware updates. Works only with -b/--bt_keys argument. '
                             'Extremely dangerous!')

    parser.add_argument("-a",
                        "--all",
                        required=False,
                        action='store_true',
                        help="Do everything: get bluetooth tokens, download A-GPS files. But "
                             "do NOT download firmware updates")

    parser.add_argument("-n",
                        "--no_logout",
                        required=False,
                        action='store_true',
                        help="Do not logout, keep active session and "\
                             "display app token and access token")

    args = parser.parse_args()

    console = Console()
    table = Table(show_header=True, header_style="bold", box=box.ASCII)
    table.add_column("ID", width=3, justify='center')
    table.add_column("ACT", width=3, justify='center')
    table.add_column("MAC", style="dim", width=17, justify='center')
    table.add_column("auth_key", width=45, justify='center')

    if args.firmware and not args.bt_keys:
        parser.error("Can not use -f/--firmware without -b/--bt_keys!")

    if args.password is None and args.method == "amazfit":
        args.password = getpass.getpass()

    device = HuamiAmazfit(method=args.method,
                          email=args.email,
                          password=args.password)
    device.get_access_token()
    device.login()

    wearables = []
    if args.bt_keys or args.all:
        wearables = device.get_wearables()
        for idx, wearable in enumerate(wearables):
            table.add_row(str(idx), wearable['active_status'],
                          wearable['mac_address'], wearable['auth_key'])
        console.print(table)

    if args.firmware:
        print("Downloading the firmware is untested and can brick your device. "
              "I am not responsible for any problems that might arise.")
        answer = input("Do you want to proceed? [yes/no] ")
        if answer.lower() in ['yes', 'y', 'ye']:
            wearable_id = input("ID of the device to check for updates (-1 for all of them): ")
            if wearable_id == "-1":
                print("Be extremely careful with downloaded files!")
                for idx, wearable in enumerate(wearables):
                    print(f"\nChecking for device {idx}...")
                    device.get_firmware(wearable)
            elif int(wearable_id) in range(0, len(wearables)):
                device.get_firmware(wearables[int(wearable_id)])
            else:
                print("Wrong input!")


    if args.gps or args.all:
        device.get_gps_data()

    if args.no_logout:
        print("\nNo logout!")
        print(f"app_token={device.app_token}\nlogin_token={device.login_token}")
    else:
        device.logout()
