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
import urllib.parse
import uuid
from typing import Tuple, Dict, Union, Any, List
import zipfile
import zlib

import requests

import errors
import urls

def encode_uint32(value: int) -> bytes:
    """Convert 4-bytes value into a list with 4 bytes"""
    return bytes([value & 0xff]) + bytes([(value >> 8) & 0xff]) + \
        bytes([(value >> 16) & 0xff]) + bytes([(value >> 24) & 0xff])

class HuamiAmazfit:
    """Base class for logging in and receiving auth keys and GPS packs"""
    def __init__(self, method: str = "amazfit", email: str = "", password: str = "") -> None:

        if method == 'amazfit' and (not email or not password):
            raise ValueError("For Amazfit method E-Mail and Password can not be null.")
        self.method: str = method
        self.email: str = email
        self.password: str = password
        self.access_token: str = ""
        self.country_code: str = ""

        self.app_token: str = ""
        self.login_token: str = ""
        self.user_id: str = ""

        self.r = str(uuid.uuid4())

        # IMEI or something unique
        self.device_id = (
            f"02:00:00:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:"
            f"{random.randint(0, 255):02x}"
        )


    def get_access_token(self) -> str:
        """Get access token for log in"""

        if self.method == 'xiaomi':
            login_url = urls.URLS["login_xiaomi"]

            print(f"Copy this URL to web-browser \n\n{login_url}\n\nand login to your Mi account.")

            token_url = input("\nPaste URL after redirection here.\n")

            parsed_token_url = urllib.parse.urlparse(token_url)
            token_url_parameters = urllib.parse.parse_qs(parsed_token_url.query)

            if 'code' not in token_url_parameters:
                raise ValueError("No 'code' parameter in login url.")

            self.access_token = token_url_parameters['code'][0]
            self.country_code = 'US'

        elif self.method == 'amazfit':

            auth_url = urls.URLS['tokens_amazfit'].format(user_email=urllib.parse.quote(self.email))

            data = urls.PAYLOADS['tokens_amazfit']
            data['password'] = self.password

            response = requests.post(auth_url, data=data, allow_redirects=False, timeout=10)
            response.raise_for_status()

            # 'Location' parameter contains url with login status
            redirect_url = urllib.parse.urlparse(response.headers.get('Location'))
            redirect_url_parameters = urllib.parse.parse_qs(str(redirect_url.query))

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
                self.country_code = redirect_url_parameters['country_code'][0]

            self.access_token = redirect_url_parameters['access'][0]
        return self.access_token

    def login(self, external_token: str = "") -> str:
        """Perform login and get app and login tokens"""
        if external_token:
            self.access_token = external_token

        login_url = urls.URLS['login_amazfit']

        data: Dict[str, str] = urls.PAYLOADS['login_amazfit']
        data['country_code'] = self.country_code
        data['device_id'] = self.device_id
        data['third_name'] = 'huami' if self.method == 'amazfit' else 'mi-watch'
        data['code'] = self.access_token
        data['grant_type'] = 'access_token' if self.method == 'amazfit' else 'request_token'

        response = requests.post(login_url, data=data, allow_redirects=False, timeout=10)
        response.raise_for_status()
        login_result = response.json()

        if 'error_code' in login_result:
            error_code = login_result['error_code']
            error_message = errors.ERRORS.get(error_code, error_code)
            raise ValueError(f"Login error. Error: {error_message}")

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
        return self.user_id

    def get_wearables(self) -> List[Dict[str, Any]]:
        """Request a list of linked devices"""
        devices_url = urls.URLS['devices'].format(user_id=urllib.parse.quote(self.user_id))

        headers = urls.PAYLOADS['devices']
        headers['apptoken'] = self.app_token
        params = {'enableMultiDevice': 'true'}

        response = requests.get(devices_url, params=params, headers=headers, timeout=10)
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
    def get_firmware(_wearable: Dict[str, str]) -> Tuple[List[str], List[str]]:
        """Check and download updates for the furmware and fonts"""
        fw_url = urls.URLS["fw_updates"]
        params: Dict[str, Union[str, Any]] = urls.PAYLOADS["fw_updates"]
        params['deviceSource'] = _wearable['device_source']
        params['firmwareVersion'] = _wearable['firmware_version']
        params['hardwareVersion'] = _wearable['hardware_version']
        params['productionSource'] = _wearable['production_source']
        headers = {
           'appplatform': 'android_phone',
            'appname': 'com.huami.midong',
            'lang': 'en_US'
        }
        response = requests.get(fw_url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        fw_response = response.json()
        fw_links = []
        fw_hashes = []

        if 'firmwareUrl' in fw_response:
            fw_links.append(fw_response['firmwareUrl'])
            fw_hashes.append(fw_response['firmwareMd5'])
        if 'fontUrl' in fw_response:
            fw_links.append(fw_response['fontUrl'])
            fw_hashes.append(fw_response['fontMd5'])

        return (fw_links, fw_hashes)

    def get_gps_data(self) -> None:
        """Download GPS packs: almanac and AGPS"""
        agps_packs = ["AGPS_ALM", "AGPSZIP", "LLE", "AGPS"]
        agps_file_names = ["cep_1week.zip", "cep_7days.zip", "lle_1week.zip", "cep_pak.bin"]
        agps_link = urls.URLS['agps']

        headers = urls.PAYLOADS['agps']
        headers['apptoken'] = self.app_token

        for pack_idx, agps_pack_name in enumerate(agps_packs):
            print(f"Downloading {agps_pack_name}...")
            response = requests.get(agps_link.format(pack_name=agps_pack_name),
                headers=headers, timeout=10)
            response.raise_for_status()
            agps_result = response.json()[0]
            if 'fileUrl' not in agps_result:
                raise ValueError("No 'fileUrl' parameter in files request.")
            with requests.get(agps_result['fileUrl'], stream=True, timeout=10) as request:
                with open(agps_file_names[pack_idx], 'wb') as gps_file:
                    shutil.copyfileobj(request.raw, gps_file)

    def build_gps_uihh(self) -> None:
        """ Prepare uihh gps file """
        print("Building gps_uihh.bin")
        d = {'gps_alm.bin':0x05, 'gln_alm.bin':0x0f, 'lle_bds.lle':0x86, 'lle_gps.lle':0x87,
             'lle_glo.lle':0x88, 'lle_gal.lle':0x89, 'lle_qzss.lle':0x8a}
        with zipfile.ZipFile('cep_7days.zip', 'r') as cep_archive, \
            zipfile.ZipFile('lle_1week.zip', 'r') as lle_archive, \
            open('gps_uihh.bin', 'wb') as uihh_file:
            content = bytes()
            filecontent = bytes()
            fileheader = bytes()

            for key, value in d.items():
                if value >= 0x86:
                    filecontent = lle_archive.read(key)
                else:
                    filecontent = cep_archive.read(key)

                fileheader = bytes([1]) + bytes([value]) + encode_uint32(len(filecontent)) + \
                    encode_uint32(zlib.crc32(filecontent) & 0xffffffff)
                content += fileheader + filecontent

            header = b'UIHH' + \
                bytes([0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]) + \
                encode_uint32(zlib.crc32(content) & 0xffffffff) + \
                bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + \
                encode_uint32(len(content)) + \
                bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

            content = header + content
            uihh_file.write(content)

    def logout(self) -> str:
        """Log out from the current account"""
        logout_url = urls.URLS['logout']

        data = urls.PAYLOADS['logout']
        data['login_token'] = self.login_token

        response = requests.post(logout_url, data=data, timeout=10)
        result = str(response.json()['result'])
        return result


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

    if args.firmware and not args.bt_keys:
        parser.error("Can not use -f/--firmware without -b/--bt_keys!")

    if args.password is None and args.method == "amazfit":
        args.password = getpass.getpass()

    device = HuamiAmazfit(method=args.method,
                          email=args.email,
                          password=args.password)

    print(f"Getting access token with '{args.method}' login method...")
    access_token = device.get_access_token()
    print(f"Token: {access_token}")

    print("Logging in...")
    user_id = device.login(external_token=access_token)
    print(f"Logged in! User id: {user_id}")

    print("Getting linked wearables...")
    wearables = []
    if args.bt_keys or args.all:
        wearables = device.get_wearables()
        footer = "\u2559" + "\u2500" * 12
        for idx, wearable in enumerate(wearables):
            print(f"\n\u2553\u2500\u2500\u2500Device {idx}")
            is_active = "Yes" if wearable['active_status'] == '1' else "No"
            print(f"\u2551  MAC: {wearable['mac_address']}, active: {is_active}")
            print(f"\u2551  Key: {wearable['auth_key']}")
            print(footer)

    if args.gps or args.all:
        device.get_gps_data()
        device.build_gps_uihh()

    if args.firmware:
        footer = "\u2559" + "\u2500" * 12
        print("\nDownloading the firmware is untested and can brick your device. "
              "I am not responsible for any problems that might arise.")
        answer = input("Do you want to proceed? [yes/no] ")
        if answer.lower() in ['yes', 'y', 'ye']:
            wearable_id = int(input("ID of the device to check for updates (-1 for all of them): "))
            print("Be extremely careful with downloaded files!")

            for idx, wearable in enumerate(wearables):
                if wearable_id in (idx, -1):
                    print(f"\n\u2553\u2500\u2500\u2500Device {idx}")
                    links, hashes = device.get_firmware(wearables[int(idx)])
                    if links:
                        for link, hash_sum in zip(links, hashes):
                            file_name = link.split('/')[-1]
                            print(f"\u2551  File: {file_name}")
                            print(f"\u2551  Hash: {hash_sum}")
                            with requests.get(link, stream=True, timeout=10) as r:
                                with open(file_name, 'wb') as f:
                                    shutil.copyfileobj(r.raw, f)
                    else:
                        print("\u2551  No updates found")
                    print(footer)

    if args.no_logout:
        print("\nNo logout!")
        print(f"app_token={device.app_token}\nlogin_token={device.login_token}")
    else:
        logout_result = device.logout()
        if logout_result == 'ok':
            print("\nLogged out.")
        else:
            print("\nError logging out.")
