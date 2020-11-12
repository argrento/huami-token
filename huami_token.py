#!/usr/bin/env python3
# pylint: disable=too-many-instance-attributes
# pylint: disable=invalid-name

"""Main module"""

import json
import uuid
import random
import shutil
import urllib
import argparse
import getpass
import requests

from rich.console import Console
from rich.table import Table
from rich import box

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
                raise ValueError("No 'country_code' parameter in login url.")

            self.access_token = redirect_url_parameters['access']
            self.country_code = redirect_url_parameters['country_code']

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

    def get_wearable_auth_keys(self) -> dict:
        """Request a list of linked devices"""
        print("Getting linked wearables...")

        devices_url = urls.URLS['devices'].format(user_id=urllib.parse.quote(self.user_id))

        headers = urls.PAYLOADS['devices']
        headers['apptoken'] = self.app_token

        response = requests.get(devices_url, headers=headers)
        response.raise_for_status()
        device_request = response.json()
        if 'items' not in device_request:
            raise ValueError("No 'items' parameter in devices data.")
        devices = device_request['items']

        devices_dict = {}

        for wearable in devices:
            if 'macAddress' not in wearable:
                raise ValueError("No 'macAddress' parameter in device data.")
            mac_address = wearable['macAddress']

            if 'additionalInfo' not in wearable:
                raise ValueError("No 'additionalInfo' parameter in device data.")
            device_info = json.loads(wearable['additionalInfo'])

            if 'auth_key' not in device_info:
                raise ValueError("No 'auth_key' parameter in device data.")
            key_str = device_info['auth_key']
            auth_key = '0x' + (key_str if key_str != '' else '00')

            devices_dict[f'{mac_address}'] = auth_key

        return devices_dict

    def get_gps_data(self) -> None:
        """Download GPS packs: almanac and AGPS"""
        agps_packs = ["AGPS_ALM", "AGPSZIP"]
        agps_file_names = ["cep_alm_pak.zip", "cep_7days.zip"]
        agps_link = urls.URLS['agps']

        headers = urls.PAYLOADS['agps']
        headers['apptoken'] = self.app_token

        for idx, agps_pack_name in enumerate(agps_packs):
            print("Downloading {}...".format(agps_pack_name))
            response = requests.get(agps_link.format(pack_name=agps_pack_name), headers=headers)
            response.raise_for_status()
            agps_result = response.json()[0]
            if 'fileUrl' not in agps_result:
                raise ValueError("No 'fileUrl' parameter in files request.")
            with requests.get(agps_result['fileUrl'], stream=True) as request:
                with open(agps_file_names[idx], 'wb') as gps_file:
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
    parser.add_argument("-a",
                        "--all",
                        required=False,
                        action='store_true',
                        help="Do everything: get bluetooth tokens, download A-GPS files")

    parser.add_argument("-n",
                        "--no_logout",
                        required=False,
                        action='store_true',
                        help="Do not logout, keep active session and "\
                             "display app token and access token")

    args = parser.parse_args()

    console = Console()
    table = Table(show_header=True, header_style="bold", box=box.ASCII)
    table.add_column("MAC", style="dim", width=17, justify='center')
    table.add_column("auth_key", width=50, justify='center')

    if args.password is None and args.method == "amazfit":
        args.password = getpass.getpass()

    device = HuamiAmazfit(method=args.method,
                          email=args.email,
                          password=args.password)
    device.get_access_token()
    device.login()

    if args.bt_keys or args.all:
        device_keys = device.get_wearable_auth_keys()
        for device_key in device_keys:
            table.add_row(device_key, device_keys[device_key])
        console.print(table)

    if args.gps or args.all:
        device.get_gps_data()

    if args.no_logout:
        print("\nNo logout!")
        print(f"app_token={device.app_token}\nlogin_token={device.login_token}")
    else:
        device.logout()
