#!/usr/bin/env python3
"""Command line interface for huami-token."""

import argparse
import getpass
import sys
from pathlib import Path

from .errors import HuamiTokenError, LogoutError, MigrationInProgressError
from .helpers import build_gps_uihh
from .zepp import ZeppClient, ZeppSession


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Obtain Bluetooth Auth key from Amazfit (Zepp). "
        "Currently only supports Amazfit.\nFor progress on Xiaomi support, see "
        "https://codeberg.org/argrento/huami-token/issues/119."
    )
    parser.add_argument(
        "-m",
        "--method",
        choices=["amazfit", "xiaomi"],
        default="amazfit",
        required=True,
        help="Login method. Chose Amazfit for Zepp.",
    )
    parser.add_argument("-e", "--email", required=False, help="Account e-mail address")
    parser.add_argument("-p", "--password", required=False, help="Account Password")
    parser.add_argument(
        "-b",
        "--bt_keys",
        required=False,
        action="store_true",
        help="Get bluetooth tokens of paired devices",
    )
    parser.add_argument(
        "-g",
        "--gps",
        required=False,
        action="store_true",
        help="Download GPS files (AGPS_ALM, AGPSZIP, LLE, etc.)",
    )
    parser.add_argument(
        "-n",
        "--no_logout",
        required=False,
        action="store_true",
        help="Do not logout, keep active session and "
        "display app token and access token",
    )

    args = parser.parse_args()

    try:
        match args.method:
            case "amazfit":
                if args.password is None:
                    args.password = getpass.getpass()
                session = ZeppSession(username=args.email, password=args.password)
                session.login()
                client = ZeppClient(session)
            case "xiaomi":
                raise MigrationInProgressError()

        if args.bt_keys:
            devices = client.get_devices()
            for i, device in enumerate(devices):
                active = "Yes" if device.active else "No"
                print(f"Device {i}:")
                print(f"  MAC: {device.mac}, Active: {active}")
                print(f"  Key: 0x{device.auth_key}")

        if args.gps:
            output_dir = Path.cwd()
            client.download_gps_data(output_dir)
            build_gps_uihh(base_folder=output_dir)

        if args.no_logout:
            print("\nNo logout!")
            print(f"app_token={session.app_token}\nlogin_token={session.login_token}")
        else:
            try:
                session.logout()
                print("\nLogged out.")
            except LogoutError:
                print("\nError logging out.")

    except MigrationInProgressError:
        raise
    except HuamiTokenError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
