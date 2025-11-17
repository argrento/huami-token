#!/usr/bin/env python3
"""Command line interface for huami-token.

This module will eventually replace the CLI functionality in src.py
as part of the project restructuring.
"""

import argparse
import getpass

import loguru

from .errors import MigrationInProgressError
from .zepp import Zepp


def main():
    """Main entry point for the CLI.

    Currently just imports and calls the original main function.
    This will be expanded later to follow the refactoring plan.
    """
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

    match args.method:
        case "amazfit":
            if args.password is None:
                args.password = getpass.getpass()
            device = Zepp(username=args.email, password=args.password)
            device.login()
        case "xiaomi":
            raise MigrationInProgressError()

    if args.bt_keys:
        device.get_devices()

    if args.gps:
        device.download_gps_data()

    if args.no_logout:
        print("\nNo logout!")
        print(f"app_token={device.app_token}\nlogin_token={device.login_token}")
    else:
        logout_result = device.logout()
        if logout_result == "ok":
            print("\nLogged out.")
        else:
            print("\nError logging out.")


if __name__ == "__main__":
    main()
