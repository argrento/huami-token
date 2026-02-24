#!/usr/bin/env python3
"""Command line interface for huami-token."""

import argparse
import getpass
import sys
from pathlib import Path

from .errors import HuamiTokenError, LogoutError
from .helpers import build_gps_uihh
from .xiaomi import XiaomiClient, XiaomiSession
from .zepp import ZeppClient, ZeppSession


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Obtain Bluetooth Auth key from Amazfit (Zepp) or Xiaomi Mi Fitness."
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

            case "xiaomi":
                if args.password is None:
                    args.password = getpass.getpass()
                xi_session = XiaomiSession(username=args.email, password=args.password)
                xi_session.login()

                if args.bt_keys:
                    xi_client = XiaomiClient(xi_session)
                    result = xi_client.get_source_list()
                    sources = result.get("result", {}).get("list") or []
                    if not sources:
                        print("No bound devices found.")
                    for i, source in enumerate(sources):
                        name = source.get("name", "Unknown").strip()
                        detail = source.get("detail", {})
                        if isinstance(detail, str):
                            import json
                            detail = json.loads(detail)
                        mac = detail.get("mac", source.get("mac", "??:??:??:??:??:??"))
                        auth_key = detail.get("auth_key", "")
                        print(f"Device {i}: {name}")
                        print(f"  MAC: {mac}")
                        if auth_key:
                            print(f"  Key: 0x{auth_key}")
                        else:
                            print("  Key: (not available)")

                if args.no_logout:
                    print("\nNo logout!")
                    print(f"ssecurity={xi_session.ssecurity}")
                    print(f"service_token={xi_session.service_token}")
                    print(f"user_id={xi_session.user_id}")
                    print(f"c_user_id={xi_session.c_user_id}")
                else:
                    print("\nLogged in successfully.")
                    print(f"user_id={xi_session.user_id}")

    except HuamiTokenError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
