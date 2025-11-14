Huami-token is now hosted on [codeberg.org](https://codeberg.org/argrento/huami-token/).

<a href="https://codeberg.org/argrento/huami-token/">
    <img alt="Get it on Codeberg" src="https://get-it-on.codeberg.org/get-it-on-white-on-black.png" height="60">
</a>


# Huami-token (Redesign in progress)

[![status-badge](https://ci.codeberg.org/api/badges/argrento/huami-token/status.svg)](https://ci.codeberg.org/argrento/huami-token)

Script to obtain watch or band bluetooth access token from Zepp (Amazfit) servers. 
For progress on Xiaomi support, see https://codeberg.org/argrento/huami-token/issues/119.

## About

To use new versions of Amazfit and Xiaomi watches and bands with Gadgetbridge you need special unique key.
Read more here: https://codeberg.org/Freeyourgadget/Gadgetbridge/wiki/Huami-Server-Pairing.

## Community

If you would like to get in touch 
* Matrix: [`#huami-token:matrix.org`](https://matrix.to/#/#huami-token:matrix.org)

## Preparation

1. Ensure that you can login in the Zepp App with e-mail and password. If not, create new Amazfit account
with e-mail and password.
2. Pair, sync and update your watch with Zepp App. Your pairing key will be stored on
Huami servers.
3. Install `uv`: https://docs.astral.sh/uv/getting-started/installation/
4. Download this repo.
5. Go to the source directory.
6. Create virtual environment: `uv venv`
7. Activate environment: `source .venv/bin/activate`
8. Install dependencies: `uv pip install -e ".[dev]"`

## Usage
```
usage: main.py [-h] -m {amazfit,xiaomi} [-e EMAIL] [-p PASSWORD] [-b] [-n]

Obtain Bluetooth Auth key from Amazfit (Zepp). Currently only supports Amazfit. For progress on Xiaomi support, see https://codeberg.org/argrento/huami-token/issues/119.

options:
  -h, --help            show this help message and exit
  -m {amazfit,xiaomi}, --method {amazfit,xiaomi}
                        Login method. Chose Amazfit for Zepp.
  -e EMAIL, --email EMAIL
                        Account e-mail address
  -p PASSWORD, --password PASSWORD
                        Account Password
  -b, --bt_keys         Get bluetooth tokens of paired devices
  -n, --no_logout       Do not logout, keep active session and display app token and access token
```


## Logging in with Amazfit account
Run script with your credentials: `python3 huami_token.py --method amazfit --email youemail@example.com --password your_password --bt_keys`.

Sample output:
```bash
> python3 src.py --method amazfit --email my_email --password password --bt_keys
2025-11-14 18:41:43.316 | INFO     | src.zepp:login:48 - Logging in...
2025-11-14 18:41:44.268 | INFO     | src.zepp:_get_refresh_and_access_tokens:108 - Received access and refresh tokens successfully
2025-11-14 18:41:45.217 | INFO     | src.zepp:login:51 - Logged in! User id: 1234567890
2025-11-14 18:41:45.217 | INFO     | src.zepp:get_devices:151 - Getting linked devices...
2025-11-14 18:41:45.504 | INFO     | src.zepp:get_devices:190 - Device 0:
2025-11-14 18:41:45.504 | INFO     | src.zepp:get_devices:191 - MAC: AB:CD:EF:12:34:56, Active: Yes
2025-11-14 18:41:45.504 | INFO     | src.zepp:get_devices:192 - Key: 0xa3c10e34e5c14637eea6b9efc06106
2025-11-14 18:41:46.400 | INFO     | src.zepp:logout:219 - Logged out.

```

Here the `Key` is the unique pairing key for your watch. The `Active` tab shows whether a device is
active or not.

## Logging in with Xiaomi account
This is not yet reimplemented.

## Experimental: updates download
This is not yet reimplemented.


## Dependencies

* Python 3.7.7
* argparse
* requests
* loguru
* pycryptodome

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
