Currently, this does not work due to API changes. More info: https://codeberg.org/argrento/huami-token/issues/119

Huami-token is now hosted on [codeberg.org](https://codeberg.org/argrento/huami-token/).

<a href="https://codeberg.org/argrento/huami-token/">
    <img alt="Get it on Codeberg" src="https://get-it-on.codeberg.org/get-it-on-white-on-black.png" height="60">
</a>


# Huami-token

[![status-badge](https://ci.codeberg.org/api/badges/argrento/huami-token/status.svg)](https://ci.codeberg.org/argrento/huami-token)

Script to obtain watch or band bluetooth access token from Zepp (Amazfit) or Xiaomi Mi Fitness servers.

## About

To use new versions of Amazfit and Xiaomi watches and bands with Gadgetbridge you need special unique key.
Read more here: https://gadgetbridge.org/basics/pairing/huami-xiaomi-server/.

## Community

If you would like to get in touch
* Matrix: [`#huami-token:matrix.org`](https://matrix.to/#/#huami-token:matrix.org)

## Installation

### From PyPI (currently outdated)

```bash
pip install huami-token
```

### From source

1. Ensure that you can login in the Zepp App with e-mail and password. If not, create new Amazfit account
with e-mail and password.
2. Pair, sync and update your watch with Zepp App. Your pairing key will be stored on
Huami servers.
3. Install `uv`: https://docs.astral.sh/uv/getting-started/installation/
4. Clone this repo and `cd` into it.
5. Install the package: `uv pip install -e ".[dev]"`

## Usage

After installation, the `huami-token` command is available:

```
usage: huami-token [-h] -m {amazfit,xiaomi} [-e EMAIL] [-p PASSWORD] [-b] [-g] [-n]

Obtain Bluetooth Auth key from Amazfit (Zepp) or Xiaomi Mi Fitness.

options:
  -h, --help            show this help message and exit
  -m {amazfit,xiaomi}, --method {amazfit,xiaomi}
                        Login method. Chose Amazfit for Zepp.
  -e EMAIL, --email EMAIL
                        Account e-mail address
  -p PASSWORD, --password PASSWORD
                        Account Password
  -b, --bt_keys         Get bluetooth tokens of paired devices
  -g, --gps             Download GPS files (AGPS_ALM, AGPSZIP, LLE, etc.)
  -n, --no_logout       Do not logout, keep active session and display app token and access token
```

You can also run directly via `python main.py` if you prefer not to install.

## Logging in with Amazfit account

Run with your credentials:

```bash
huami-token --method amazfit --email your_email@example.com --password your_password --bt_keys
```

Sample output:
```
2025-11-14 18:41:43.316 | INFO     | huami_token.zepp:login:67 - Logging in...
2025-11-14 18:41:44.268 | INFO     | huami_token.zepp:_get_refresh_and_access_tokens:120 - Received access and refresh tokens successfully
2025-11-14 18:41:45.217 | INFO     | huami_token.zepp:login:70 - Logged in! User id: 1234567890
2025-11-14 18:41:45.217 | INFO     | huami_token.zepp:get_devices:187 - Getting linked devices...
Device 0:
  MAC: AB:CD:EF:12:34:56, Active: Yes
  Key: 0xa3c10e34e5c14637eea6b9efc06106
2025-11-14 18:41:46.400 | INFO     | huami_token.zepp:logout:178 - Logged out.

Logged out.
```

Here the `Key` is the unique pairing key for your watch. The `Active` tab shows whether a device is
active or not.

## Logging in with Xiaomi account

```bash
huami-token --method xiaomi --email your_email@example.com --password your_password --bt_keys
```

Sample output:
```
2025-11-14 18:41:43.316 | INFO     | huami_token.xiaomi:login:81 - Logging in to Xiaomi...
2025-11-14 18:41:44.268 | INFO     | huami_token.xiaomi:login:85 - Logged in! User id: 1234567890
Device 0: Amazfit Band 7
  MAC: AB:CD:EF:12:34:56
  Key: 0xa3c10e34e5c14637eea6b9efc06106

Logged in successfully.
user_id=1234567890
```

Note: GPS download (`--gps`) is not yet supported for Xiaomi accounts.

## AGPS

This script can download AGPS files (requires login):

```bash
huami-token --method amazfit --email your_email@example.com --password your_password --gps
```

The following files are downloaded:
* AGPS_ALM -- `cep_1week.zip`
* AGPSZIP -- `cep_7days.zip`
* LLE -- `lle_1week.zip`
* AGPS -- `cep_pak.bin`
* EPO -- `EPO.ZIP`
* LTO -- LTO data file

## Development

```bash
uv pip install -e ".[dev]"

# Run tests
pytest -m "not integration"

# Lint
ruff check .

# Type check
mypy huami_token/

# Build wheel
uv build
```

## Dependencies

* Python >= 3.10
* requests
* loguru
* pycryptodome

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
