Huami-token is now hosted on [codeberg.org](https://codeberg.org/argrento/huami-token/).

<a href="https://codeberg.org/argrento/huami-token/">
    <img alt="Get it on Codeberg" src="https://get-it-on.codeberg.org/get-it-on-white-on-black.png" height="60">
</a>


# Huami-token

[![status-badge](https://ci.codeberg.org/api/badges/argrento/huami-token/status.svg)](https://ci.codeberg.org/argrento/huami-token)

Script to obtain watch or band bluetooth access token from Huami servers.
It will also download AGPS data packs `cep_alm_pak.zip` and `cep_7days.zip`.

## About

To use new versions of Amazfit and Xiaomi watches and bands with Gadgetbridge you need special unique key.
Read more here: https://codeberg.org/Freeyourgadget/Gadgetbridge/wiki/Huami-Server-Pairing.

## Preparation

1. Ensure that you login in Amazfit App with Amazfit or Xiaomi account --
because only this login methods are supported. If not, create new Amazfit account
with e-mail and password.
2. Pair, sync and update your watch with Amazfit App. Your pairing key will be stored on
Huami servers.
3. Clone this repo:
```git clone https://codeberg.org/argrento/huami-token.git```
4. Install requirements: `pip3 install -r requirements.txt`

## Usage
```
usage: huami_token.py [-h] -m {amazfit,xiaomi} [-e EMAIL] [-p PASSWORD] [-b]
                      [-g] [-a] [-n]

Obtain Bluetooth Auth key from Amazfit servers and download AGPS data.

optional arguments:
  -h, --help            show this help message and exit
  -m {amazfit,xiaomi}, --method {amazfit,xiaomi}
                        Login method
  -e EMAIL, --email EMAIL
                        Account e-mail address
  -p PASSWORD, --password PASSWORD
                        Account Password
  -b, --bt_keys         Get bluetooth tokens of paired devices
  -g, --gps             Download A-GPS files
  -f, --firmware        Request firmware updates. Works only with -b/--bt_keys
                        argument. Extremely dangerous
  -a, --all             Do everything: get bluetooth tokens, download A-GPS
                        files. But do NOT download firmware updates
  -n, --no_logout       Do not logout, keep active session and display app
                        token and access token
```


## Logging in with Amazfit account
Run script with your credentials: `python3 huami_token.py --method amazfit --email youemail@example.com --password your_password --bt_keys`.

Sample output:
```bash
> python3 huami_token.py --method amazfit --email my_email --password password --bt_keys
Getting access token with amazfit login method...
Token: ['UaFHW53RJVYwqXaa7ncPQ']
Logging in...
Logged in! User id: 1234567890
Getting linked wearables...

╓───Device 0
║  MAC: AB:CD:EF:12:34:56, active: Yes
║  Key: 0xa3c10e34e5c14637eea6b9efc06106
╙────────────

Logged out.
```

Here the `auth_key` is the unique pairing key for your watch. The `ACT` tab shows whether a device is
active or not.

### Logging in with Xiaomi account
This is a little bit harder to use, since you need to login manually on the Xiaomi web site.

1. Run script `python3 huami_token.py --method xiaomi --bt_keys`.
2. Script will ask you to open Xiaomi login web page. https://account.xiaomi.com/oauth2/authorize?skip_confirm=false&client_id=2882303761517383915&pt=0&scope=1+6000+16001+20000&redirect_uri=https%3A%2F%2Fhm.xiaomi.com%2Fwatch.do&_locale=en_US&response_type=code
3. Login with your credentials there.
4. If your login is successful, browser will show the error that connection is not secured.
On this stage address will look like this: `https://hm.xiaomi.com/watch.do?code=ALSG_CLOUDSRV_9B8D87D0EB77C71B45FF73B2266D922B`.
5. Copy this address.
6. Return to script, paste this address and press `enter`.

Sample output:
```bash
> python3 huami_token.py --method xiaomi --bt_keys
Getting access token with xiaomi login method...
Copy this URL to web-browser

https://account.xiaomi.com/oauth2/authorize?skip_confirm=false&client_id=2882303761517383915&pt=0&scope=1+6000+16001+20000&redirect_uri=https%3A%2F%2Fhm.xiaomi.com%2Fwatch.do&_locale=en_US&response_type=code

and login to your Mi account.

Paste URL after redirection here.
https://hm.xiaomi.com/watch.do?code=ALSG_CLOUDSRV_9B8D87D0EB77C71B45FF73B2266D922B
Token: ['ALSG_CLOUDSRV_9B8D87D0EB77C71B45FF73B2266D922B']
Logging in...
Logged in! User id: 3000654321
Getting linked wearables...

╓───Device 0
║  MAC: 12:34:56:AB:CD:EF, active: Yes
║  Key: 0x3c10e34e5c1463527579996fa83e6d
╙────────────

╓───Device 1
║  MAC: BA:DC:FE:21:43:65, active: No
║  Key: 0x00
╙────────────

Logged out.
```

Here the `auth_key` is the unique pairing key for your watch. The `ACT` tab shows whether a device is
active or not.

In this example I have two devices: the first one is my Amazfit Bip S watch,
the second one is my Xiaomi Mi Smart Scale.

## Experimental: updates download

This is extremely dangerous: flashing the wrong version can brick your device!
I am not responsible for any of problems that might arise.

Can be enabled with `-f/--firmware` argument. Will work only with `-b/--bt_keys` argument.
You should input the ID of a device, or `-1` to check for all.
Script will try to find updates for the firmware and the font pack for the device from 
the table above.

Use the downloaded files at your own risk!

## Dependencies

* Python 3.7.7
* argparse
* requests
* urllib
* random
* uuid
* json
* shutil

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
