URLS = {
    'login_xiaomi': 'https://account.xiaomi.com/oauth2/authorize?skip_confirm=false&'
                    'client_id=2882303761517383915&pt=0&scope=1+6000+16001+20000&'
                    'redirect_uri=https%3A%2F%2Fhm.xiaomi.com%2Fwatch.do&_locale=en_US&response_type=code',
    'tokens_amazfit': 'https://api-user.huami.com/registrations/{user_email}/tokens',
    'login_amazfit': 'https://account.huami.com/v2/client/login',
    'devices': 'https://api-mifit-us2.huami.com/users/{user_id}/devices',
    'agps': 'https://api-mifit-us2.huami.com/apps/com.huami.midong/fileTypes/{pack_name}/files',
    'data_short': 'https://api-mifit-us2.huami.com/users/{user_id}/deviceTypes/4/data',
    'logout': 'https://account-us2.huami.com/v1/client/logout'
}

PAYLOADS = {
    'login_xiaomi': None,
    'tokens_amazfit': {
        'state':        'REDIRECTION',
        'client_id':    'HuaMi',
        'password':     None,
        'redirect_uri': 'https://s3-us-west-2.amazonws.com/hm-registration/successsignin.html',
        'region':       'us-west-2',
        'token':        'access',
        'country_code': 'US'
    },
    'login_amazfit': {
        'dn':                 'account.huami.com,api-user.huami.com,app-analytics.huami.com,api-watch.huami.com,'
                              'api-analytics.huami.com,api-mifit.huami.com',
        'app_version':        '4.3.0-play',
        'source':             'com.huami.watch.hmwatchmanager',
        'country_code':       None,
        'device_id':          None,
        'third_name':         None,
        'lang':               'en',
        'device_model':       'android_phone',
        'allow_registration': 'false',
        'app_name':           'com.huami.midong',
        'code':               None,
        'grant_type':         None
    },
    'devices': {
        'apptoken': None
    },
    'agps': {
        'apptoken': None
    },
    'data_short': {
        'apptoken': None,
        'startDay': None,
        'endDay': None
    },
    'logout': {
        'login_token': None
    },
}