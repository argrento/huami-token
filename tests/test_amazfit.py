import os
import unittest
from huami_token import HuamiAmazfit

class TestAmazfit(unittest.TestCase):
    def test_login(self) -> None:
        email: str = os.environ.get('AMAZFIT_EMAIL', '')
        password: str = os.environ.get('AMAZFIT_PASSWORD', '')

        device = HuamiAmazfit(method="amazfit",
                              email=email,
                              password=password)
        access_token = device.get_access_token()
        user_id = device.login(external_token=access_token)
        logout_result = device.logout()
        print(user_id)

        self.assertEqual(user_id, 
                         "1132356262",
                         "Unexpected user id")

if __name__ == '__main__':
    unittest.main()
