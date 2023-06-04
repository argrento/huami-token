import os
import unittest
from huami_token import HuamiAmazfit
import pytest

class TestMifitness(unittest.TestCase):
    @pytest.mark.skipif(os.environ.get('LIMITED_ENV', '0') == '1',
                        reason="Skipped due to limited environment: test can require 2FA.")
    def test_login(self) -> None:
        email: str = os.environ.get('MIFITNESS_EMAIL', '')
        password: str = os.environ.get('MIFITNESS_PASSWORD', '')

        device = HuamiAmazfit(method="mifitness",
                              email=email,
                              password=password)
        access_token = device.get_access_token()
        user_id = device.login(external_token=access_token)
        print(user_id)

        self.assertEqual(user_id,
                         8205585008,
                         "Unexpected user id")

if __name__ == '__main__':
    unittest.main()
