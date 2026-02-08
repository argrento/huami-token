from huami_token.helpers import zepp_encrypt_payload, zepp_decrypt_payload


def test_zepp_encrypt_decrypt() -> None:
    key = b"xeNtBVqzDc6tuNTh"
    iv = b"MAAAYAAAAAAAAABg"

    raw_payload = (
        b"""emailOrPhone=a%40a.com&state=REDIRECTION&client_id=HuaMi&password=a&"""
        b"""redirect_uri=https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fhm-registration%2Fsuccesssignin.html&"""
        b"""region=us-west-2&token=access&token=refresh&country_code=US"""
    )

    captured_data = (
        b"""[\x06\x02\xa5R<L\x8f\xe0\xb0\xad\xb9\x87\xd6\x122\x0c\x18\xf9\x8cE\x84\xd1\xc8\x84\\\x04\x06\x8f4"""
        b"""\xa6\xb1VL\xf1\xb0"\x89\x94%\xfe\xa7w\xbc\x18(p\x85\xa2\x95\xdd\x1e4\xcc\xdb\xa9\x17\x98\x8f\xe9\t"""
        b"""Tn\xaa\x16\x9d\xd4\xc5\xd5\xa0\xf3\xe8,\x9e0,\x05\x0fMxI\x93]\xdf\xebc3\xed\x7fm\x0b\xb7\xf2N\xc5P"""
        b"""\x9fF\xed\xdb\xc6\x0f\xfd\xe7:\xaa\xf8\x913\x01\xbf\xd1i\x05ML\x940\t\xa88y\xcc\xcef7l\xb1\x8f\x95="""
        b"""\xacX\xef\xf6\xfc<w\xb53\xb7\x19\x11H\x9d\xa2F\xdf\xd8\xf1\xde\xcd\x8c\xcb\x9ejh\xeeCv\xc8%\x8cpm"""
        b"""\xf8\xfc\xfe\xcd\xfec;)z\xd7\x95V\x0f\xa8g?\xd5\xb8Onu\xd1\t>\xf5\x99\xb6\xa8|\xd3D\x987\xcac\xb5<"""
        b"""\xfd\xba\xdf\xec\xfe\x08\xba\x9c\xafe\xf9\x03Q\x1fM\x84\xa3\x883\x8f\xc4\xb6"""
    )

    encrypted_data = zepp_encrypt_payload(raw_payload, key, iv)
    decrypted_data = zepp_decrypt_payload(captured_data, key, iv)

    assert encrypted_data == captured_data
    assert raw_payload == decrypted_data
