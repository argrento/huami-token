from urllib.parse import unquote

from huami_token.mi_crypto import (
    compute_signing_path,
    generate_nonce,
    mi_decrypt_params,
    mi_decrypt_response,
    mi_encrypt_params,
)

SSECURITY = "YrTdzxpoL2f5MVGlER9E8w=="


def test_decrypt_response() -> None:
    nonce = unquote("R42d%2B0k3e1wBv42r")
    body = "DPGjfdGeLhOcEauyRBJHKM845nz2j9E2TTStMnWkp4bRnqLLUVfXnpEn7jHaRzCqyjNaNaKWbETueJbGRFA="
    result = mi_decrypt_response(body, nonce, SSECURITY)
    assert result == '{"code":0,"message":"ok","result":{"datas":null,"last_id":-1}}'


def test_decrypt_params() -> None:
    nonce = unquote("R42d%2B0k3e1wBv42r")
    decrypted = mi_decrypt_params(
        {
            "data": unquote(
                "DPGke9HZNgvUVOiwTAhDLMkvmyekkJg4Q3q%2BJHKOopbRnunFF1rKkotx9mWdG3Ckh"
                "TBfM7qsJxruJt6BUE5lyIr%2BqsjYUDgvkGZinSG8hS97q4Y6VMZso%2BA%3D"
            ),
            "rc4_hash__": unquote("QPhJ2ehekyhADdflTzZv3o7f0qeW0%2BRdOZSFjA%3D%3D"),
        },
        nonce,
        SSECURITY,
    )
    assert decrypted["data"] == (
        '{"did":"xiaomiwear_app","last_id":0,"limit":20,'
        '"module":"device_setting","update_time":0}'
    )


def test_encrypt_matches_captured_traffic() -> None:
    """Verify encrypted output matches byte-for-byte with captured traffic."""
    nonce = unquote("R42d%2B0k3e1wBv42r")

    result = mi_encrypt_params(
        "POST",
        "/setting/get_user_device_settings",
        {
            "data": (
                '{"did":"xiaomiwear_app","last_id":0,"limit":20,'
                '"module":"device_setting","update_time":0}'
            )
        },
        nonce,
        SSECURITY,
    )

    captured_data = unquote(
        "DPGke9HZNgvUVOiwTAhDLMkvmyekkJg4Q3q%2BJHKOopbRnunFF1rKkotx9mWdG3Ckh"
        "TBfM7qsJxruJt6BUE5lyIr%2BqsjYUDgvkGZinSG8hS97q4Y6VMZso%2BA%3D"
    )
    captured_rc4_hash = unquote("QPhJ2ehekyhADdflTzZv3o7f0qeW0%2BRdOZSFjA%3D%3D")

    assert result["data"] == captured_data
    assert result["rc4_hash__"] == captured_rc4_hash


def test_encrypt_decrypt_roundtrip() -> None:
    nonce = generate_nonce()
    plaintext = {"data": '{"test":"value","num":42}'}

    encrypted = mi_encrypt_params("POST", "/setting/get_x", plaintext, nonce, SSECURITY)

    enc_only = {k: v for k, v in encrypted.items() if k not in ("signature", "_nonce")}
    decrypted = mi_decrypt_params(enc_only, nonce, SSECURITY)

    assert decrypted["data"] == plaintext["data"]


def test_compute_signing_path() -> None:
    assert (
        compute_signing_path("/healthapp/setting/get_user_device_settings", "healthapp/")
        == "/setting/get_user_device_settings"
    )
    assert (
        compute_signing_path("/healthapp/privacy/get_privacy_change", "healthapp/")
        == "/privacy/get_privacy_change"
    )
    assert (
        compute_signing_path("/app/v1/source/get_source_list", "")
        == "/app/v1/source/get_source_list"
    )
    assert (
        compute_signing_path("/cgi-op/api/v1/miwear/sports/list", "cgi-op/api/v1/miwear/")
        == "/sports/list"
    )


def test_signing_path_with_captured_get_source_list() -> None:
    """Verify that empty pathPrefix means full path is used for signing."""
    nonce = unquote("WJLZldGzqgEBv42r")

    decrypted = mi_decrypt_params(
        {
            "data": unquote("13wc21mXVNlEBm1V6377FO82qjYB0rMbnvH/"),
            "rc4_hash__": unquote("iEb0n3F4yHV8uK5wr8PlxmaMwhKqVO+++pa8Sg=="),
        },
        nonce,
        SSECURITY,
    )

    # Re-encrypt with the same nonce and verify
    signing_path = compute_signing_path("/app/v1/source/get_source_list", "")
    data_only = {k: v for k, v in decrypted.items() if k != "rc4_hash__"}
    result = mi_encrypt_params("POST", signing_path, data_only, nonce, SSECURITY)

    captured_data = unquote("13wc21mXVNlEBm1V6377FO82qjYB0rMbnvH/")
    captured_rc4_hash = unquote("iEb0n3F4yHV8uK5wr8PlxmaMwhKqVO+++pa8Sg==")

    assert result["data"] == captured_data
    assert result["rc4_hash__"] == captured_rc4_hash
