from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encode_uint32(value: int) -> bytes:
    """Convert 4-bytes value into a list with 4 bytes"""
    return bytes([value & 0xff]) + bytes([(value >> 8) & 0xff]) + \
        bytes([(value >> 16) & 0xff]) + bytes([(value >> 24) & 0xff])

def zepp_encrypt_payload(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return encrypted

def zepp_decrypt_payload(encrypted: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted
