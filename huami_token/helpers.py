import zipfile
import zlib
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from loguru import logger


def encode_uint32(value: int) -> bytes:
    """Convert 4-bytes value into a list with 4 bytes"""
    return (
        bytes([value & 0xFF])
        + bytes([(value >> 8) & 0xFF])
        + bytes([(value >> 16) & 0xFF])
        + bytes([(value >> 24) & 0xFF])
    )


def zepp_encrypt_payload(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return encrypted


def zepp_decrypt_payload(encrypted: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted


def build_gps_uihh(base_folder: Path) -> None:
    """Prepare uihh gps file"""
    logger.info("Preparing gps uihh file...")
    d = {
        "gps_alm.bin": 0x05,
        "gln_alm.bin": 0x0F,
        "lle_bds.lle": 0x86,
        "lle_gps.lle": 0x87,
        "lle_glo.lle": 0x88,
        "lle_gal.lle": 0x89,
        "lle_qzss.lle": 0x8A,
    }

    cep_7days = next(base_folder.glob("*cep_7days.zip"))
    lle_1week = next(base_folder.glob("*lle_1week.zip"))

    with (
        zipfile.ZipFile(cep_7days, "r") as cep_archive,
        zipfile.ZipFile(lle_1week, "r") as lle_archive,
        open("gps_uihh.bin", "wb") as uihh_file,
    ):
        content = bytes()

        for key, value in d.items():
            if value >= 0x86:
                file_content = lle_archive.read(key)
            else:
                file_content = cep_archive.read(key)

            file_header = (
                bytes([1])
                + bytes([value])
                + encode_uint32(len(file_content))
                + encode_uint32(zlib.crc32(file_content) & 0xFFFFFFFF)
            )
            content += file_header + file_content

        header = (
            b"UIHH"
            + bytes([0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
            + encode_uint32(zlib.crc32(content) & 0xFFFFFFFF)
            + bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            + encode_uint32(len(content))
            + bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        )

        content = header + content
        uihh_file.write(content)
