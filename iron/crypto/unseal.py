import base64
import typing as t
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import constant_time, padding

from iron.crypto.common import *


class ParsedSeal(t.NamedTuple):
    password_id: str
    encryption_salt: str
    encryption_iv: str
    encrypted_b64: str
    expiration: str
    hmac_salt: str
    hmac_digest: str


def parse_seal(seal: str) -> ParsedSeal:
    try:
        prefix, *args = seal.split('*')
    except Exception:
        raise ValueError("Cannot parse seal")
    if (MAC_PREFIX != prefix):
        raise ValueError(f"Wrong prefix: {prefix}")
    return ParsedSeal(*args)


def unseal(data: str, password: str | PasswordPair | PasswordTable, options: SealOptions) -> bytes:
    """  Verifies, decrypts, and reconstruct an iron protocol string into a bytes.

    Args:
        data: an iron protocol string generated with seal()
        password: a password value passed to seal()
        options: an options value passed to seal()

    Returns:
        the verified bytestring that can contain serialized objects.
    """
    password = normalize_password(password)
    seal = parse_seal(data)
    # check expiration
    expiration = datetime.fromtimestamp(int(seal.expiration)/1000)
    if expiration <= datetime.now() + timedelta(seconds=options.timestamp_skew_sec):
        raise ValueError('Expired seal')
    # verify hmac
    hmac_base = "*".join([MAC_PREFIX, *seal[:5]])
    integrity_password = password[seal.password_id].integrity
    hmac, _ = create_hmac_with_password(integrity_password, options.integrity, seal.hmac_salt)
    hmac.update(hmac_base.encode('utf8'))
    digest = base64.urlsafe_b64encode(hmac.finalize()).rstrip(b'=')
    if not constant_time.bytes_eq(digest, seal.hmac_digest.encode('utf8')):
        raise ValueError("HMAC verification failed")
    # decrypts body
    encryption_password = password[seal.password_id].encryption
    encrypted = base64.urlsafe_b64decode(seal.encrypted_b64 + "==")
    iv = base64.urlsafe_b64decode(seal.encryption_iv + "==")
    decryptor, _, _ = create_decryptor(encryption_password, options.encryption, seal.encryption_salt, iv)
    body = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(AES.block_size).unpadder()
    return unpadder.update(body)+ unpadder.finalize()

