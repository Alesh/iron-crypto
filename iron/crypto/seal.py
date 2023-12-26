import base64
from datetime import datetime

from iron.crypto.common import *
from cryptography.hazmat.primitives import padding


def seal(data: bytes, password: str | PasswordPair | PasswordTable, options: SealOptions) -> str:
    """ Encrypts and signs bytestring into an iron protocol string

    Args:
        data: a bytestring that can contain serialized objects
        password: a password string used to generate a key using the pbkdf2 algorithm
        options: an options to make seal, see `seal_options`

    Returns:
         iron sealed string
    """
    expiration = str(round(datetime.now().timestamp() * 1000) + options.ttl)
    password = normalize_password(password)
    password_id = tuple(password.keys())[0]
    # encrypts body
    encryption_password = password[password_id].encryption
    encryptor, encryption_salt, iv = create_encryptor(encryption_password, options.encryption)
    padder = padding.PKCS7(AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_b64 = base64.urlsafe_b64encode(encrypted).rstrip(b'=').decode('utf8')
    encryption_iv = base64.urlsafe_b64encode(iv).rstrip(b'=').decode('utf8')
    # create hmac
    hmac_base = "*".join([MAC_PREFIX, password_id, encryption_salt, encryption_iv, encrypted_b64, expiration])
    integrity_password = password[password_id].integrity
    hmac, hmac_salt = create_hmac_with_password(integrity_password, options.integrity)
    hmac.update(hmac_base.encode('utf8'))
    hmac_digest = base64.urlsafe_b64encode(hmac.finalize()).rstrip(b'=').decode('utf8')
    return "*".join([hmac_base, hmac_salt, hmac_digest])
