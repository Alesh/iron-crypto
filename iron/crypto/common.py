import random
from collections import namedtuple
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes, AEADDecryptionContext, AEADEncryptionContext
from cryptography.hazmat.primitives.ciphers.algorithms import AES128, AES256, AES
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAC_FORMAT_VERSION = '2'
MAC_PREFIX = f"Fe26.{MAC_FORMAT_VERSION}"


@dataclass
class SealConfigOptions:
    algorithm: str
    salt_bits: int = 256
    iterations: int = 1
    min_password_length: int = 32


@dataclass
class SealOptions:
    encryption: SealConfigOptions = SealConfigOptions('aes-256-cbc')
    integrity: SealConfigOptions = SealConfigOptions('sha256')
    timestamp_skew_sec: int = 60
    ttl: int = 0


def seal_options(ttl=0, **kwargs):
    """ Construct seal options from defaults.

    Examples:
        seal(data, password, seal_options(ttl=900000))
        unseal(data, password, seal_options())
    """
    return SealOptions(ttl=ttl, **kwargs)


PasswordPair = namedtuple('PasswordPair', ['encryption', 'integrity'])
PasswordTable = dict[str, str | PasswordPair]


def normalize_password(password: str | PasswordPair | PasswordTable) -> PasswordTable:
    if isinstance(password, str):
        return {'1': PasswordPair(password, password)}
    elif isinstance(password, PasswordPair):
        return {'1': password}
    return password


def create_pbkdf2_key(password: str, options: SealConfigOptions, salt: str = None) -> tuple[bytes, str]:
    if salt is None:
        salt = random.randbytes(32).hex()
    pbkdf = PBKDF2HMAC(algorithm=SHA1(), salt=salt.encode('utf8'), length=options.min_password_length,
                       iterations=options.iterations, backend=default_backend())
    key = pbkdf.derive(password.encode('utf8'))
    return key, salt


def create_cipher(key: bytes, options: SealConfigOptions, iv: bytes = None) -> tuple[Cipher, bytes]:
    if iv is None:
        iv = random.randbytes(16)
    if options.algorithm == 'aes-256-cbc':
        return Cipher(AES256(key), modes.CBC(iv)), iv
    elif options.algorithm == 'aes-128-ctr':
        return Cipher(AES128(key), modes.CTR(iv)), iv
    raise ValueError(f"Unsupported algorithm {options.algorithm}")


def create_hmac_with_password(password: str, options: SealConfigOptions, salt: str = None) -> tuple[HMAC, str]:
    key, salt = create_pbkdf2_key(password, options, salt)
    if options.algorithm == 'sha256':
        return HMAC(key, SHA256()), salt
    raise ValueError(f"Unsupported algorithm {options.algorithm}")


def create_decryptor(password: str, options: SealConfigOptions,
                     salt: str = None, iv: bytes = None) -> tuple[AEADDecryptionContext, str, bytes]:
    key, _ = create_pbkdf2_key(password, options, salt)
    cipher, _ = create_cipher(key, options, iv)
    decryptor = cipher.decryptor()
    return decryptor, salt, iv


def create_encryptor(password: str, options: SealConfigOptions) -> tuple[AEADEncryptionContext, str, bytes]:
    key, salt = create_pbkdf2_key(password, options)
    cipher, iv = create_cipher(key, options)
    encryptor = cipher.encryptor()
    return encryptor, salt, iv

