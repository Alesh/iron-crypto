# IronCrypto

This Python package is a partial implementation of @hapi/iron 
and contains the following methods:

* `seal` - Encrypts and signs bytestring into an iron protocol string.
* `unseal` - Verifies, decrypts, and reconstruct an iron protocol string into a bytes.
* `seal_options` - Construct seal options from defaults.

Examples:
```python
from iron.crypto import seal, unseal, seal_options

data = b'Hello, world!'
password = 'SECRET!'

sealed = seal(data, password, seal_options(ttl=900000))
unsealed = unseal(sealed, password, seal_options())
assert data == unsealed
```