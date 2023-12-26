from asyncio import sleep

import pytest

from iron.crypto.common import seal_options
from iron.crypto.seal import seal
from iron.crypto.unseal import unseal


def test_unseal():
    sealed_from_node = 'Fe26.2*1*66a78e2d170beda5ba96f72f20697bbe400c614d6ae7f7368712653b9b3093d3*pCSZP-GmxRqsey6OemTvxA*TQPvAZbNXX5FNvuJ4nqFCInxLXeMQ9CwWOWJM8boPsfojJ9mmYMCYVIanOmaROnQYYKSohkOs3ij8FXg7TdG5A*1704740337189*2d2b548deaef4dc52a387668f3775d0a59cd2d92d31dddc35635b7756df30ab6*8cl5UcX_km-aTVrThu5G5yiNs7IfNVV0GIKCKi99bwU'
    password = 'AawB2iMuVrYbgrpmhOYTp+awfKukUwW8Y9iUtKGBJjgAUTH'
    assert b'{"user":{"account_id":100500,"username":"Alesh"}}' == unseal(sealed_from_node, password,
                                                                          seal_options())

    data = b'Hello, world!'
    sealed = seal(data, password, seal_options(ttl=62000))
    sleep(0.1)
    unsealed = unseal(sealed, password, seal_options())
    assert data == unsealed

    data = b'Hello, world!'
    sealed = seal(data, password, seal_options(ttl=60000))
    sleep(0.1)
    with pytest.raises(ValueError, match='Expired seal'):
        unseal(sealed, password, seal_options())
