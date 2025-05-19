
from __future__ import annotations
from typing import Generator
from secrets import token_bytes as rand
from arka import _crypto

import asyncio


class Verifier(object):

    def __init__(self,
        key: bytes, loop: asyncio.AbstractEventLoop | None = None
    ):
        self.key = key
        self._loop = loop or asyncio.get_running_loop()

    async def verify(self, signature: bytes, hash: bytes) -> bool:
        return await self._loop.run_in_executor(
            None, _crypto.verify, self.key, signature, hash
        )

    async def spawn(self, nonce: bytes) -> Keypair:
        if len(nonce) != 32:
            ValueError('nonce must be 32 bytes.')
        seed = await self._loop.run_in_executor(
            None, _crypto.key_exchange_vartime, nonce, self.key
        )
        return Keypair(seed, self._loop)


class Keypair(object):

    def __init__(self,
        seed: bytes | None = None,
        loop: asyncio.AbstractEventLoop | None = None
    ):
        self._seed = rand(32) if seed is None else seed
        self._keypair: bytes | None = None
        self._verifier: bytes | None = None
        self._loop = loop or asyncio.get_running_loop()
    
    def __await__(self) -> Generator[object, object, Keypair]:
        return self.derive().__await__()

    async def derive(self) -> Keypair:
        if self._keypair is None:
            self._keypair = await self._loop.run_in_executor(
                None, _crypto.keypair, self._seed
            )
            self._verifier = self._keypair[32:]
        return self

    async def sign(self, hash: bytes) -> bytes:
        if self._keypair is None:
            await self
        return await self._loop.run_in_executor(
            None, _crypto.sign, self._keypair, hash
        )

    async def verifier(self) -> Verifier:
        if self._verifier is None:
            await self
        return Verifier(self._verifier, self._loop)

    async def spawn(self, verifier: Verifier) -> Keypair:
        seed = await self._loop.run_in_executor(
            None, _crypto.key_exchange_vartime, self._seed, verifier.key
        )
        return Keypair(seed, self._loop)


class Cipher(object):

    MASK_WIDTH = 20
    ITERATIONS = 5_000_000

    def __init__(self,
        password: bytes,
        salt: bytes,
        loop: asyncio.AbstractEventLoop | None = None
    ):
        self._password = password
        self._salt = salt
        self._loop = loop or asyncio.get_running_loop()
        self._key: bytes | None = None

    def __await__(self) -> Generator[object, object, Cipher]:
        return self.derive().__await__()

    async def derive(self) -> Cipher:
        if self._key is not None:
            return self
        self._key = await self._loop.run_in_executor(
            None, _crypto.derive_key, self._password, self._salt,
            self.MASK_WIDTH, self.ITERATIONS
        )
        return self

    async def encrypt(self, nonce: bytes, message: bytes) -> bytes:
        if self._key is None:
            await self
        return await self._loop.run_in_executor(
            None, _crypto.encrypt, self._key, nonce, message
        )


async def keccak_800(
    msg: bytes | bytearray,
    outlen: int = 32,
    loop: asyncio.AbstractEventLoop | None = None
):
    loop = loop or asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _crypto.keccak_800, msg, outlen
    )


async def keccak_1600(
    msg: bytes | bytearray,
    outlen: int = 32,
    loop: asyncio.AbstractEventLoop | None = None
):
    loop = loop or asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _crypto.keccak_1600, msg, outlen
    )


async def mint(
    prefix: bytes,
    diff: tuple[int, int],
    limit: int = 0xffffffffffffffff,
    loop: asyncio.AbstractEventLoop | None = None
) -> int:
    loop = loop or asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _crypto.mint, prefix, diff[0], diff[1], limit
    )


async def check_mint(
    preimage: bytes,
    diff: tuple[int, int],
    loop: asyncio.AbstractEventLoop | None = None
) -> bool:
    loop = loop or asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _crypto.check_mint, preimage, diff[0], diff[1]
    )
