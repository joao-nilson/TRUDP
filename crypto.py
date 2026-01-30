import os
import random
import hashlib
import hmac
import random
from typing import Tuple, Optional

class TRUCrypto:

    def __init__(self):
        self.session_key = None
        self.iv = None

    @staticmethod
    def generate_dh_params() -> Tuple[int, int, int]:
        p = 23
        g = 5
        private_key = random.randint(1, p-2)
        return g, p, private_key

    @staticmethod
    def compute_dh_public(base: int, modulus: int, private: int) -> int:
        return pow(base, private, modulus)

    @staticmethod
    def compute_dh_shared(public: int, private: int, modulus: int) -> int:
        return pow(public, private, modulus)

    @staticmethod
    def derive_key(shared_secret: int, salt: bytes = None) -> Tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(16)

        key_material = str(shared_secret).encode() + salt
        derived_key = hashlib.sha256(key_material).digest()

        while len(derived_key) < 32:
            derived_key += hashlib.sha256(derived_key + key_material).digest()
        
        return derived_key[:32], salt

    @staticmethod
    def encrypt_data(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        iv = os.urandom(16)
        keystream = hashlib.sha256(key + iv).digest()

        encrypted = bytes(a ^ b for a, b in zip(data, keystream[:len(data)]))
        return encrypted, iv

    @staticmethod
    def decrypt_data(encrypted: bytes, key: bytes, iv: bytes) -> bytes:
        keystream = hashlib.sha256(key + iv).digest()
        return bytes(a ^ b for a, b in zip(encrypted, keystream[:len(encrypted)]))

    @staticmethod
    def compute_hmac(data: bytes, key: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()[:16]
