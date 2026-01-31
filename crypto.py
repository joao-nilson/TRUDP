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
        p = 0xFFFFFFFB
        g = 5
        
        private_key = random.randint(1, p-2)  # Chave privada grande
        print(f"[CRYPTO-DEBUG] Gerando params: g={g}, p={p}, private_key={private_key}")
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

        # Usar HKDF para derivar chave segura
        shared_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
        key_material = shared_bytes + salt
        
        # Primeira extração
        prk = hmac.new(salt, key_material, hashlib.sha256).digest()
        
        # Expansão
        info = b"TRUDP Key Derivation"
        t = b""
        okm = b""
        
        while len(okm) < 32:  # 256 bits
            t = hmac.new(prk, t + info + bytes([len(t) + 1]), hashlib.sha256).digest()
            okm += t
        
        return okm[:32], salt

    @staticmethod
    def encrypt_data(data: bytes, key: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        if iv is None:
            iv = os.urandom(16)
        
        print(f"[ENCRYPT_DATA] Criptografando {len(data)} bytes com chave de {len(key)} bytes, IV: {iv.hex()[:8]}...")
        
        # Usar modo CTR simples para stream cipher
        keystream = TRUCrypto._generate_keystream(key, iv, len(data))
        
        encrypted = bytes(a ^ b for a, b in zip(data, keystream))
        
        print(f"[ENCRYPT_DATA] Criptografia concluída: {len(encrypted)} bytes")
        return encrypted, iv

    @staticmethod
    def decrypt_data(encrypted: bytes, key: bytes, iv: bytes) -> bytes:
        # A descriptografia é igual à criptografia em modo XOR
        keystream = TRUCrypto._generate_keystream(key, iv, len(encrypted))
        return bytes(a ^ b for a, b in zip(encrypted, keystream))

    @staticmethod
    def _generate_keystream(key: bytes, iv: bytes, length: int) -> bytes:
        keystream = b""
        counter = 0
        
        while len(keystream) < length:
            # Combinar IV e contador
            block_data = iv + counter.to_bytes(8, 'big')
            # Gerar bloco de keystream
            block = hmac.new(key, block_data, hashlib.sha256).digest()
            keystream += block
            counter += 1
        
        return keystream[:length]

    @staticmethod
    def compute_hmac(data: bytes, key: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()[:16]

    def test_encryption(self, key: bytes) -> bool:
        test_data = b"Teste de criptografia TRUDP"
        
        # Criptografar
        encrypted, iv = self.encrypt_data(test_data, key)
        
        # Descriptografar
        decrypted = self.decrypt_data(encrypted, key, iv)
        
        # Verificar integridade
        success = test_data == decrypted
        
        if success:
            print(f"[CRYPTO-TEST] Sucesso! Dados: {test_data[:20]}...")
            print(f"[CRYPTO-TEST] Criptografado: {encrypted.hex()[:20]}...")
            print(f"[CRYPTO-TEST] IV: {iv.hex()[:20]}...")
        else:
            print(f"[CRYPTO-TEST] Falha! Original: {test_data}, Decriptado: {decrypted}")
        
        return success