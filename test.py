import base64
import hashlib
import json
import array
import sys
from Crypto.Cipher import AES

from hashlib import sha256
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode
from generator import PKCS12ParameterGenerator, RandomSaltGenerator

str_encode = lambda s: str(s, 'utf-8')

class Decryptor: 
    def __init__(self) -> None:
        self._cipher_factory = AES.new
        self._cipher_mode = AES.MODE_CBC
        self.password = "Passw0rd"
        self.iterations = 4000
        self.key_generator = PKCS12ParameterGenerator(SHA256)
        self.salt_generator = RandomSaltGenerator()

    @staticmethod
    def pad(block_size, s):
        padding = block_size - len(s) % block_size
        return s + bytes([padding] * padding)
    @staticmethod
    def unpad(s):
        return s[0:-s[-1]]
    
    def encrypt(self, text ):

        # generate a 16 byte salt which is used to generate key material and iv
        salt = self.salt_generator.generate_salt()

        # generate key material
        key, iv = self.key_generator.generate_derived_parameters(self.password, salt, self.iterations)

        # setup AES cipher
        cipher = self._cipher_factory(key, self._cipher_mode, iv)

        # pad the plain text secret to AES block size
        encrypted_message = cipher.encrypt(self.pad(AES.block_size, text.encode()))

        # concatenate salt + encrypted message
        return str_encode(b64encode(bytes(salt) + encrypted_message))

    
    def decrypt(self, ciphertext):

        # decode the base64 encoded and encrypted secret
        n_cipher_bytes = b64decode(ciphertext)
        # extract salt bytes 0 - SALT_SIZE
        salt = n_cipher_bytes[:self.salt_generator.salt_block_size]

        # create reverse key material
        key, iv = self.key_generator.generate_derived_parameters(self.password, salt, self.iterations)

        cipher = self._cipher_factory(key, self._cipher_mode, iv)

        # extract encrypted message bytes SALT_SIZE - len(cipher)
        n_cipher_message = n_cipher_bytes[self.salt_generator.salt_block_size:]
        decoded = cipher.decrypt(n_cipher_message)
        print(f"str_encode(self.unpad(decoded)) {self.unpad(decoded)}")
        return json.loads(str_encode(self.unpad(decoded)))
    
print(Decryptor().encrypt(r'{"url":"https://www.saucedemo.com","username":"standard_user","password":"secret_sauce"}'))
print(Decryptor().decrypt("NXlvZJ5uLzPqIlvX/ieq/6c3+wQCsIdHPPij0uoRKfrl3yGjaIYGVy/quGH1oNXN5bLRyXElCCrwLlRhSBiliq9dpaOhnPwzDNgjDL1Kc2c="))