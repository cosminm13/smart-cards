import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
import random

signature = hashlib.sha512

def generate_random_int(length):
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def importKey(key):
    return RSA.importKey(key)

# AES
def generate_aes_key():
    return hashlib.sha256(Random.new().read(16)).digest()


def aes_symmetric_encryption(message_bytes, aes_key):
    padding_char = b' '
    padded_message = message_bytes + (padding_char * ((16-len(message_bytes)) % 16))
    aes_cipher = AES.new(aes_key)
    return aes_cipher.encrypt(padded_message)


def aes_symmetric_decryption(enc_message, aes_key):
    aes_cipher = AES.new(aes_key)
    return aes_cipher.decrypt(enc_message)

# RSA
def generate_rsa_keys():
    modulus_length = 1024

    private_key = RSA.generate(modulus_length)

    public_key = private_key.publickey()

    return private_key, public_key

def rsa_encryption(message, public_key):
    return public_key.encrypt(message, 32)


def rsa_decryption(enc_message, private_key):
    return private_key.decrypt(enc_message)

# Hybrid
def rsa_aes_hybrid_encryption(message, public_key, aes_key):
    aes_key_enc = rsa_encryption(aes_key, public_key)
    return aes_symmetric_encryption(message, aes_key), aes_key_enc[0]

def rsa_aes_hybrid_decryption(enc_message, private_key, aes_key_enc):
    aes_key_dec = rsa_decryption(aes_key_enc, private_key)
    return aes_symmetric_decryption(enc_message, aes_key_dec).strip()
