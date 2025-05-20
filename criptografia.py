from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

def pad(text, block_size):
    while len(text) % block_size != 0:
        text += ' '
    return text

def encrypt_AES(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(text, AES.block_size)
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode()

def decrypt_AES(encrypted_text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decoded = base64.b64decode(encrypted_text)
    return cipher.decrypt(decoded).decode().strip()

def encrypt_DES(text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(text, DES.block_size)
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode()

def decrypt_DES(encrypted_text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decoded = base64.b64decode(encrypted_text)
    return cipher.decrypt(decoded).decode().strip()

def generate_RSA_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def encrypt_RSA(text, public_key_str):
    public_key = RSA.import_key(public_key_str)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_RSA(encrypted_text, private_key_str):
    private_key = RSA.import_key(private_key_str)
    cipher = PKCS1_OAEP.new(private_key)
    decoded = base64.b64decode(encrypted_text)
    return cipher.decrypt(decoded).decode()
