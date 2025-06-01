from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import base64

SIGNING_PRIVATE_KEY_PATH = 'producer_signing_private.pem'
SIGNING_PUBLIC_KEY_PATH = 'producer_signing_public.pem'

def pad(text, block_size): # Sua função pad original
    while len(text) % block_size != 0:
        text += ' '
    return text

from Crypto.Cipher import AES, DES # Mova para o topo se ainda não estiver lá

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

def generate_RSA_keys(): # Para chaves de criptografia efêmeras
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def encrypt_RSA(text, public_key_str): # Para criptografia RSA
    public_key = RSA.import_key(public_key_str)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_RSA(encrypted_text, private_key_str): # Para decriptografia RSA
    private_key = RSA.import_key(private_key_str)
    cipher = PKCS1_OAEP.new(private_key)
    decoded = base64.b64decode(encrypted_text)
    return cipher.decrypt(decoded).decode()

# autenticação com assinatura RSA
def generate_persistent_signing_keys(): # Gera e SALVA chaves de assinatura
    key = RSA.generate(2048)
    private_key_bytes = key.export_key()
    public_key_bytes = key.publickey().export_key()
    with open(SIGNING_PRIVATE_KEY_PATH, "wb") as f_priv:
        f_priv.write(private_key_bytes)
    with open(SIGNING_PUBLIC_KEY_PATH, "wb") as f_pub:
        f_pub.write(public_key_bytes)
    return public_key_bytes, private_key_bytes

def sign_message_RSA(data_str, private_key_bytes):
    key = RSA.import_key(private_key_bytes)
    h = SHA256.new(data_str.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode()

def verify_message_signature_RSA(data_str, signature_b64_str, public_key_input):
    key = RSA.import_key(public_key_input)
    h = SHA256.new(data_str.encode('utf-8'))
    signature = base64.b64decode(signature_b64_str)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False