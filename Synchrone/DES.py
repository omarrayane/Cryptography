# DES.py - Utilisation de pycryptodome

from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import time
from PIL import Image
import numpy as np

def des_ecb_encrypt(data, key):
    """DES mode ECB."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')[:8].ljust(8, b'\x00')
    
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(data, DES.block_size)
    return cipher.encrypt(padded)

def des_ecb_decrypt(ciphertext, key):
    """DES mode ECB."""
    if isinstance(key, str):
        key = key.encode('utf-8')[:8].ljust(8, b'\x00')
    
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, DES.block_size).decode('utf-8')

def des_cbc_encrypt(data, key, iv=None):
    """DES mode CBC avec IV aléatoire."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')[:8].ljust(8, b'\x00')
    if iv is None:
        iv = get_random_bytes(DES.block_size)
    
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    padded = pad(data, DES.block_size)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext

def des_cbc_decrypt(ciphertext, key):
    """DES mode CBC."""
    if isinstance(key, str):
        key = key.encode('utf-8')[:8].ljust(8, b'\x00')
    
    iv = ciphertext[:DES.block_size]
    actual_ciphertext = ciphertext[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(actual_ciphertext)
    return unpad(decrypted, DES.block_size).decode('utf-8')

def triple_des_cbc_encrypt(data, key):
    """Triple DES mode CBC."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')[:24].ljust(24, b'\x00')
    
    iv = get_random_bytes(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded = pad(data, DES3.block_size)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext

def triple_des_cbc_decrypt(ciphertext, key):
    """Triple DES mode CBC."""
    if isinstance(key, str):
        key = key.encode('utf-8')[:24].ljust(24, b'\x00')
    
    iv = ciphertext[:DES3.block_size]
    actual_ciphertext = ciphertext[DES3.block_size:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(actual_ciphertext)
    return unpad(decrypted, DES3.block_size).decode('utf-8')

def des_encrypt(plaintext, key):
    """Interface simple pour DES encryption."""
    return des_cbc_encrypt(plaintext, key)

def des_decrypt(ciphertext, key):
    """Interface simple pour DES decryption."""
    return des_cbc_decrypt(ciphertext, key)

if __name__ == "__main__":
    print("DES module loaded successfully")
