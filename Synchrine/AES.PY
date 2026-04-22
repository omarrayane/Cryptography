# AES.py
# ============================================================

import hashlib

# ============================================================
#  Tables S-Box et Inverse S-Box
# ============================================================

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

INV_SBOX = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ─────────────────────────────────────────────
#  Opérations de base
# ─────────────────────────────────────────────

def sub_bytes(state):
    return [SBOX[b] for b in state]

def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]

def shift_rows(state):
    matrix = [state[i::4] for i in range(4)]
    for i in range(4):
        matrix[i] = matrix[i][i:] + matrix[i][:i]
    result = [0] * 16
    for i in range(4):
        for j in range(4):
            result[j*4 + i] = matrix[i][j]
    return result

def inv_shift_rows(state):
    matrix = [state[i::4] for i in range(4)]
    for i in range(4):
        matrix[i] = matrix[i][-i:] + matrix[i][:-i] if i else matrix[i]
    result = [0] * 16
    for i in range(4):
        for j in range(4):
            result[j*4 + i] = matrix[i][j]
    return result

def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF

def gf_mul(a, b):
    result = 0
    temp = a
    for _ in range(8):
        if b & 1:
            result ^= temp
        temp = xtime(temp)
        b >>= 1
    return result

def mix_columns(state):
    result = list(state)
    for i in range(4):
        col = state[i*4:(i+1)*4]
        result[i*4]     = gf_mul(2, col[0]) ^ gf_mul(3, col[1]) ^ col[2] ^ col[3]
        result[i*4 + 1] = col[0] ^ gf_mul(2, col[1]) ^ gf_mul(3, col[2]) ^ col[3]
        result[i*4 + 2] = col[0] ^ col[1] ^ gf_mul(2, col[2]) ^ gf_mul(3, col[3])
        result[i*4 + 3] = gf_mul(3, col[0]) ^ col[1] ^ col[2] ^ gf_mul(2, col[3])
    return result

def inv_mix_columns(state):
    result = list(state)
    for i in range(4):
        col = state[i*4:(i+1)*4]
        result[i*4]     = gf_mul(14, col[0]) ^ gf_mul(11, col[1]) ^ gf_mul(13, col[2]) ^ gf_mul(9, col[3])
        result[i*4 + 1] = gf_mul(9, col[0]) ^ gf_mul(14, col[1]) ^ gf_mul(11, col[2]) ^ gf_mul(13, col[3])
        result[i*4 + 2] = gf_mul(13, col[0]) ^ gf_mul(9, col[1]) ^ gf_mul(14, col[2]) ^ gf_mul(11, col[3])
        result[i*4 + 3] = gf_mul(11, col[0]) ^ gf_mul(13, col[1]) ^ gf_mul(9, col[2]) ^ gf_mul(14, col[3])
    return result

def add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]


# ─────────────────────────────────────────────
#  Expansion de clé (AES-128, 192, 256)
# ─────────────────────────────────────────────

def key_expansion(key):
    """
    Expansion pour AES-128 (16 bytes), AES-192 (24 bytes), AES-256 (32 bytes)
    """
    key_bytes = list(key)
    n = len(key_bytes)

    # Déterminer les paramètres
    if n == 16:
        nk = 4   # mots de 4 octets
        nr = 10  # rounds
    elif n == 24:
        nk = 6
        nr = 12
    elif n == 32:
        nk = 8
        nr = 14
    else:
        raise ValueError(f"Taille de clé invalide: {n} bytes (doit être 16, 24 ou 32)")

    nb = 4  # taille du bloc en mots

    # Initialiser les mots
    w = []
    for i in range(nk):
        w.append(key_bytes[4*i:4*i+4])

    for i in range(nk, nb * (nr + 1)):
        temp = list(w[i-1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[(i // nk) - 1]
        elif nk == 8 and i % nk == 4:
            temp = [SBOX[b] for b in temp]

        w.append([a ^ b for a, b in zip(w[i - nk], temp)])

    # Convertir en round keys
    round_keys = []
    for r in range(nr + 1):
        rk = []
        for j in range(4):
            rk.extend(w[r*4 + j])
        round_keys.append(rk)

    return round_keys, nr


# ─────────────────────────────────────────────
#  Chiffrement/Déchiffrement par bloc
# ─────────────────────────────────────────────

def aes_encrypt_block(plaintext_block, key):
    round_keys, nr = key_expansion(key)
    state = list(plaintext_block)

    state = add_round_key(state, round_keys[0])

    for r in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[nr])

    return bytes(state)

def aes_decrypt_block(ciphertext_block, key):
    round_keys, nr = key_expansion(key)
    state = list(ciphertext_block)

    state = add_round_key(state, round_keys[nr])

    for r in range(nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return bytes(state)


# ─────────────────────────────────────────────
#  Padding et modes
# ─────────────────────────────────────────────

def pad(data):
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def aes_encrypt_ecb(plaintext, key):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = hashlib.sha256(key.encode()).digest()[:len(key) if len(key.encode()) in [16,24,32] else 32]

    data = pad(plaintext)
    ciphertext = b''
    for i in range(0, len(data), 16):
        ciphertext += aes_encrypt_block(data[i:i+16], key)
    return ciphertext

def aes_decrypt_ecb(ciphertext, key):
    if isinstance(key, str):
        key = hashlib.sha256(key.encode()).digest()[:len(key) if len(key.encode()) in [16,24,32] else 32]

    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        plaintext += aes_decrypt_block(ciphertext[i:i+16], key)
    return unpad(plaintext).decode('utf-8')


# ─────────────────────────────────────────────
#  Mode CBC
# ─────────────────────────────────────────────

def aes_encrypt_cbc(plaintext, key, iv):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(iv, str):
        iv = iv.encode('utf-8')[:16]

    data = pad(plaintext)
    ciphertext = b''
    previous = iv

    for i in range(0, len(data), 16):
        block = data[i:i+16]
        xored = bytes([b ^ p for b, p in zip(block, previous)])
        encrypted = aes_encrypt_block(xored, key)
        ciphertext += encrypted
        previous = encrypted

    return ciphertext

def aes_decrypt_cbc(ciphertext, key, iv):
    plaintext = b''
    previous = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = aes_decrypt_block(block, key)
        xored = bytes([d ^ p for d, p in zip(decrypted, previous)])
        plaintext += xored
        previous = block

    return unpad(plaintext).decode('utf-8')


# ─────────────────────────────────────────────
#  Mode CTR
# ─────────────────────────────────────────────

def aes_encrypt_ctr(plaintext, key, nonce):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(nonce, str):
        nonce = nonce.encode('utf-8')[:8]

    ciphertext = b''
    counter = 0

    for i in range(0, len(plaintext), 16):
        # Construire le compteur (nonce + counter)
        counter_bytes = nonce + counter.to_bytes(8, 'big')
        if len(counter_bytes) < 16:
            counter_bytes = counter_bytes.ljust(16, b'\x00')

        keystream = aes_encrypt_block(counter_bytes[:16], key)
        block = plaintext[i:i+16]
        xored = bytes([k ^ p for k, p in zip(keystream, block)])
        ciphertext += xored
        counter += 1

    return ciphertext

def aes_decrypt_ctr(ciphertext, key, nonce):
    return aes_encrypt_ctr(ciphertext, key, nonce)


# ─────────────────────────────────────────────
#  Démonstration
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  AES-128, AES-192, AES-256")
    print("=" * 60)

    message = input("\n📝 Entrez un message à chiffrer : ")
    password = input("🔑 Entrez un mot de passe : ")

    # AES-128
    print("\n" + "-" * 40)
    print("  AES-128 (ECB mode)")
    print("-" * 40)
    key128 = hashlib.sha256(password.encode()).digest()[:16]
    encrypted = aes_encrypt_ecb(message, key128)
    print(f"   Chiffré (hex) : {encrypted.hex()}")
    decrypted = aes_decrypt_ecb(encrypted, key128)
    print(f"   Déchiffré     : {decrypted}")

    # AES-192
    print("\n" + "-" * 40)
    print("  AES-192 (ECB mode)")
    print("-" * 40)
    key192 = hashlib.sha256(password.encode()).digest()[:24]
    encrypted = aes_encrypt_ecb(message, key192)
    print(f"   Chiffré (hex) : {encrypted.hex()}")
    decrypted = aes_decrypt_ecb(encrypted, key192)
    print(f"   Déchiffré     : {decrypted}")

    # AES-256
    print("\n" + "-" * 40)
    print("  AES-256 (CBC mode)")
    print("-" * 40)
    key256 = hashlib.sha256(password.encode()).digest()
    iv = b"0123456789abcdef"
    encrypted = aes_encrypt_cbc(message, key256, iv)
    print(f"   Chiffré (hex) : {encrypted.hex()}")
    decrypted = aes_decrypt_cbc(encrypted, key256, iv)
    print(f"   Déchiffré     : {decrypted}")

    # AES-256 (CTR mode)
    print("\n" + "-" * 40)
    print("  AES-256 (CTR mode)")
    print("-" * 40)
    nonce = b"ABCD1234"
    encrypted = aes_encrypt_ctr(message, key256, nonce)
    print(f"   Chiffré (hex) : {encrypted.hex()}")
    decrypted = aes_decrypt_ctr(encrypted, key256, nonce).decode('utf-8')
    print(f"   Déchiffré     : {decrypted}")

    print("\n✅ Tous les chiffrements AES fonctionnent !")
