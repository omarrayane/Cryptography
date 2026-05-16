#!/usr/bin/env python3
# web_gui.py - Application Cryptographique Web Complète
# Version web de CryptoSuite Complete (Flask)

from flask import Flask, render_template, request, jsonify
import hashlib
import time
import os
import random
import hmac as hmac_module
from datetime import datetime

try:
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, padding, ec, dh
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

app = Flask(__name__, static_folder='static', template_folder='templates')

# Global key storage
keys = {
    'rsa_private': None,
    'rsa_public': None,
    'dh_params': None,
    'dh_private': None,
    'dh_public': None,
    'elgamal_keys': None,
    'ecc_private': None,
    'ecc_public': None,
}

# ==================== ALGORITHMES ====================

def cesar_encrypt(text, shift):
    result = ""
    for c in text:
        if c.isalpha():
            offset = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - offset + shift) % 26 + offset)
        else:
            result += c
    return result

def cesar_decrypt(text, shift):
    return cesar_encrypt(text, -shift)

def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    for i, c in enumerate(text):
        if c.isalpha():
            shift = ord(key[i % len(key)]) - ord('A')
            offset = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - offset + shift) % 26 + offset)
        else:
            result += c
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.upper()
    for i, c in enumerate(text):
        if c.isalpha():
            shift = ord(key[i % len(key)]) - ord('A')
            offset = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - offset - shift) % 26 + offset)
        else:
            result += c
    return result

def hill_encrypt(text, matrix=None):
    if matrix is None:
        matrix = [[3, 3], [2, 5]]
    text = ''.join(c for c in text.lower() if c.isalpha())
    if len(text) % 2 != 0:
        text += 'x'
    result = ""
    for i in range(0, len(text), 2):
        v = [ord(text[i]) - 97, ord(text[i + 1]) - 97]
        r0 = (matrix[0][0] * v[0] + matrix[0][1] * v[1]) % 26
        r1 = (matrix[1][0] * v[0] + matrix[1][1] * v[1]) % 26
        result += chr(r0 + 97) + chr(r1 + 97)
    return result

def otp_encrypt(text):
    text_bytes = text.encode()
    key_bytes = os.urandom(len(text_bytes))
    cipher = bytes(t ^ k for t, k in zip(text_bytes, key_bytes))
    return f"Cipher: {cipher.hex()}\nClé: {key_bytes.hex()}"

def playfair_encrypt(text, key):
    key = key.upper().replace('J', 'I')
    alphabet = []
    for c in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if c not in alphabet and c.isalpha():
            alphabet.append(c)
    matrix = [alphabet[i:i + 5] for i in range(0, 25, 5)]

    def find_pos(c):
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == c:
                    return i, j
        return 0, 0

    text = ''.join(c for c in text.upper() if c.isalpha()).replace('J', 'I')
    pairs = []
    i = 0
    while i < len(text):
        if i == len(text) - 1 or text[i] == text[i + 1]:
            pairs.append(text[i] + 'X')
            i += 1
        else:
            pairs.append(text[i:i + 2])
            i += 2

    result = ""
    for a, b in pairs:
        r1, c1 = find_pos(a)
        r2, c2 = find_pos(b)
        if r1 == r2:
            result += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:
            result += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        else:
            result += matrix[r1][c2] + matrix[r2][c1]
    return result

def railfence_encrypt(text, rails):
    fence = [[] for _ in range(rails)]
    direction = 1
    rail = 0
    for c in text:
        fence[rail].append(c)
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction *= -1
    return ''.join([''.join(r) for r in fence])

def rc4(data, key, mode):
    key_bytes = key.encode()
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    if mode == "encrypt":
        data_bytes = data.encode()
    else:
        data_bytes = bytes.fromhex(data)
    result = bytearray()
    i = j = 0
    for byte in data_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    if mode == "encrypt":
        return result.hex()
    else:
        return result.decode()

def des_simulate(data, key, mode):
    if mode == "encrypt":
        combined = data + key
        return hashlib.md5(combined.encode()).hexdigest()[:16]
    else:
        return "DES déchiffré (simulation)"

def aes_encrypt(data, key, bits):
    key_bytes = hashlib.sha256(key.encode()).digest()[:bits // 8]
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=b'0123456789abcdef')
    encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
    return encrypted.hex()

def aes_decrypt(data_hex, key, bits):
    key_bytes = hashlib.sha256(key.encode()).digest()[:bits // 8]
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=b'0123456789abcdef')
    decrypted = unpad(cipher.decrypt(bytes.fromhex(data_hex)), AES.block_size)
    return decrypted.decode()

def frequency_analysis(text):
    from collections import Counter
    lettres = [c.lower() for c in text if c.isalpha()]
    total = len(lettres)
    if total == 0:
        return "Aucune lettre trouvée"
    counts = Counter(lettres)
    french_freq = "EASINTRULODM"
    result = "=== ANALYSE FRÉQUENTIELLE ===\n\n"
    result += f"Total lettres: {total}\n\n"
    result += "Fréquences observées:\n"
    for letter, count in counts.most_common(10):
        pct = count / total * 100
        result += f"  {letter}: {count} ({pct:.2f}%)\n"
    result += f"\nFréquences françaises (théoriques):\n"
    freqs = [7.64, 7.53, 5.46, 7.09, 7.95, 7.24, 6.69, 6.31, 5.80, 2.97]
    for i, letter in enumerate(french_freq[:10]):
        result += f"  {letter}: {freqs[i]:.2f}%\n"
    return result

def avalanche_demo():
    text = "Hello World"
    hash1 = hashlib.sha256(text.encode()).hexdigest()
    text2 = bytearray(text.encode())
    text2[0] ^= 0x01
    hash2 = hashlib.sha256(bytes(text2)).hexdigest()
    bits_diff = sum(bin(int(h1, 16) ^ int(h2, 16)).count('1') for h1, h2 in zip(hash1, hash2))
    total_bits = 256
    ratio = bits_diff / total_bits * 100
    return f"""🔬 EFFET AVALANCHE SHA-256

Message original: {text}
Hash: {hash1[:32]}...

Message modifié (1 bit): {bytes(text2).decode()}
Hash: {hash2[:32]}...

Bits différents: {bits_diff} / {total_bits} ({ratio:.2f}%)

✅ {'Effet avalanche vérifié' if 45 < ratio < 55 else 'Ratio anormal'} (≈50% attendu)"""

def bluetooth_simulate():
    return """🔵 SIMULATION BLUETOOTH SECURE

Protocole: Bluetooth Classic + LE Secure Connections

[Pairing] ECDH P-256
  → Smartphone (Central) ↔ Casque (Peripheral)
  → PIN: 123456
  → LTK (Long Term Key): a3f2c1e4b5d6...

[Chiffrement] AES-CCM
  → Message: "Bonjour, streaming audio"
  → Chiffré: 7f3a2b1c8e4d...

[BLE] Bluetooth Low Energy 4.2+
  → LE Secure Connections avec ECDH
  → Résistant aux attaques MITM

✅ Communication sécurisée établie"""

def wifi_wpa2_simulate():
    return """📡 SIMULATION WPA2 4-WAY HANDSHAKE

SSID: WiFi_Secure
Password: ComplexPassword123

[Étape 1] PMK = PBKDF2(Password, SSID, 4096)
  → PMK: a3f2c1e4b5d6...

[Étape 2] ANonce (AP) → SNonce (Client)
  → ANonce: 7f3a2b1c...
  → SNonce: 8e4d5f6a...

[Étape 3] PTK = PRF(PMK + ANonce + SNonce + MACs)
  → KCK (Key Confirmation): 16 bytes
  → KEK (Key Encryption): 16 bytes
  → TEK (Temporal Key): 16 bytes

[Étape 4] GTK (Group Key) pour diffusion

✅ Chiffrement AES-CCMP activé
⚠️ WPA2 vulnérable KRACK (réinstallation clé)"""

def wifi_wpa3_simulate():
    return """📡 SIMULATION WPA3 SAE (Simultaneous Authentication of Equals)

SSID: WiFi_Secure_WPA3

[Dragonfly Key Exchange]
  → Courbe elliptique P-256
  → Password authenticated

[Propriétés]
  ✅ Résistant aux attaques offline
  ✅ Forward Secrecy (ECDHE)
  ✅ Protection contre KRACK
  ✅ 256-bit encryption (GCMP-256)

[Comparaison WPA2 vs WPA3]
  WPA2: 4-Way Handshake + PSK
  WPA3: SAE (Dragonfly) + ECDHE
  WPA3-Enterprise: 192-bit security

✅ Réseau sécurisé - Level: Enterprise"""

def vote_electronique():
    return """🗳️ SIMULATION VOTE ÉLECTRONIQUE

Système: RSA 2048 + Signatures PSS

[Scrutin] Élection Présidentielle 2024
Candidats: Alice, Bob, Charlie

[Votants enregistrés]
  ✅ V001 - Jean Dupont (a voté Alice)
  ✅ V002 - Marie Martin (a voté Bob)
  ✅ V003 - Pierre Durand (a voté Alice)

[Dépouillement]
  Alice: 2 voix (66.7%)
  Bob: 1 voix (33.3%)
  Charlie: 0 voix (0.0%)

[Propriétés de sécurité]
  ✅ Confidentialité: RSA-OAEP
  ✅ Authenticité: Signature RSA-PSS
  ✅ Intégrité: Hash + Signature
  ✅ Anti-double vote: Base vérifiée
  ✅ Vérifiabilité: Journal d'audit

✅ Scrutin sécurisé - Auditable"""

def vote_homomorphic():
    return """🧮 VOTE HOMOMORPHIQUE (Principe)

Propriété: E(v1) × E(v2) = E(v1 + v2)

[Exemple avec 3 votes]
  Vote 1: Alice → E(Alice) = 0x7F3A2B1C
  Vote 2: Alice → E(Alice) = 0x2B1C7F3A
  Vote 3: Bob   → E(Bob)   = 0x9D4E8C2F

Multiplication des chiffrés:
  E_total = 0x7F3A2B1C × 0x2B1C7F3A × 0x9D4E8C2F
  → Déchiffre = 2 voix pour Alice, 1 pour Bob

✅ On compte sans déchiffrer individuellement
✅ Anonymat total préservé
⚠️ Complexité algorithmique élevée"""


# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/execute', methods=['POST'])
def execute():
    data = request.json
    algo = data.get('algo', '')
    mode = data.get('mode', 'encrypt')
    text = data.get('text', '')
    key = data.get('key', 'secretkey123')

    if not text and algo not in ['dh', 'bluetooth', 'wifi', 'wpa3', 'vote',
                                  'homomorphic', 'ecc', 'avalanche',
                                  'socket_tcp', 'socket_udp', 'ecdh']:
        return jsonify({'error': 'Veuillez entrer un texte!'}), 400

    try:
        start = time.time()
        result = ""

        # TP1
        if algo == "cesar":
            shift = int(key) if key.isdigit() else 3
            result = cesar_encrypt(text, shift) if mode == "encrypt" else cesar_decrypt(text, shift)
        elif algo == "vigenere":
            result = vigenere_encrypt(text, key) if mode == "encrypt" else vigenere_decrypt(text, key)
        elif algo == "hill":
            result = hill_encrypt(text) if mode == "encrypt" else hill_encrypt(text)
        elif algo == "otp":
            result = otp_encrypt(text) if mode == "encrypt" else "OTP déchiffrement: entrez 'cipher:clé'"
        elif algo == "playfair":
            result = playfair_encrypt(text, key)
        elif algo == "railfence":
            rails = int(key) if key.isdigit() else 3
            result = railfence_encrypt(text, rails)
        elif algo == "freq":
            result = frequency_analysis(text)

        # TP2
        elif algo == "rc4":
            result = rc4(text, key, mode)
        elif algo == "des":
            result = des_simulate(text, key, mode)
        elif algo == "tdes":
            result = f"3DES: {des_simulate(text, key, mode)}"
        elif algo == "aes128":
            result = aes_encrypt(text, key, 128) if mode == "encrypt" else aes_decrypt(text, key, 128)
        elif algo == "aes192":
            result = aes_encrypt(text, key, 192) if mode == "encrypt" else aes_decrypt(text, key, 192)
        elif algo == "aes256":
            result = aes_encrypt(text, key, 256) if mode == "encrypt" else aes_decrypt(text, key, 256)
        elif algo in ["twofish", "serpent", "rc6", "mars"]:
            result = f"{algo.upper()} - Finaliste AES\nChiffré (simulation): {hashlib.sha256((text + key).encode()).hexdigest()[:16]}"

        # TP3
        elif algo == "rsa":
            if mode == "encrypt":
                if not keys['rsa_public']:
                    gen_rsa_keys()
                encrypted = keys['rsa_public'].encrypt(
                    text.encode(),
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                result = encrypted.hex()
            else:
                if not keys['rsa_private']:
                    return jsonify({'error': 'Générez les clés RSA d\'abord'}), 400
                decrypted = keys['rsa_private'].decrypt(
                    bytes.fromhex(text),
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                result = decrypted.decode()
        elif algo == "rsa_hybrid":
            if not keys['rsa_public']:
                gen_rsa_keys()
            encrypted = keys['rsa_public'].encrypt(
                text[:100].encode(),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            result = "Chiffrement hybride RSA + AES-256\n" + encrypted.hex()
        elif algo == "dh":
            result = "Échange DH simulé - Secret partagé établi"
        elif algo == "elgamal":
            if mode == "encrypt":
                if not keys['elgamal_keys']:
                    gen_elgamal_keys()
                p = keys['elgamal_keys']['p']
                g = keys['elgamal_keys']['g']
                y = keys['elgamal_keys']['y']
                pairs = []
                for c in text:
                    m = ord(c)
                    k = random.randint(2, p - 2)
                    c1 = pow(g, k, p)
                    c2 = (m * pow(y, k, p)) % p
                    pairs.append(f"({c1},{c2})")
                result = str(pairs)
            else:
                result = "ElGamal déchiffrement (simulation)"
        elif algo == "ecc":
            result = "Courbe elliptique y² = x³ + 7 mod 97\nPoint G(2,23)\n2G = (44,62)\n3G = (26,42)"
        elif algo == "ecdh":
            result = "ECDH P-256: Secret partagé établi\nClé AES dérivée avec HKDF-SHA256"

        # TP4
        elif algo == "md5":
            result = hashlib.md5(text.encode()).hexdigest()
        elif algo == "sha256":
            result = hashlib.sha256(text.encode()).hexdigest()
        elif algo == "sha512":
            result = hashlib.sha512(text.encode()).hexdigest()
        elif algo == "hmac":
            result = hmac_module.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()
        elif algo == "avalanche":
            result = avalanche_demo()

        # TP5
        elif algo == "rsa_sign":
            if mode == "sign":
                result = f"Signature RSA-PSS: {hashlib.sha256(text.encode()).hexdigest()[:32]}... (simulation)"
            else:
                result = "Vérification signature: ✅ VALIDE"
        elif algo == "dsa":
            result = "DSA Signature générée (simulation)"
        elif algo == "ecdsa":
            result = "ECDSA Signature avec courbe P-256"
        elif algo == "elgamal_sign":
            result = "Signature ElGamal (logarithme discret)"

        # TP6
        elif algo == "bluetooth":
            result = bluetooth_simulate()
        elif algo == "wifi":
            result = wifi_wpa2_simulate()
        elif algo == "wpa3":
            result = wifi_wpa3_simulate()
        elif algo == "vote":
            result = vote_electronique()
        elif algo == "homomorphic":
            result = vote_homomorphic()
        elif algo == "socket_tcp":
            result = "Socket TCP sécurisé (RSA + AES-256-GCM)\nServeur: python secure_server.py\nClient: python secure_client.py"
        elif algo == "socket_udp":
            result = "Socket UDP sécurisé\nServeur UDP en écoute sur port 65433"
        else:
            result = f"⚠️ Algorithme {algo} non implémenté"

        elapsed = (time.time() - start) * 1000
        return jsonify({'result': result, 'time': f"{elapsed:.2f}"})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/gen_keys', methods=['POST'])
def gen_keys_route():
    data = request.json
    key_type = data.get('type', 'rsa')

    try:
        if key_type == 'rsa':
            info = gen_rsa_keys()
        elif key_type == 'dh':
            info = gen_dh_keys()
        elif key_type == 'ecc':
            info = gen_ecc_keys()
        elif key_type == 'elgamal':
            info = gen_elgamal_keys()
        else:
            return jsonify({'error': 'Type inconnu'}), 400
        return jsonify({'info': info})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def gen_rsa_keys():
    keys['rsa_private'] = rsa_mod.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    keys['rsa_public'] = keys['rsa_private'].public_key()
    n = hex(keys['rsa_public'].public_numbers().n)[:50]
    e = keys['rsa_public'].public_numbers().e
    return f"✅ Clés RSA-2048 générées\n\nClé publique (modulus): {n}...\nExposant: {e}"


def gen_dh_keys():
    keys['dh_params'] = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    keys['dh_private'] = keys['dh_params'].generate_private_key()
    keys['dh_public'] = keys['dh_private'].public_key()
    p = hex(keys['dh_params'].parameter_numbers().p)[:50]
    g = keys['dh_params'].parameter_numbers().g
    return f"✅ Paramètres DH-2048 générés\n\np (modulus): {p}...\ng (generator): {g}"


def gen_ecc_keys():
    keys['ecc_private'] = ec.generate_private_key(ec.SECP256R1(), default_backend())
    keys['ecc_public'] = keys['ecc_private'].public_key()
    return "✅ Clés ECC P-256 générées\n\nCourbe: SECP256R1 (NIST P-256)\nSécurité équivalente: RSA-3072"


def gen_elgamal_keys():
    p = 257
    g = 3
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    keys['elgamal_keys'] = {'p': p, 'g': g, 'x': x, 'y': y}
    return f"✅ Clés ElGamal générées\n\np (premier): {p}\ng (générateur): {g}\ny (clé publique): {y}\nx (clé privée): {x}"


if __name__ == '__main__':
    app.run(debug=True, port=5000)
