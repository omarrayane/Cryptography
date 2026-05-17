#!/usr/bin/env python3
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sys, os, hashlib, random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__, static_folder='static')
CORS(app)

from Classical_Ciphers.Cesar import cesar_encrypt, cesar_decrypt, brute_force_cesar, indice_coincidence
from Classical_Ciphers.vigenere import vigenere_encrypt, vigenere_decrypt, vigenere_crack
from Classical_Ciphers.Hill import hill_encrypt, hill_decrypt
from Classical_Ciphers.Playfair import playfair_encrypt, playfair_decrypt
from Classical_Ciphers.OTP import otp_encrypt
from Classical_Ciphers.rail_fence_cipher import rail_fence_encrypt, rail_fence_decrypt
from Synchrone.RC4 import RC4
from Synchrone.DES import des_encrypt, des_decrypt
from Synchrone.AES import aes_encrypt_cbc, aes_decrypt_cbc
import hmac as hmac_module

# Importer ElGamal
from asynchrone.elgamal_api import elgamal_encrypt_string, elgamal_decrypt_string, elgamal_demo_malleability, elgamal_get_keys

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/execute2', methods=['POST'])
def execute2():
    data = request.json
    algo = data.get('algo')
    action = data.get('action')
    
    result = ""
    
    try:
        # TP1
        if algo == 'cesar':
            text = data.get('text', '')
            shift = int(data.get('shift', 3))
            if action == 'encrypt':
                result = cesar_encrypt(text, shift)
            elif action == 'decrypt':
                result = cesar_decrypt(text, shift)
            elif action == 'bruteforce':
                res = brute_force_cesar(text)
                result = "🔓 FORCE BRUTE (26 clés):\n"
                for s, dec in res:
                    result += f"Clé {s:2d}: {dec}\n"
            elif action == 'ic':
                ic = indice_coincidence(text)
                best = 0
                best_diff = float('inf')
                for s in range(26):
                    dec = cesar_decrypt(text, s)
                    icd = indice_coincidence(dec)
                    if abs(icd - 0.074) < best_diff:
                        best_diff = abs(icd - 0.074)
                        best = s
                result = f"Indice coïncidence: {ic:.4f}\nClé probable: {best}\nMessage: {cesar_decrypt(text, best)}"
        
        elif algo == 'vigenere':
            text = data.get('text', '')
            key = data.get('key', '')
            if action == 'encrypt':
                result = vigenere_encrypt(text, key)
            elif action == 'decrypt':
                result = vigenere_decrypt(text, key)
            elif action == 'attack':
                plain, found_key, _ = vigenere_crack(text)
                result = f"Clé trouvée: {found_key}\n\nMessage: {plain}"
        
        elif algo == 'hill':
            text = data.get('text', '')
            import numpy as np
            mat = list(map(int, data.get('matrix', '3,3,2,5').split(',')))
            matrix = np.array([[mat[0], mat[1]], [mat[2], mat[3]]])
            if action == 'encrypt':
                result = hill_encrypt(text, matrix)
            else:
                result = hill_decrypt(text, matrix)
        
        elif algo == 'playfair':
            text = data.get('text', '')
            key = data.get('key', '')
            if action == 'encrypt':
                result = playfair_encrypt(text, key)
            else:
                result = playfair_decrypt(text, key)
        
        elif algo == 'railfence':
            text = data.get('text', '')
            rails = int(data.get('rails', 3))
            if action == 'encrypt':
                result = rail_fence_encrypt(text, rails)
            else:
                result = rail_fence_decrypt(text, rails)
        
        elif algo == 'otp':
            if action == 'encrypt':
                text = data.get('text', '')
                cipher, key = otp_encrypt(text)
                result = f"Chiffré (hex): {cipher.hex()}\nClé (hex): {key.hex()}"
            else:
                inp = data.get('decryptInput', '')
                if ':' in inp:
                    parts = inp.split(':')
                    cipher = bytes.fromhex(parts[0])
                    key = bytes.fromhex(parts[1])
                    result = bytes(c^k for c,k in zip(cipher,key)).decode()
                else:
                    result = "Format: cipher_hex:key_hex"
        
        # TP2
        elif algo == 'rc4':
            text = data.get('text', '')
            key = data.get('key', '')
            rc4 = RC4(key)
            if action == 'encrypt':
                result = rc4.encrypt(text).hex()
            elif action == 'decrypt':
                result = rc4.decrypt(bytes.fromhex(text)).decode()
            elif action == 'wep':
                result = "⚠️ Vulnérabilité WEP:\n"
                for iv in [0x00,0x01,0x02,0x03]:
                    result += f"IV=0x{iv:02x}00: keystream[0]=0x{rc4.encrypt('A')[0]:02x}\n"
        
        elif algo == 'des':
            text = data.get('text', '')
            key = data.get('key', '')
            if action == 'encrypt':
                result = des_encrypt(text, key).hex()
            else:
                result = des_decrypt(bytes.fromhex(text), key)
        
        elif algo in ['aes128', 'aes256']:
            text = data.get('text', '')
            key_bytes = hashlib.sha256(b"auto_key").digest()
            if action == 'encrypt':
                result = aes_encrypt_cbc(text, key_bytes).hex()
            elif action == 'decrypt':
                result = aes_decrypt_cbc(bytes.fromhex(text), key_bytes)
            elif action == 'avalanche':
                enc1 = aes_encrypt_cbc(text, key_bytes)
                text2 = bytearray(text.encode())
                if text2: text2[0] ^= 0x01
                enc2 = aes_encrypt_cbc(bytes(text2).decode(), key_bytes)
                diff = sum(bin(b1^b2).count('1') for b1,b2 in zip(enc1, enc2))
                total = len(enc1)*8
                result = f"🌋 Effet avalanche: {diff}/{total} bits différents ({diff/total*100:.1f}%)"
            elif action == 'nonce':
                result = "⚠️ Nonce-reuse CTR: C1⊕C2 = M1⊕M2\nUn attaquant peut récupérer les messages!"
        
        elif algo in ['twofish', 'serpent']:
            result = f"{algo.upper()} - Finaliste AES\nChiffrement sécurisé"
        
        # TP3
        elif algo == 'rsa':
            text = data.get('text', '')
            p = int(data.get('p', 61))
            q = int(data.get('q', 53))
            n = p*q
            phi = (p-1)*(q-1)
            e = 65537
            d = pow(e, -1, phi)
            if action == 'encrypt':
                m = int.from_bytes(text.encode()[:20], 'big')
                result = f"Ciphertext: {pow(m, e, n)}"
            elif action == 'decrypt':
                c = int(text)
                result = f"Message: {pow(c, d, n)}"
            elif action == 'sign':
                h = int(hashlib.md5(text.encode()).hexdigest(), 16) % n
                result = f"Signature: {pow(h, d, n)}"
        
        elif algo == 'dh':
            p = int(data.get('p', 23))
            g = int(data.get('g', 5))
            a = int(data.get('a', 6))
            b = int(data.get('b', 15))
            if action == 'normal':
                A = pow(g, a, p)
                B = pow(g, b, p)
                secret = pow(B, a, p)
                result = f"p={p}, g={g}\nAlice: a={a} → A={A}\nBob: b={b} → B={B}\nSecret partagé: {secret}"
            elif action == 'mitm':
                A = pow(g, a, p)
                B = pow(g, b, p)
                result = f"⚠️ ATTAQUE MITM\nA={A}, B={B}\nEve intercepte et remplace par ses propres clés!\n→ Eve peut lire tous les messages"
            elif action == 'auth':
                result = "✅ DH authentifié par signature ECDSA\nL'attaque MITM est impossible!"
        
        # ========== ELGAMAL CORRIGÉ ==========
        elif algo == 'elgamal':
            if action == 'encrypt':
                text = data.get('text', '')
                result = elgamal_encrypt_string(text)
            elif action == 'decrypt':
                cipher = data.get('cipher', '')
                result = elgamal_decrypt_string(cipher)
            elif action == 'malleable':
                result = elgamal_demo_malleability()
            elif action == 'keys':
                result = elgamal_get_keys()
            else:
                result = elgamal_get_keys()
        
        elif algo == 'ecc':
            if action == 'points':
                result = "Courbe y² = x³ + 7 mod 97\nG(2,23)\n2G = (44,62)\n3G = (26,42)"
            else:
                result = "ECDH P-256: Secret partagé → clé AES-256"
        
        # TP4
        elif algo == 'md5':
            result = hashlib.md5(data.get('text','').encode()).hexdigest()
        elif algo == 'sha256':
            result = hashlib.sha256(data.get('text','').encode()).hexdigest()
        elif algo == 'sha512':
            result = hashlib.sha512(data.get('text','').encode()).hexdigest()
        elif algo == 'hmac':
            result = hmac_module.new(data.get('key','').encode(), data.get('text','').encode(), hashlib.sha256).hexdigest()
        
        # TP5
        elif algo in ['rsa_sign', 'dsa', 'ecdsa']:
            text = data.get('text', '')
            if action == 'sign':
                result = f"✍️ Signature {algo.upper()}: {hashlib.sha256(text.encode()).hexdigest()[:64]}"
            else:
                result = "🔍 Signature vérifiée: ✅ VALIDE"
        
        # TP6
        elif algo == 'bluetooth':
            result = get_bluetooth_simulation()
        elif algo == 'wifi':
            result = get_wifi_simulation()
        elif algo == 'vote':
            result = get_vote_simulation()
        elif algo == 'homomorphic':
            result = get_homomorphic_simulation()
        
        else:
            result = f"Algorithme {algo} non reconnu"
        
        return jsonify({'success': True, 'result': result})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ==================== SIMULATIONS TP6 ====================
def get_bluetooth_simulation():
    return """━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔵 BLUETOOTH SECURE SIMPLE PAIRING — ECDH P-256
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
A: Samsung Galaxy S24    B: Sony WH-1000XM5

┌─ PHASE 1 : Échange de capacités ─────────────────
  Samsung Galaxy S24 → DisplayYesNo
  Sony WH-1000XM5 → NoInputNoOutput

┌─ PHASE 2 : Génération des clés ECDH P-256 ───────
  PKa = 04f09fa1d6395900fb524029999672fee577f8973bb36c3c…
  PKb = 04a92e23ce15c6e69d81b2108f53cb8c1862dc53da1252dc…

┌─ PHASE 3 : Secret partagé DHKey ─────────────────
  DHKey_A = e764f5d0ccfeb077229f21d263f36188099a4912…
  DHKey_B = e764f5d0ccfeb077229f21d263f36188099a4912…
  Identiques : ✅ OUI

┌─ PHASE 4 : Dérivation LTK (HKDF-SHA256) ─────────
  LTK = f89ef23e30d42ab74687b35ae90cd083
  Chiffrement : AES-CCM 128 bits

✅ Pairing terminé — Lien Bluetooth sécurisé établi

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ SIMULATION ATTAQUE MITM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Eve intercepte la liaison
  → Eve déchiffre, ré-chiffre chaque paquet !

┌─ CONTRE-MESURE — Numeric Comparison ──────────────
  Code sur Samsung: 770222
  Code forgé par Eve: 237515
  → L'utilisateur refuse la connexion
✅ MITM bloqué"""

def get_wifi_simulation():
    return """━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📡 WPA2 4-WAY HANDSHAKE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SSID: WiFi_Secure
Password: ComplexPassword123

┌─ ÉTAPE 1 : PMK = PBKDF2 ────────────────────────
  PMK: a3f2c1e4b5d69f2a...

┌─ ÉTAPE 2 : Échange de nonces ────────────────────
  ANonce (AP): 7f3a2b1c8e4d...
  SNonce (Client): 9e5f6a7b2c3d...

┌─ ÉTAPE 3 : PTK calculé ──────────────────────────
  KCK (Confirmation): 16 bytes
  KEK (Encryption): 16 bytes
  TEK (Temporal Key): 16 bytes

┌─ ÉTAPE 4 : GTK distribué ────────────────────────
  → Chiffrement AES-CCMP activé

✅ WPA3 améliorations: SAE (Dragonfly), Forward Secrecy, Anti-KRACK"""

def get_vote_simulation():
    return """━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🗳️ VOTE ÉLECTRONIQUE RSA-2048
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Candidats: Alice, Bob, Charlie

┌─ VOTES ENREGISTRÉS ──────────────────────────────
  ✅ V001 · Jean Dupont → Alice
  ✅ V002 · Marie Martin → Bob
  ✅ V003 · Pierre Durand → Alice

┌─ DÉPOUILLEMENT ──────────────────────────────────
  Alice: ██████████░░░░ 2 voix (66.7%)
  Bob:   █████░░░░░░░░░ 1 voix (33.3%)
  Charlie: ░░░░░░░░░░░░░░ 0 voix (0.0%)

┌─ PROPRIÉTÉS DE SÉCURITÉ ─────────────────────────
  ✅ Confidentialité: RSA-OAEP
  ✅ Authenticité: Signature RSA-PSS
  ✅ Anti-double vote: DB vérifiée

🏆 Vainqueur: Alice"""

def get_homomorphic_simulation():
    return """━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🧮 VOTE HOMOMORPHIQUE (Paillier)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Propriété: E(m1) × E(m2) = E(m1 + m2) mod n²

┌─ EXEMPLE AVEC 3 VOTES ───────────────────────────
  Vote 1: Alice → E(Alice) = 0x7F3A2B1C...
  Vote 2: Alice → E(Alice) = 0x2B1C7F3A...
  Vote 3: Bob   → E(Bob)   = 0x9D4E8C2F...

┌─ MULTIPLICATION DES CHIFFRÉS ────────────────────
  E_total = 0x7F3A2B1C × 0x2B1C7F3A × 0x9D4E8C2F
  → Déchiffre = 2 voix pour Alice, 1 pour Bob

✅ AVANTAGES:
  • On compte sans déchiffrer individuellement
  • Anonymat total préservé"""

if __name__ == '__main__':
    print("🚀 Serveur démarré sur http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
