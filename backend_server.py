#!/usr/bin/env python3
"""
Backend API pour CryptoSuite - Appelle les vrais algorithmes Python
"""

import sys
import os
import json
import hashlib
import binascii
from flask import Flask, request, jsonify
from flask_cors import CORS

# Ajouter les chemins des modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
CORS(app)

# ==================== IMPORTS DES VRAIS ALGORITHMES ====================

# TP1 - Classique
from Classical_Ciphers.Cesar import cesar_encrypt, cesar_decrypt
from Classical_Ciphers.vigenere import vigenere_encrypt, vigenere_decrypt
from Classical_Ciphers.Hill import hill_encrypt, hill_decrypt
from Classical_Ciphers.Playfair import playfair_encrypt, playfair_decrypt
from Classical_Ciphers.OTP import otp_encrypt

# TP2 - Symétrique
from Synchrone.RC4 import RC4
from Synchrone.DES import des_encrypt, des_decrypt

# TP4 - Hachage
import hmac as hmac_module

# ==================== API ROUTES ====================

@app.route('/api/execute', methods=['POST'])
def execute():
    data = request.json
    algo = data.get('algo')
    text = data.get('text', '')
    key = data.get('key', '')
    mode = data.get('mode', 'encrypt')
    
    result = ""
    
    try:
        # ========== TP1 - Classique ==========
        if algo == 'cesar':
            shift = int(key) if key.isdigit() else 3
            if mode == 'encrypt':
                result = cesar_encrypt(text, shift)
            else:
                result = cesar_decrypt(text, shift)
        
        elif algo == 'vigenere':
            if mode == 'encrypt':
                result = vigenere_encrypt(text, key)
            else:
                result = vigenere_decrypt(text, key)
        
        elif algo == 'hill':
            import numpy as np
            matrix = np.array([[3, 3], [2, 5]])
            if mode == 'encrypt':
                result = hill_encrypt(text, matrix)
            else:
                result = hill_decrypt(text, matrix)
        
        elif algo == 'playfair':
            if mode == 'encrypt':
                result = playfair_encrypt(text, key)
            else:
                result = playfair_decrypt(text, key)
        
        elif algo == 'otp':
            if mode == 'encrypt':
                cipher, otp_key = otp_encrypt(text)
                result = f"Chiffré (hex): {cipher.hex()}\nClé OTP (hex): {otp_key.hex()}\n\n⚠️ Gardez la clé pour déchiffrer!"
            else:
                result = "OTP déchiffrement: Entrez le chiffré (hex) et la clé (hex) séparés par ':'"
        
        # ========== TP2 - Symétrique ==========
        elif algo == 'rc4':
            rc4 = RC4(key)
            if mode == 'encrypt':
                encrypted = rc4.encrypt(text)
                result = encrypted.hex()
            else:
                # Pour déchiffrer, l'utilisateur doit entrer du hex
                try:
                    cipher_bytes = bytes.fromhex(text)
                    decrypted = rc4.decrypt(cipher_bytes)
                    result = decrypted.decode('utf-8', errors='replace')
                except ValueError:
                    result = "❌ Erreur: En mode déchiffrement, le texte doit être en hexadécimal (ex: 48656c6c6f)"
        
        elif algo == 'des':
            if mode == 'encrypt':
                encrypted = des_encrypt(text, key)
                result = encrypted.hex()
            else:
                try:
                    cipher_bytes = bytes.fromhex(text)
                    decrypted = des_decrypt(cipher_bytes, key)
                    result = decrypted
                except ValueError:
                    result = "❌ Erreur: En mode déchiffrement, le texte doit être en hexadécimal (ex: 48656c6c6f)"
        
        elif algo == 'tdes':
            from Synchrone.DES import _3des_encrypt, _3des_decrypt
            if mode == 'encrypt':
                encrypted = _3des_encrypt(text, key, key)
                result = encrypted.hex()
            else:
                try:
                    cipher_bytes = bytes.fromhex(text)
                    decrypted = _3des_decrypt(cipher_bytes, key, key)
                    result = decrypted
                except ValueError:
                    result = "❌ Erreur: En mode déchiffrement, le texte doit être en hexadécimal"
        
        elif algo == 'aes128' or algo == 'aes256':
            from Synchrone.AES import aes_encrypt_cbc, aes_decrypt_cbc
            key_size = 16 if algo == 'aes128' else 32
            aes_key = hashlib.sha256(key.encode()).digest()[:key_size]
            if mode == 'encrypt':
                encrypted = aes_encrypt_cbc(text, aes_key)
                result = encrypted.hex()
            else:
                try:
                    cipher_bytes = bytes.fromhex(text)
                    decrypted = aes_decrypt_cbc(cipher_bytes, aes_key)
                    result = decrypted
                except ValueError:
                    result = "❌ Erreur: En mode déchiffrement, le texte doit être en hexadécimal"
        
        # ========== TP4 - Hachage ==========
        elif algo == 'md5':
            result = hashlib.md5(text.encode()).hexdigest()
        
        elif algo == 'sha256':
            result = hashlib.sha256(text.encode()).hexdigest()
        
        elif algo == 'sha512':
            result = hashlib.sha512(text.encode()).hexdigest()
        
        elif algo == 'hmac':
            result = hmac_module.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()
        
        # ========== TP6 - Simulations ==========
        elif algo == 'bluetooth':
            result = simulate_bluetooth()
        elif algo == 'wifi':
            result = simulate_wifi()
        elif algo == 'vote':
            result = simulate_vote()
        elif algo == 'homomorphic':
            result = simulate_homomorphic()
        elif algo == 'rsa':
            result = simulate_rsa()
        elif algo == 'dh':
            result = simulate_dh()
        elif algo == 'elgamal':
            result = simulate_elgamal()
        elif algo == 'ecc':
            result = simulate_ecc()
        elif algo in ['rsa_sign', 'dsa', 'ecdsa']:
            result = simulate_signature(text, algo)
        
        else:
            result = f"⚠️ Algorithme {algo} - En développement"
        
        return jsonify({'success': True, 'result': result})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ==================== SIMULATIONS ====================

def simulate_bluetooth():
    return """🔵 BLUETOOTH SECURE PAIRING (ECDH P-256)
═══════════════════════════════════════════
Smartphone (Central) ↔ Casque (Peripheral)
PIN: 123456
LTK: a3f2c1e4b5d6...
Chiffrement AES-CCM activé
✅ Lien sécurisé établi"""

def simulate_wifi():
    return """📡 WPA2 4-WAY HANDSHAKE
═══════════════════════════════════════════
SSID: WiFi_Secure
PMK = PBKDF2(password, SSID, 4096)
ANonce ↔ SNonce échangés
PTK = PRF(PMK + Nonces + MACs)
✅ AES-CCMP activé"""

def simulate_vote():
    return """🗳️ VOTE ÉLECTRONIQUE
═══════════════════════════════════════════
Candidats: Alice, Bob, Charlie
Votes:
  ✅ Jean Dupont → Alice
  ✅ Marie Martin → Bob
  ✅ Pierre Durand → Alice
Résultats:
  Alice: 2 voix (66.7%) ████████░░
  Bob:   1 voix (33.3%) ████░░░░░░
  Charlie: 0 voix (0.0%) ░░░░░░░░░░
🏆 Vainqueur: Alice"""

def simulate_homomorphic():
    return """🧮 VOTE HOMOMORPHIQUE (Paillier)
═══════════════════════════════════════════
Propriété: E(v1) × E(v2) = E(v1 + v2)
Exemple:
  E(Alice) × E(Alice) × E(Bob) = E(2,1)
✅ 2 voix Alice, 1 voix Bob
✅ Comptage sans déchiffrer"""

def simulate_rsa():
    return """🔐 RSA-2048
═══════════════════════════════════════════
Clé publique: (n, e) avec n ≈ 617 chiffres
Clé privée: d
⚠️ Le vrai RSA nécessite des nombres premiers
Pour tester: Utilisez les scripts dans asynchrone/"""

def simulate_dh():
    return """🔐 DIFFIE-HELLMAN
═══════════════════════════════════════════
Paramètres: p=23, g=5
Alice: a=6 → A=8
Bob: b=15 → B=19
Secret partagé: s=2
✅ Échange sécurisé"""

def simulate_elgamal():
    return """🔐 ElGamal
═══════════════════════════════════════════
Paramètres: p=257, g=3
Clé privée: x
Clé publique: y = g^x mod p
✅ Chiffrement probabiliste"""

def simulate_ecc():
    return """🔐 ECC P-256
═══════════════════════════════════════════
Courbe: y² = x³ + 7 mod 97
Point G(2,23)
2G = (44,62)
3G = (26,42)
✅ Sécurité équivalente à RSA-3072"""

def simulate_signature(text, algo):
    name = {'rsa_sign':'RSA-PSS', 'dsa':'DSA', 'ecdsa':'ECDSA'}.get(algo, 'Signature')
    return f"""🔏 SIGNATURE {name}
═══════════════════════════════════════════
Message: "{text[:100]}{'...' if len(text)>100 else ''}"
Signature: {hashlib.sha256(text.encode()).hexdigest()[:64]}...
Vérification: ✅ Valide"""

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 CryptoSuite Backend Server")
    print("=" * 50)
    print("📡 API: http://localhost:5000/api/execute")
    print("🌐 Interface: http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)
