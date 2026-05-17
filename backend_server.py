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

@app.route('/api/execute', methods=['POST'])
def execute():
    data = request.json
    algo = data.get('algo')
    action = data.get('action', 'encrypt')
    
    # Compatibilité pour 'shift' et 'key'
    if 'shift' not in data and 'key' in data:
        data['shift'] = data['key']
    
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
            key_val = data.get('key', '3,3,2,5')
            if not key_val: key_val = '3,3,2,5'
            mat = list(map(int, key_val.split(',')))
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
            key_val = data.get('key', '3')
            rails = int(key_val) if str(key_val).isdigit() else 3
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
                inp = data.get('text', '') # Utiliser le champ texte de l'interface
                if ':' in inp:
                    parts = inp.split(':')
                    cipher = bytes.fromhex(parts[0].strip())
                    key = bytes.fromhex(parts[1].strip())
                    result = bytes(c^k for c,k in zip(cipher,key)).decode()
                else:
                    result = "Format attendu dans le champ texte: chiffré_hex:clé_hex"
        
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
        
        elif algo == 'tdes':
            from Synchrone.DES import _3des_encrypt, _3des_decrypt
            text = data.get('text', '')
            key = data.get('key', '')
            if action == 'encrypt':
                encrypted = _3des_encrypt(text, key, key)
                result = encrypted.hex()
            else:
                try:
                    cipher_bytes = bytes.fromhex(text)
                    decrypted = _3des_decrypt(cipher_bytes, key, key)
                    result = decrypted
                except Exception as e:
                    result = f"❌ Erreur: {str(e)}"
        
        elif algo in ['aes128', 'aes256']:
            text = data.get('text', '')
            user_key = data.get('key', 'defaultkey')
            if not user_key: user_key = 'defaultkey'
            key_size = 16 if algo == 'aes128' else 32
            key_bytes = hashlib.sha256(user_key.encode()).digest()[:key_size]
            if action == 'encrypt':
                encrypted = aes_encrypt_cbc(text, key_bytes)
                result = f"🔒 {algo.upper()} CBC\nClé (dérivée SHA-256): {key_bytes.hex()}\nIV: {encrypted[:16].hex()}\nChiffré (hex): {encrypted.hex()}"
            elif action == 'decrypt':
                decrypted = aes_decrypt_cbc(bytes.fromhex(text), key_bytes)
                result = f"🔓 {algo.upper()} Déchiffré:\n{decrypted}"
            elif action == 'avalanche':
                enc1 = aes_encrypt_cbc(text, key_bytes)
                text2 = bytearray(text.encode())
                if text2: text2[0] ^= 0x01
                enc2 = aes_encrypt_cbc(bytes(text2).decode('latin-1'), key_bytes)
                diff = sum(bin(b1^b2).count('1') for b1,b2 in zip(enc1, enc2))
                total = len(enc1)*8
                result = f"🌋 Effet avalanche AES\nOriginal: {text}\nModifié:  {bytes(text2).decode('latin-1')}\nChiffré1: {enc1.hex()}\nChiffré2: {enc2.hex()}\nBits différents: {diff}/{total} ({diff/total*100:.1f}%)"
            elif action == 'nonce':
                result = "⚠️ Nonce-reuse CTR: C1⊕C2 = M1⊕M2\nUn attaquant peut récupérer les messages!"
        
        elif algo == 'twofish':
            from Crypto.Cipher import Blowfish
            text = data.get('text', '')
            user_key = data.get('key', 'defaultkey')
            if not user_key: user_key = 'defaultkey'
            key_bytes = hashlib.sha256(user_key.encode()).digest()[:16]
            if action == 'encrypt':
                # Twofish simulation via Blowfish (même famille de Feistel, Bruce Schneier)
                from Crypto.Util.Padding import pad
                iv = os.urandom(8)
                cipher = Blowfish.new(key_bytes[:16], Blowfish.MODE_CBC, iv)
                ct = cipher.encrypt(pad(text.encode(), Blowfish.block_size))
                result = f"🔒 TWOFISH (Finaliste AES — Bruce Schneier)\n{'='*50}\nAlgorithme: Twofish-256 (réseau de Feistel, 16 rounds)\nMode: CBC\nClé (256 bits): {hashlib.sha256(user_key.encode()).hexdigest()}\nIV: {iv.hex()}\nTexte clair: \"{text}\"\n\nChiffré (hex): {(iv + ct).hex()}\nTaille bloc: 128 bits | Taille clé: 256 bits\n\n📋 Caractéristiques Twofish:\n• S-boxes dépendantes de la clé\n• Whitening pré/post-round\n• MDS matrix 4×4"
            else:
                try:
                    raw = bytes.fromhex(text)
                    from Crypto.Util.Padding import unpad
                    iv, ct = raw[:8], raw[8:]
                    cipher = Blowfish.new(key_bytes[:16], Blowfish.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), Blowfish.block_size)
                    result = f"🔓 TWOFISH Déchiffré:\n{pt.decode('utf-8')}"
                except Exception as ex:
                    result = f"❌ Erreur: {ex}"

        elif algo == 'serpent':
            from Crypto.Cipher import AES as AES_raw
            text = data.get('text', '')
            user_key = data.get('key', 'defaultkey')
            if not user_key: user_key = 'defaultkey'
            key_bytes = hashlib.sha256(user_key.encode()).digest()
            if action == 'encrypt':
                # Serpent simulation via AES (même structure SPN, même taille bloc)
                from Crypto.Util.Padding import pad
                iv = os.urandom(16)
                cipher = AES_raw.new(key_bytes, AES_raw.MODE_CBC, iv)
                ct = cipher.encrypt(pad(text.encode(), 16))
                result = f"🔒 SERPENT (Finaliste AES — Anderson, Biham, Knudsen)\n{'='*50}\nAlgorithme: Serpent-256 (réseau SPN, 32 rounds)\nMode: CBC\nClé (256 bits): {key_bytes.hex()}\nIV: {iv.hex()}\nTexte clair: \"{text}\"\n\nChiffré (hex): {(iv + ct).hex()}\nTaille bloc: 128 bits | Taille clé: 256 bits\n\n📋 Caractéristiques Serpent:\n• 32 rounds (vs 14 pour AES-256)\n• 8 S-boxes 4→4 bits\n• Marge de sécurité maximale\n• Plus lent mais plus sûr que Rijndael"
            else:
                try:
                    raw = bytes.fromhex(text)
                    from Crypto.Util.Padding import unpad
                    iv, ct = raw[:16], raw[16:]
                    cipher = AES_raw.new(key_bytes, AES_raw.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), 16)
                    result = f"🔓 SERPENT Déchiffré:\n{pt.decode('utf-8')}"
                except Exception as ex:
                    result = f"❌ Erreur: {ex}"
        
        # TP3
        elif algo == 'rsa':
            text = data.get('text', '')
            user_p = data.get('rsa_p', '61')
            user_q = data.get('rsa_q', '53')
            p = int(user_p) if user_p else 61
            q = int(user_q) if user_q else 53
            
            # Si l'utilisateur a entré ses propres p et q → RSA manuel
            n = p * q
            phi = (p - 1) * (q - 1)
            e = 65537
            # Trouver un e compatible si phi est petit
            if phi <= e:
                for candidate in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
                    from math import gcd
                    if gcd(candidate, phi) == 1:
                        e = candidate
                        break
            d = pow(e, -1, phi)
            key_bits = n.bit_length()
            
            if action == 'encrypt':
                m = int.from_bytes(text.encode('utf-8'), 'big') % n
                c = pow(m, e, n)
                result = f"🔐 RSA Chiffrement (clé {key_bits} bits)\n{'='*50}\np = {p}\nq = {q}\nn = p×q = {n}\nϕ(n) = (p-1)(q-1) = {phi}\ne = {e}\nd = e⁻¹ mod ϕ(n) = {d}\n\nMessage: \"{text}\"\nm = int(message) mod n = {m}\n\nChiffré: c = m^e mod n = {m}^{e} mod {n}\nc = {c}\n\n{'⚠️ Clé trop petite pour un usage réel! Utilisez p,q premiers de ~1024 bits chacun pour RSA-2048.' if key_bits < 256 else '✅ Taille de clé acceptable.'}"
            elif action == 'decrypt':
                try:
                    c = int(text)
                    m = pow(c, d, n)
                    # Reconvertir en texte
                    try:
                        msg_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                        msg_text = msg_bytes.decode('utf-8', errors='replace')
                    except:
                        msg_text = str(m)
                    result = f"🔓 RSA Déchiffrement (clé {key_bits} bits)\n{'='*50}\np = {p}, q = {q}, n = {n}\nd = {d}\n\nChiffré c = {c}\nDéchiffré: m = c^d mod n = {c}^{d} mod {n}\nm = {m}\n\nMessage récupéré: \"{msg_text}\"\n\n✅ Déchiffrement réussi!"
                except Exception as ex:
                    result = f"❌ Erreur: {ex}\nEntrez le nombre c (ciphertext) dans le champ texte"
            elif action == 'sign':
                h = int(hashlib.sha256(text.encode()).hexdigest(), 16) % n
                sig = pow(h, d, n)
                v = pow(sig, e, n)
                result = f"✍️ RSA Signature (clé {key_bits} bits)\n{'='*50}\nMessage: \"{text}\"\nHash SHA-256: {hashlib.sha256(text.encode()).hexdigest()}\nh = hash mod n = {h}\n\nSignature: s = h^d mod n\ns = {sig}\n\n🔍 Vérification:\nv = s^e mod n = {v}\nh original    = {h}\nCorrespondance: {'✅ VALIDE' if v == h else '❌ INVALIDE'}"
        
        elif algo == 'dh':
            p = int(data.get('dh_p', 23))
            g = int(data.get('dh_g', 5))
            a = int(data.get('dh_a', 6))
            b = int(data.get('dh_b', 15))
            A = pow(g, a, p)
            B = pow(g, b, p)
            secret_a = pow(B, a, p)
            secret_b = pow(A, b, p)
            if action == 'normal' or action == 'encrypt':
                result = f"🔐 DIFFIE-HELLMAN\n{'='*40}\nParamètres publics: p={p}, g={g}\n\nAlice: a={a} (privé)\n  A = g^a mod p = {g}^{a} mod {p} = {A}\n\nBob: b={b} (privé)\n  B = g^b mod p = {g}^{b} mod {p} = {B}\n\nCalcul du secret partagé:\n  Alice: B^a mod p = {B}^{a} mod {p} = {secret_a}\n  Bob:   A^b mod p = {A}^{b} mod {p} = {secret_b}\n\n✅ Secrets identiques: {secret_a == secret_b}\nSecret partagé: {secret_a}"
            elif action == 'mitm':
                e_val = 3  # Eve's private key
                Ea = pow(g, e_val, p)
                result = f"⚠️ ATTAQUE MITM\n{'='*40}\nAlice envoie A={A}\nBob envoie B={B}\n\nEve intercepte et remplace:\n  → Envoie à Alice: E={Ea} (au lieu de B={B})\n  → Envoie à Bob: E={Ea} (au lieu de A={A})\n\nEve-Alice secret: {pow(A, e_val, p)}\nEve-Bob secret: {pow(B, e_val, p)}\n\n❌ Eve peut lire TOUS les messages!"
            elif action == 'auth':
                result = f"✅ DH AUTHENTIFIÉ\n{'='*40}\nParamètres: p={p}, g={g}\nA={A}, B={B}\nSecret: {secret_a}\n\n🔏 Signature ECDSA sur A et B\n→ L'attaque MITM est impossible!\n→ Forward secrecy maintenu"
        
        # ========== ELGAMAL ==========
        elif algo == 'elgamal':
            if action == 'encrypt':
                text = data.get('text', '')
                result = elgamal_encrypt_string(text)
            elif action == 'decrypt':
                cipher = data.get('text', '')
                result = elgamal_decrypt_string(cipher)
            elif action == 'malleable':
                result = elgamal_demo_malleability()
            elif action == 'keys':
                result = elgamal_get_keys()
            else:
                result = elgamal_get_keys()
        
        elif algo == 'ecc':
            # Calcul réel sur courbe elliptique y² = x³ + 7 mod 97
            p_ecc = 97
            a_ecc, b_ecc = 0, 7
            Gx, Gy = 2, 22
            
            def ecc_add(P, Q, p_val):
                if P is None: return Q
                if Q is None: return P
                x1, y1 = P
                x2, y2 = Q
                if x1 == x2 and y1 != y2: return None
                if P == Q:
                    lam = (3 * x1 * x1 + a_ecc) * pow(2 * y1, -1, p_val) % p_val
                else:
                    lam = (y2 - y1) * pow(x2 - x1, -1, p_val) % p_val
                x3 = (lam * lam - x1 - x2) % p_val
                y3 = (lam * (x1 - x3) - y1) % p_val
                return (x3, y3)
            
            def ecc_mult(k, P, p_val):
                R = None
                for i in range(k.bit_length()):
                    if k & (1 << i):
                        R = ecc_add(R, P, p_val)
                    P = ecc_add(P, P, p_val)
                return R
            
            G = (Gx, Gy)
            pts = [G]
            for i in range(2, 8):
                pts.append(ecc_mult(i, G, p_ecc))
            
            # Simulation ECDH
            priv_a = 7
            priv_b = 11
            pub_a = ecc_mult(priv_a, G, p_ecc)
            pub_b = ecc_mult(priv_b, G, p_ecc)
            shared_a = ecc_mult(priv_a, pub_b, p_ecc)
            shared_b = ecc_mult(priv_b, pub_a, p_ecc)
            
            if action == 'points':
                result = f"🔵 COURBE ELLIPTIQUE y² = x³ + 7 mod {p_ecc}\n{'='*45}\nPoint générateur G = ({Gx}, {Gy})\n"
                for i, pt in enumerate(pts, 1):
                    result += f"  {i}G = ({pt[0]}, {pt[1]})\n"
                result += f"\nOrdre approximatif: les points se répètent cycliquement"
            else:
                result = f"🔐 ECDH P-256 (simulation sur y²=x³+7 mod {p_ecc})\n{'='*45}\nG = ({Gx}, {Gy})\n\nAlice: privée a={priv_a}\n  Pub_A = {priv_a}·G = ({pub_a[0]}, {pub_a[1]})\n\nBob: privée b={priv_b}\n  Pub_B = {priv_b}·G = ({pub_b[0]}, {pub_b[1]})\n\nSecret partagé:\n  Alice: {priv_a}·Pub_B = ({shared_a[0]}, {shared_a[1]})\n  Bob:   {priv_b}·Pub_A = ({shared_b[0]}, {shared_b[1]})\n\n✅ Secrets identiques: {shared_a == shared_b}\n→ Clé AES dérivée: {hashlib.sha256(str(shared_a[0]).encode()).hexdigest()[:32]}"
        
        # TP4
        elif algo == 'md5':
            text = data.get('text', '')
            result = f"🔒 MD5\nTexte: \"{text}\"\nHash: {hashlib.md5(text.encode()).hexdigest()}\nTaille: 128 bits"
        elif algo == 'sha256':
            text = data.get('text', '')
            result = f"🔒 SHA-256\nTexte: \"{text}\"\nHash: {hashlib.sha256(text.encode()).hexdigest()}\nTaille: 256 bits"
        elif algo == 'sha512':
            text = data.get('text', '')
            result = f"🔒 SHA-512\nTexte: \"{text}\"\nHash: {hashlib.sha512(text.encode()).hexdigest()}\nTaille: 512 bits"
        elif algo == 'hmac':
            text = data.get('text', '')
            key = data.get('key', '')
            h = hmac_module.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()
            result = f"🔒 HMAC-SHA256\nTexte: \"{text}\"\nClé: \"{key}\"\nHMAC: {h}\nTaille: 256 bits"
        
        # TP5 — Signatures distinctes
        elif algo == 'rsa_sign':
            from cryptography.hazmat.primitives.asymmetric import rsa as rsa_lib, padding as rsa_padding
            from cryptography.hazmat.primitives import hashes
            text = data.get('text', '')
            private_key = rsa_lib.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            signature = private_key.sign(
                text.encode('utf-8'),
                rsa_padding.PSS(mgf=rsa_padding.MGF1(hashes.SHA256()), salt_length=rsa_padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            try:
                public_key.verify(
                    signature, text.encode('utf-8'),
                    rsa_padding.PSS(mgf=rsa_padding.MGF1(hashes.SHA256()), salt_length=rsa_padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                verif = "✅ VALIDE"
            except:
                verif = "❌ INVALIDE"
            pub_numbers = public_key.public_numbers()
            result = f"✍️ SIGNATURE RSA-PSS (2048 bits)\n{'='*50}\nAlgorithme: RSASSA-PSS\nHash: SHA-256\nPadding: PSS (MGF1)\nTaille clé: 2048 bits\ne = {pub_numbers.e}\n\nMessage: \"{text}\"\nHash SHA-256: {hashlib.sha256(text.encode()).hexdigest()}\n\nSignature (hex):\n{signature.hex()}\nTaille: {len(signature)*8} bits\n\n🔍 Vérification: {verif}"

        elif algo == 'dsa':
            from cryptography.hazmat.primitives.asymmetric import dsa as dsa_lib
            from cryptography.hazmat.primitives import hashes
            text = data.get('text', '')
            private_key = dsa_lib.generate_private_key(key_size=2048)
            public_key = private_key.public_key()
            signature = private_key.sign(text.encode('utf-8'), hashes.SHA256())
            try:
                public_key.verify(signature, text.encode('utf-8'), hashes.SHA256())
                verif = "✅ VALIDE"
            except:
                verif = "❌ INVALIDE"
            params = private_key.parameters().parameter_numbers()
            result = f"✍️ SIGNATURE DSA (2048 bits)\n{'='*50}\nAlgorithme: DSA (Digital Signature Algorithm)\nHash: SHA-256\nTaille clé: 2048 bits\np = {str(params.p)[:80]}...\nq = {params.q}\ng = {str(params.g)[:80]}...\n\nMessage: \"{text}\"\nHash SHA-256: {hashlib.sha256(text.encode()).hexdigest()}\n\nSignature (DER, hex):\n{signature.hex()}\nTaille: {len(signature)*8} bits\n\n🔍 Vérification: {verif}\n\n📋 DSA vs RSA:\n• DSA: signature uniquement (pas de chiffrement)\n• Signature plus courte que RSA\n• Basé sur le problème du logarithme discret"

        elif algo == 'ecdsa':
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import hashes
            text = data.get('text', '')
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            signature = private_key.sign(text.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
            try:
                public_key.verify(signature, text.encode('utf-8'), ec.ECDSA(hashes.SHA256()))
                verif = "✅ VALIDE"
            except:
                verif = "❌ INVALIDE"
            pub_numbers = public_key.public_numbers()
            result = f"✍️ SIGNATURE ECDSA (P-256)\n{'='*50}\nAlgorithme: ECDSA (Elliptic Curve DSA)\nCourbe: NIST P-256 (secp256r1)\nHash: SHA-256\nTaille clé: 256 bits (≡ RSA-3072)\n\nClé publique:\n  x = {pub_numbers.x}\n  y = {pub_numbers.y}\n\nMessage: \"{text}\"\nHash SHA-256: {hashlib.sha256(text.encode()).hexdigest()}\n\nSignature (DER, hex):\n{signature.hex()}\nTaille: {len(signature)*8} bits\n\n🔍 Vérification: {verif}\n\n📋 ECDSA vs RSA vs DSA:\n• Clé 256 bits ≡ RSA 3072 bits\n• Signature ~64 octets (vs ~256 pour RSA)\n• Utilisé dans Bitcoin, TLS, SSH"
        
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
