# elgamal_api.py - Interface simple pour ElGamal
from asynchrone.ElGamal import ElGamal

_elgamal_instance = None

def get_elgamal():
    global _elgamal_instance
    if _elgamal_instance is None:
        _elgamal_instance = ElGamal(key_bits=256)  # petit pour vitesse
    return _elgamal_instance

def elgamal_encrypt_string(text):
    elg = get_elgamal()
    result = []
    for c in text:
        c1, c2 = elg.encrypt(ord(c))
        result.append(f"({c1},{c2})")
    return str(result)

def elgamal_decrypt_string(cipher_str):
    elg = get_elgamal()
    # Parse format "[(c1,c2), (c1,c2), ...]"
    import ast
    pairs = ast.literal_eval(cipher_str)
    result = ""
    for c1, c2 in pairs:
        m = elg.decrypt(c1, c2)
        result += chr(m)
    return result

def elgamal_demo_malleability():
    elg = get_elgamal()
    M = 12345
    c1, c2 = elg.encrypt(M)
    c2_forged = (2 * c2) % elg.p
    M_forged = elg.decrypt(c1, c2_forged)
    return f"""⚠️ MALLÉABILITÉ D'ELGAMAL

Message original: {M}
Chiffré: (c1={c1}, c2={c2})
Attaque: forger E(2M) = (c1, 2*c2 mod p)
Résultat déchiffré: {M_forged}
2M = {2*M}

✅ Vérifié: Un attaquant peut modifier le ciphertext sans connaître la clé!"""

def elgamal_get_keys():
    elg = get_elgamal()
    return f"""🔑 CLÉS ELGAMAL

p (nombre premier): {elg.p}
g (générateur): {elg.g}
y (clé publique): {elg.y}
x (clé privée): {elg.x}

Chiffrement: c1 = g^k mod p, c2 = m * y^k mod p
Déchiffrement: m = c2 * (c1^x)^(-1) mod p"""
