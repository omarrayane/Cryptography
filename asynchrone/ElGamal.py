import random

# ============================================================
#  ElGamal Encryption (implémentation pédagogique)
# ============================================================

def mod_inverse(a, p):
    """
    Calcule l'inverse modulaire de a modulo p en utilisant
    le petit théorème de Fermat (puisque p est premier) :
    a^(p-1) ≡ 1 (mod p)  =>  a * a^(p-2) ≡ 1 (mod p)
    """
    return pow(a, p - 2, p)

def generate_keys():
    """
    Génère les clés publique et privée pour ElGamal.
    (Valeurs pédagogiques)
    """
    # Choisir un nombre premier p > 255 pour pouvoir chiffrer des caractères ASCII (0-255)
    p = 257
    # g est une racine primitive modulo 257
    g = 3

    # Choisir la clé privée (a)
    a = random.randint(2, p - 2)

    # Calculer la clé publique (A = g^a mod p)
    A = pow(g, a, p)

    return (p, g, A), a

def encrypt(message, public_key):
    """
    Chiffre un message avec la clé publique d'ElGamal.
    Pour la démonstration, on chiffre chaque caractère séparément.
    """
    p, g, A = public_key
    cipher = []
    
    for char in message:
        m = ord(char)
        if m >= p:
            raise ValueError(f"La valeur du caractère '{char}' ({m}) est trop grande pour le nombre premier p ({p}).")
            
        # Choisir un entier aléatoire k
        k = random.randint(2, p - 2)
        
        # c1 = g^k mod p
        c1 = pow(g, k, p)
        
        # c2 = m * A^k mod p
        c2 = (m * pow(A, k, p)) % p
        
        cipher.append((c1, c2))
        
    return cipher

def decrypt(cipher, private_key, p):
    """
    Déchiffre un message avec la clé privée.
    """
    a = private_key
    message = ""
    
    for c1, c2 in cipher:
        # s = c1^a mod p
        s = pow(c1, a, p)
        
        # s_inv = s^(-1) mod p
        s_inv = mod_inverse(s, p)
        
        # m = c2 * s_inv mod p
        m = (c2 * s_inv) % p
        
        message += chr(m)
        
    return message

# ============================================================
#  Démonstration
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  Chiffrement ElGamal")
    print("=" * 60)

    # Génération des clés
    public_key, private_key = generate_keys()
    p, g, A = public_key
    
    print(f"\n📌 Paramètres publics :")
    print(f"   p (premier)    = {p}")
    print(f"   g (générateur) = {g}")
    print(f"   A (clé publique) = {A}")
    print(f"\n🔑 Clé privée :")
    print(f"   a = {private_key}")

    # Chiffrement
    message = input("\n📝 Entrez un message à chiffrer : ")
    print(f"\n   Message original  : {message}")

    encrypted = encrypt(message, public_key)
    print(f"   Message chiffré   : {encrypted}")

    # Déchiffrement
    decrypted = decrypt(encrypted, private_key, p)
    print(f"   Message déchiffré : {decrypted}")

    print(f"\n{'=' * 60}")
    if message == decrypted:
        print("  ✅ Chiffrement / Déchiffrement ElGamal réussi !")
    else:
        print("  ❌ Erreur de déchiffrement !")
    print(f"{'=' * 60}")
