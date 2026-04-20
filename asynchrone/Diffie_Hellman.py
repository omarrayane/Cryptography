import random
import hashlib

# ============================================================
#  Diffie-Hellman Key Exchange (Échange de clés)
# ============================================================

def is_primitive_root(g, p):
    """Vérifie si g est une racine primitive modulo p (simplifiée)."""
    required = set(range(1, p))
    actual = set(pow(g, i, p) for i in range(1, p))
    return required == actual


def generate_dh_parameters():
    """
    Génère les paramètres publics de Diffie-Hellman :
      - p : un nombre premier
      - g : une racine primitive modulo p
    (Valeurs pédagogiques, petites pour la démonstration)
    """
    p = 23  # nombre premier
    g = 5   # racine primitive modulo 23
    return p, g


def generate_private_key(p):
    """Génère une clé privée aléatoire dans [2, p-2]."""
    return random.randint(2, p - 2)


def generate_public_key(g, private_key, p):
    """Calcule la clé publique : A = g^a mod p."""
    return pow(g, private_key, p)


def compute_shared_secret(other_public, private_key, p):
    """Calcule le secret partagé : s = B^a mod p  (ou A^b mod p)."""
    return pow(other_public, private_key, p)


def derive_aes_key(shared_secret):
    """
    Dérive une clé AES 256 bits à partir du secret partagé
    en utilisant SHA-256.
    """
    secret_bytes = str(shared_secret).encode('utf-8')
    return hashlib.sha256(secret_bytes).digest()  # 32 octets = 256 bits


# ============================================================
#  Démonstration
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  Diffie-Hellman Key Exchange")
    print("=" * 60)

    # --- Étape 1 : Paramètres publics ---
    p, g = generate_dh_parameters()
    print(f"\n📌 Paramètres publics Diffie-Hellman :")
    print(f"   p (nombre premier)     = {p}")
    print(f"   g (racine primitive)   = {g}")

    # --- Étape 2 : Génération des clés privées ---
    a = generate_private_key(p)   # clé privée d'Alice
    b = generate_private_key(p)   # clé privée de Bob
    print(f"\n🔑 Clés privées :")
    print(f"   Alice (a) = {a}")
    print(f"   Bob   (b) = {b}")

    # --- Étape 3 : Calcul des clés publiques ---
    A = generate_public_key(g, a, p)  # clé publique d'Alice
    B = generate_public_key(g, b, p)  # clé publique de Bob
    print(f"\n🌐 Clés publiques échangées :")
    print(f"   Alice envoie A = g^a mod p = {g}^{a} mod {p} = {A}")
    print(f"   Bob   envoie B = g^b mod p = {g}^{b} mod {p} = {B}")

    # --- Étape 4 : Calcul du secret partagé ---
    secret_alice = compute_shared_secret(B, a, p)  # Alice calcule B^a mod p
    secret_bob   = compute_shared_secret(A, b, p)  # Bob   calcule A^b mod p
    print(f"\n🤝 Secret partagé :")
    print(f"   Alice calcule : B^a mod p = {B}^{a} mod {p} = {secret_alice}")
    print(f"   Bob   calcule : A^b mod p = {A}^{b} mod {p} = {secret_bob}")
    assert secret_alice == secret_bob, "Erreur : les secrets ne correspondent pas !"
    print(f"   ✅ Les deux secrets sont identiques : {secret_alice}")

    # --- Étape 5 : Dérivation de la clé AES ---
    aes_key = derive_aes_key(secret_alice)
    print(f"\n🔐 Clé AES-256 dérivée (SHA-256) :")
    print(f"   {aes_key.hex()}")

    print(f"\n{'=' * 60}")
    print("  ✅ Échange de clés terminé avec succès !")
    print(f"{'=' * 60}")
