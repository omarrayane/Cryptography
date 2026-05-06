# SHA256.py - Secure Hash Algorithm 2 (256 bits)
# ============================================================

import hashlib
import time
import os
import struct


# ============================================================
#  CONSTANTES SHA-256
# ============================================================

# Constantes K[i] = premiers 32 bits des racines cubiques des 64 premiers nombres premiers
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Valeurs initiales des 8 registres (premiers 32 bits des racines carrées des 8 premiers nombres premiers)
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]


# ============================================================
#  OPÉRATIONS SHA-256
# ============================================================

def rotr(x, n):
    """Rotation droite."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def shr(x, n):
    """Décalage droite."""
    return (x >> n) & 0xFFFFFFFF


def ch(x, y, z):
    """Fonction de choix."""
    return (x & y) ^ ((~x) & z)


def maj(x, y, z):
    """Fonction de majorité."""
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x):
    """Sigma 0."""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def sigma1(x):
    """Sigma 1."""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def gamma0(x):
    """Gamma 0."""
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def gamma1(x):
    """Gamma 1."""
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


# ============================================================
#  IMPLÉMENTATION PÉDAGOGIQUE DE SHA-256
# ============================================================

def sha256_padding(message: bytes) -> bytes:
    """
    Padding Merkle-Damgård pour SHA-256.
    """
    original_length = len(message) * 8  # en bits
    message = bytearray(message)

    # Ajouter 0x80
    message.append(0x80)

    # Ajouter des 0 jusqu'à ce que longueur ≡ 56 mod 64
    while (len(message) * 8) % 512 != 448:
        message.append(0x00)

    # Ajouter la longueur originale sur 64 bits (big endian)
    message += struct.pack('>Q', original_length)

    return bytes(message)


def sha256_compress(block: bytes, state: list) -> list:
    """
    Fonction de compression sur un bloc de 512 bits.
    """
    # Extension du message : 16 mots → 64 mots
    w = [0] * 64
    for i in range(16):
        w[i] = int.from_bytes(block[i*4:(i+1)*4], 'big')

    for i in range(16, 64):
        w[i] = (gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF

    # Initialisation des variables de travail
    a, b, c, d, e, f, g, h = state

    # Compression (64 tours)
    for i in range(64):
        t1 = (h + sigma1(e) + ch(e, f, g) + K[i] + w[i]) & 0xFFFFFFFF
        t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF

    # Mise à jour de l'état
    new_state = [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
        (state[4] + e) & 0xFFFFFFFF,
        (state[5] + f) & 0xFFFFFFFF,
        (state[6] + g) & 0xFFFFFFFF,
        (state[7] + h) & 0xFFFFFFFF
    ]

    return new_state


def sha256_pedagogical(message: bytes) -> str:
    """
    Implémentation pédagogique de SHA-256.
    """
    # Padding
    padded = sha256_padding(message)

    # État initial
    state = H0.copy()

    # Traitement par blocs de 512 bits (64 octets)
    for i in range(0, len(padded), 64):
        block = padded[i:i+64]
        state = sha256_compress(block, state)

    # Construction du hash final
    result = b''
    for s in state:
        result += s.to_bytes(4, 'big')

    return result.hex()


# ============================================================
#  FONCTIONS UTILITAIRES
# ============================================================

def sha256_hash(data):
    """
    Hash SHA-256 avec hashlib (standard).
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def sha256_file_hash(filename):
    """
    Hash SHA-256 d'un fichier.
    """
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_integrity():
    """
    Simule la vérification d'intégrité d'un fichier.
    Compare le hash local avec un hash officiel.
    """
    print("\n" + "=" * 60)
    print("  VÉRIFICATION D'INTÉGRITÉ (SHA-256)")
    print("=" * 60)

    # Créer un fichier de test
    test_file = "test_integrity.txt"
    with open(test_file, "w") as f:
        f.write("Ceci est un fichier important")

    # Calcul du hash
    actual_hash = sha256_file_hash(test_file)

    # Hash officiel (simulé)
    official_hash = input(f"Entrez le hash officiel de {test_file} : ")

    print(f"\nHash calculé : {actual_hash}")
    print(f"Hash officiel: {official_hash}")

    if actual_hash == official_hash:
        print("\n✅ FICHIER INTACT - Intégrité vérifiée")
    else:
        print("\n❌ FICHIER CORROMPU OU MODIFIÉ !")

    # Nettoyage
    os.remove(test_file)


def avalanche_effect_sha256():
    """
    Calcule l'effet avalanche pour SHA-256.
    """
    print("\n" + "=" * 60)
    print("  EFFET AVALANCHE - SHA-256")
    print("=" * 60)

    original = b"Hello World"
    modified = bytearray(original)
    modified[0] ^= 0x01

    h1 = hashlib.sha256(original).digest()
    h2 = hashlib.sha256(bytes(modified)).digest()

    print(f"\nMessage original : {original}")
    print(f"Message modifié  : {bytes(modified)}")

    different_bits = 0
    total_bits = len(h1) * 8

    for b1, b2 in zip(h1, h2):
        xor = b1 ^ b2
        different_bits += bin(xor).count('1')

    ratio = (different_bits / total_bits) * 100

    print(f"\n📊 Résultat :")
    print(f"   Bits différents : {different_bits} / {total_bits} ({ratio:.2f}%)")

    if 45 < ratio < 55:
        print("   ✅ Effet avalanche vérifié (≈50%)")


def benchmark_sha256(sizes_mb=[1, 10, 100]):
    """
    Benchmark SHA-256.
    """
    print("\n" + "=" * 60)
    print("  BENCHMARK SHA-256")
    print("=" * 60)

    print(f"\n{'Taille':<15} {'Temps (s)':<15} {'Débit (Mo/s)':<15}")
    print("-" * 45)

    for size_mb in sizes_mb:
        data = os.urandom(size_mb * 1024 * 1024)

        start = time.time()
        hash_result = hashlib.sha256(data).hexdigest()
        elapsed = time.time() - start

        throughput = size_mb / elapsed if elapsed > 0 else 0
        print(f"{size_mb} Mo{'':<10} {elapsed:<15.4f} {throughput:<15.2f}")


def compare_with_hashlib():
    """
    Compare l'implémentation pédagogique avec hashlib.
    """
    print("\n" + "=" * 60)
    print("  COMPARAISON IMPLÉMENTATION vs HASHLIB")
    print("=" * 60)

    test_strings = [
        b"",
        b"a",
        b"abc",
        b"Hello World",
        b"Message plus long pour tester SHA-256"
    ]

    print(f"\n{'Message':<30} {'Pédagogique':<35} {'Hashlib':<35} {'Match':<10}")
    print("-" * 110)

    for msg in test_strings:
        ped_result = sha256_pedagogical(msg)
        lib_result = hashlib.sha256(msg).hexdigest()

        match = "✅" if ped_result == lib_result else "❌"

        display_msg = msg.decode()[:27] + "..." if len(msg) > 27 else msg.decode()
        print(f"{display_msg:<30} {ped_result:<35} {lib_result:<35} {match:<10}")


def menu():
    print("\n" + "=" * 50)
    print("      SHA-256 - SECURE HASH ALGORITHM")
    print("=" * 50)
    print("1. Hacher un message")
    print("2. Hacher un fichier")
    print("3. Vérification d'intégrité")
    print("4. Effet avalanche")
    print("5. Benchmark")
    print("6. Comparer implémentation vs hashlib")
    print("7. Quitter")
    print("-" * 50)


if __name__ == "__main__":
    while True:
        menu()

        try:
            choix = int(input("Choisissez une option : "))

            if choix == 7:
                print("Au revoir !")
                break

            if choix == 1:
                test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                if test == 't':
                    message = "Hello World"
                    print(f"Message de test : {message}")
                else:
                    message = input("📝 Entrez le message : ")

                hash_result = sha256_hash(message)
                print(f"\nSHA-256 (256 bits / 64 hex) : {hash_result}")
                print(f"Longueur : {len(hash_result)} caractères hex")

            elif choix == 2:
                filename = input("Nom du fichier : ")
                if os.path.exists(filename):
                    hash_result = sha256_file_hash(filename)
                    print(f"\nSHA-256 de {filename} : {hash_result}")
                else:
                    print(f"❌ Fichier {filename} introuvable")

            elif choix == 3:
                verify_integrity()

            elif choix == 4:
                avalanche_effect_sha256()

            elif choix == 5:
                benchmark_sha256()

            elif choix == 6:
                compare_with_hashlib()

        except Exception as e:
            print(f"Erreur : {e}")
