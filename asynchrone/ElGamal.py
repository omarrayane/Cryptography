# ElGamal.py - Chiffrement ElGamal

import random
import hashlib
from math import gcd

class ElGamal:
    """
    Implémentation complète du chiffrement ElGamal.
    """

    def __init__(self, key_bits: int = 1024):
        self.key_bits = key_bits
        self.p = None
        self.g = None
        self.x = None
        self.y = None
        self._generate_keys()

    def _is_prime(self, n: int, k: int = 10) -> bool:
        if n < 2:
            return False
        if n in [2, 3]:
            return True
        if n % 2 == 0:
            return False

        # Écrire n-1 = d * 2^s
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _generate_prime(self, bits: int) -> int:
        while True:
            candidate = random.getrandbits(bits)
            candidate |= (1 << bits - 1) | 1  # bits de poids fort et faible à 1
            if self._is_prime(candidate):
                return candidate

    def _is_primitive_root(self, g: int, p: int) -> bool:
        # Vérification simple (p-1 doit être première avec g)
        phi = p - 1
        # Pour p grand, on vérifie les facteurs premiers de phi
        # Version simplifiée pour démonstration
        for factor in [2, 3, 5, 7, 11, 13, 17, 19]:
            if phi % factor == 0:
                if pow(g, phi // factor, p) == 1:
                    return False
        return True

    def _find_primitive_root(self, p: int) -> int:
        for g in range(2, p):
            if self._is_primitive_root(g, p):
                return g
        return 2

    def _generate_keys(self):
        # Génération du nombre premier p
        self.p = self._generate_prime(self.key_bits)

        # Recherche du générateur
        self.g = self._find_primitive_root(self.p)

        # Clé privée (1 < x < p-1)
        self.x = random.randint(2, self.p - 2)

        # Clé publique y = g^x mod p
        self.y = pow(self.g, self.x, self.p)

    def encrypt(self, message: int) -> tuple:
        """
        Chiffre un entier M (0 < M < p).
        Retourne (c1, c2)
        """
        if message >= self.p:
            raise ValueError(f"Message {message} >= p ({self.p})")

        # Choisir k aléatoire (1 < k < p-1)
        k = random.randint(2, self.p - 2)

        c1 = pow(self.g, k, self.p)

        # c2 = M * y^k mod p
        c2 = (message * pow(self.y, k, self.p)) % self.p

        return (c1, c2)

    def decrypt(self, c1: int, c2: int) -> int:
        """
        Déchiffre un couple (c1, c2).
        Retourne M.
        """
        s = pow(c1, self.x, self.p)

        s_inv = pow(s, self.p - 2, self.p)

        # M = c2 * s_inv mod p
        m = (c2 * s_inv) % self.p

        return m

    def encrypt_string(self, text: str) -> list:
        result = []
        for char in text:
            c1, c2 = self.encrypt(ord(char))
            result.append((c1, c2))
        return result

    def decrypt_string(self, ciphertext: list) -> str:
        result = ""
        for c1, c2 in ciphertext:
            m = self.decrypt(c1, c2)
            result += chr(m)
        return result

    def get_keys(self):
        return {
            'public': {'p': self.p, 'g': self.g, 'y': self.y},
            'private': {'x': self.x}
        }

def demonstrate_malleability():
    """
    Démontre la propriété de malléabilité d'ElGamal.
    E(M1) * E(M2) = E(M1 * M2 mod p)
    """
    print("\n" + "=" * 60)
    print("  MALLÉABILITÉ D'ELGAMAL")
    print("=" * 60)

    # Utilisation de petits paramètres pour la démonstration
    elgamal = ElGamal(key_bits=16)  # petit pour démo

    M1 = 12345
    M2 = 6789

    print(f"\nMessages originaux :")
    print(f"  M1 = {M1}")
    print(f"  M2 = {M2}")

    c1_1, c2_1 = elgamal.encrypt(M1)
    c1_2, c2_2 = elgamal.encrypt(M2)

    print(f"\nChiffrés :")
    print(f"  E(M1) = (c1={c1_1}, c2={c2_1})")
    print(f"  E(M2) = (c1={c1_2}, c2={c2_2})")

    # Multiplication des chiffrés
    c1_prod = (c1_1 * c1_2) % elgamal.p
    c2_prod = (c2_1 * c2_2) % elgamal.p

    print(f"\nMultiplication des chiffrés :")
    print(f"  E(M1) * E(M2) = (c1={c1_prod}, c2={c2_prod})")

    M_prod = elgamal.decrypt(c1_prod, c2_prod)
    expected = (M1 * M2) % elgamal.p

    print(f"\nRésultat :")
    print(f"  D(E(M1) * E(M2)) = {M_prod}")
    print(f"  M1 * M2 mod p = {expected}")

    if M_prod == expected:
        print("\n✅ VÉRIFIÉ : E(M1) * E(M2) = E(M1 * M2 mod p)")

    print("\n" + "-" * 50)
    print("  ATTAQUE : Forger E(2M) sans connaître M")
    print("-" * 50)

    # Ciphertext original (c1, c2) = E(M)
    c1, c2 = elgamal.encrypt(M1)

    # Pour obtenir E(2M), on fait (c1, 2*c2 mod p)
    c2_forged = (2 * c2) % elgamal.p

    M_forged = elgamal.decrypt(c1, c2_forged)

    print(f"  E(M) original = (c1={c1}, c2={c2})")
    print(f"  E(2M) forgé   = (c1={c1}, c2={c2_forged})")
    print(f"  D(E(2M) forgé) = {M_forged}")
    print(f"  2M original = {2 * M1}")

    if M_forged == (2 * M1) % elgamal.p:
        print("\n✅ Un attaquant peut modifier le chiffré sans connaître la clé !")
        print("   C'est la malléabilité d'ElGamal.")

def compare_key_sizes():
    """
    Compare les tailles des clés et chiffrés RSA vs ElGamal.
    """
    print("\n" + "=" * 60)
    print("  COMPARAISON DES TAILLES")
    print("  RSA-2048 vs ElGamal-2048")
    print("=" * 60)

    print("\n📌 RSA-2048 :")
    print("   - clé publique = 2048 bits")
    print("   - clé privée = 2048 bits")
    print("   - chiffré = 2048 bits")

    # ElGamal-2048
    print("\n📌 ElGamal-2048 :")
    print("   - clé publique = 2048 bits")
    print("   - clé privée = 2048 bits")
    print("   - chiffré = 4096 bits")

    # Conclusion
    print("\n✅ RSA est plus efficace en termes de taille de clé et de chiffré.")
