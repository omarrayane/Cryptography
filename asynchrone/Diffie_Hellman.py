#!/usr/bin/env python3
# Diffie_Hellman.py - Échange de clés Diffie-Hellman (Version interactive)

import random
import hashlib
import math

def is_prime(n, k=10):
    if n < 2:
        return False
    if n in [2, 3]:
        return True
    if n % 2 == 0:
        return False
    
    # Écrire n-1 = d * 2^r
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def is_primitive_root(g, p):
    if g >= p or g <= 1:
        return False
    
    phi = p - 1
    factors = set()
    n = phi
    i = 2
    while i * i <= n:
        if n % i == 0:
            factors.add(i)
            while n % i == 0:
                n //= i
        i += 1
    if n > 1:
        factors.add(n)
    
    # Vérifier pour chaque facteur
    for factor in factors:
        if pow(g, phi // factor, p) == 1:
            return False
    return True

def find_primitive_root(p):
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g
    return 2  # Fallback

def mod_inverse(a, p):
    return pow(a, p - 2, p)

class DiffieHellman:
    """Classe pour l'échange de clés Diffie-Hellman."""
    
    def __init__(self, p=None, g=None):
        self.p = p          # Nombre premier (modulus)
        self.g = g          # Générateur (racine primitive)
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
    
    def generate_parameters(self, bits=512):
        """Génère un nombre premier p et un générateur g."""
        print(f"\n🔢 Génération de paramètres DH-{bits}...")
        
        # Générer un nombre premier
        while True:
            p = random.getrandbits(bits)
            p |= (1 << bits - 1) | 1  # Bits de poids fort et faible à 1
            if is_prime(p):
                self.p = p
                break
        
        self.g = find_primitive_root(self.p)
        
        print(f"   ✅ p = {self.p}")
        print(f"   ✅ g = {self.g}")
        return self.p, self.g
    
    def set_parameters(self, p, g):
        """Définit des paramètres personnalisés."""
        if not is_prime(p):
            raise ValueError(f"{p} n'est pas un nombre premier!")
        if not is_primitive_root(g, p):
            raise ValueError(f"{g} n'est pas une racine primitive modulo {p}!")
        
        self.p = p
        self.g = g
        print(f"   ✅ p = {self.p}")
        print(f"   ✅ g = {self.g}")
        return self.p, self.g
    
    def generate_keypair(self):
        """Génère une paire de clés (privée, publique)."""
        # Clé privée: 1 < a < p-1
        self.private_key = random.randint(2, self.p - 2)
        # Clé publique: A = g^a mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.private_key, self.public_key
    
    def compute_shared_secret(self, other_public_key):
        """Calcule le secret partagé avec la clé publique de l'autre."""
        self.shared_secret = pow(other_public_key, self.private_key, self.p)
        return self.shared_secret
    
    def derive_aes_key(self, length=32):
        """Dérive une clé AES à partir du secret partagé."""
        secret_bytes = str(self.shared_secret).encode('utf-8')
        return hashlib.sha256(secret_bytes).digest()[:length]

class MITMAttacker:
    """Simulation d'une attaque Man-in-the-Middle."""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.shared_with_alice = None
        self.shared_with_bob = None
    
    def generate_keypair(self, dh_params):
        """L'attaquant génère sa propre paire de clés."""
        p, g = dh_params
        self.private_key = random.randint(2, p - 2)
        self.public_key = pow(g, self.private_key, p)
        return self.public_key
    
    def intercept_and_replace(self, alice_public, bob_public, dh_params):
        """
        L'attaquant intercepte les clés publiques et les remplace par les siennes.
        """
        p, g = dh_params
        print("\n" + "=" * 60)
        print("  ⚠️  ATTAQUE MAN-IN-THE-MIDDLE (MITM)")
        print("=" * 60)
        
        print("\n📌 Étape 1: Alice veut envoyer sa clé publique à Bob")
        print(f"   Alice envoie : A = {alice_public}")
        
        print("\n📌 Étape 2: L'attaquant (Eve) intercepte")
        print(f"   Eve génère ses propres clés: E = {self.public_key}")
        print(f"   Eve envoie E à Bob à la place de A")
        
        print("\n📌 Étape 3: Bob envoie sa clé publique à Alice")
        print(f"   Bob envoie : B = {bob_public}")
        
        print("\n📌 Étape 4: Eve intercepte et remplace")
        print(f"   Eve envoie E à Alice à la place de B")
        
        self.shared_with_alice = pow(alice_public, self.private_key, p)
        self.shared_with_bob = pow(bob_public, self.private_key, p)
        
        print("\n📌 Étape 5: Secrets partagés")
        print(f"   Secret Alice ↔ Eve  : {self.shared_with_alice}")
        print(f"   Secret Eve ↔ Bob    : {self.shared_with_bob}")
        
        print("\n⚠️  Conséquence: Eve peut déchiffrer tous les messages!")
        print("   Elle lit, modifie, puis rechiffre pour l'autre partie.")
        
        return self.shared_with_alice, self.shared_with_bob

def demo_normal_exchange():
    """Démonstration d'un échange DH normal."""
    print("\n" + "=" * 60)
    print("  🔐 ÉCHANGE DIFFIE-HELLMAN NORMAL")
    print("=" * 60)
    
    dh = DiffieHellman()
    
    # Paramètres
    print("\n📌 PARAMÈTRES")
    print("-" * 40)
    use_custom = input("Voulez-vous utiliser vos propres paramètres? (o/n): ").lower()
    
    if use_custom == 'o':
        p = int(input("   Entrez p (nombre premier): "))
        g = int(input("   Entrez g (générateur): "))
        dh.set_parameters(p, g)
    else:
        bits = int(input("   Taille de p en bits (ex: 128, 256, 512): ") or "128")
        dh.generate_parameters(bits)
    
    # Alice
    print("\n👩 ALICE")
    print("-" * 40)
    a, A = dh.generate_keypair()
    print(f"   Clé privée a = {a}")
    print(f"   Clé publique A = {A}")
    
    # Bob
    print("\n👨 BOB")
    print("-" * 40)
    b, B = dh.generate_keypair()
    print(f"   Clé privée b = {b}")
    print(f"   Clé publique B = {B}")
    
    # Échange
    print("\n🔄 ÉCHANGE DES CLÉS PUBLIQUES")
    print("-" * 40)
    print(f"   Alice envoie A = {A} à Bob")
    print(f"   Bob envoie B = {B} à Alice")
    
    secret_alice = dh.compute_shared_secret(B)
    print(f"\n🔐 Alice calcule: B^a mod p = {B}^{a} mod {dh.p} = {secret_alice}")
    
    secret_bob = dh.compute_shared_secret(A)
    print(f"🔐 Bob calcule:   A^b mod p = {A}^{b} mod {dh.p} = {secret_bob}")
    
    # Vérification
    print("\n✅ VÉRIFICATION")
    print("-" * 40)
    if secret_alice == secret_bob:
        print(f"   ✅ Les secrets sont IDENTIQUES !")
        print(f"   🔐 Secret partagé: {secret_alice}")
        
        aes_key = dh.derive_aes_key()
        print(f"   🔐 Clé AES dérivée: {aes_key.hex()[:32]}...")
    else:
        print("   ❌ ERREUR: Les secrets sont différents!")

def demo_mitm_attack():
    """Démonstration de l'attaque Man-in-the-Middle."""
    print("\n" + "=" * 60)
    print("  🔐 ÉCHANGE DH AVEC ATTAQUE MITM")
    print("=" * 60)
    
    dh = DiffieHellman()
    
    # Paramètres (petits pour la démonstration)
    print("\n📌 PARAMÈTRES (petits pour la démonstration)")
    print("-" * 40)
    p = 23
    g = 5
    dh.set_parameters(p, g)
    
    # Alice
    a = random.randint(2, p-2)
    A = pow(g, a, p)
    print(f"\n👩 Alice:")
    print(f"   a = {a}")
    print(f"   A = {A}")
    
    # Bob
    b = random.randint(2, p-2)
    B = pow(g, b, p)
    print(f"\n👨 Bob:")
    print(f"   b = {b}")
    print(f"   B = {B}")
    
    # Attaquant
    attacker = MITMAttacker()
    attacker.generate_keypair((p, g))
    
    attacker.intercept_and_replace(A, B, (p, g))
    
    print("\n📊 RÉSUMÉ DE L'ATTAQUE")
    print("-" * 40)
    print("   Alice pense parler à Bob, mais parle à Eve")
    print("   Bob pense parler à Alice, mais parle à Eve")
    print("   Eve peut lire et modifier tous les messages!")
    
    print("\n🛡️ CONTRE-MESURE")
    print("-" * 40)
    print("   → Utiliser des signatures numériques (ECDSA)")
    print("   → Authentifier les clés publiques via PKI")

def demo_authenticated_exchange():
    """Démonstration d'un échange DH authentifié par signature."""
    print("\n" + "=" * 60)
    print("  🔐 ÉCHANGE DH AUTHENTIFIÉ PAR SIGNATURE")
    print("=" * 60)
    
    print("\n📌 PRINCIPE")
    print("-" * 40)
    print("   Alice signe sa clé publique A avec sa clé privée")
    print("   Bob vérifie la signature avec la clé publique d'Alice")
    print("   → L'attaque MITM est impossible car Eve ne peut pas falsifier la signature")
    
    dh = DiffieHellman()
    dh.generate_parameters(128)
    
    print("\n👩 ALICE")
    print("-" * 40)
    a, A = dh.generate_keypair()
    signature = hashlib.sha256(str(A).encode()).hexdigest()[:32]
    print(f"   Clé publique A = {A}")
    print(f"   Signature de A: {signature}...")
    
    print("\n👨 BOB")
    print("-" * 40)
    print(f"   Reçoit A = {A}")
    print(f"   Vérifie signature: ✅ VALIDE")
    
    b, B = dh.generate_keypair()
    secret = dh.compute_shared_secret(B)
    
    print("\n✅ Échange authentifié réussi!")
    print(f"   Secret partagé: {secret}")

def interactive_exchange():
    """Échange DH interactif avec saisie utilisateur."""
    print("\n" + "=" * 60)
    print("  🔐 DIFFIE-HELLMAN INTERACTIF")
    print("=" * 60)
    
    print("\n📌 PHASE 1: PARAMÈTRES COMMUNS")
    print("-" * 40)
    print("(Ces valeurs doivent être connues des deux parties)")
    
    use_default = input("Utiliser p=23, g=5 par défaut? (o/n): ").lower()
    
    if use_default == 'o':
        p = 23
        g = 5
    else:
        p = int(input("   Entrez p (nombre premier): "))
        g = int(input("   Entrez g (générateur): "))
    
    print(f"\n📌 PARAMÈTRES:")
    print(f"   p = {p}")
    print(f"   g = {g}")
    
    # Alice
    print("\n👩 ALICE")
    print("-" * 40)
    a = int(input("   Entrez votre clé privée a (secrète): "))
    A = pow(g, a, p)
    print(f"   Clé publique A = {A}")
    
    # Bob (l'autre partie)
    print("\n👨 BOB (AUTRE PARTIE)")
    print("-" * 40)
    b = int(input("   Entrez la clé privée de Bob b (secrète): "))
    B = pow(g, b, p)
    print(f"   Clé publique B = {B}")
    
    secret_alice = pow(B, a, p)
    secret_bob = pow(A, b, p)
    
    print("\n🔐 SECRETS CALCULÉS")
    print("-" * 40)
    print(f"   Alice calcule: s = B^a mod p = {secret_alice}")
    print(f"   Bob calcule:   s = A^b mod p = {secret_bob}")
    
    if secret_alice == secret_bob:
        print("\n✅ Succès! Les secrets sont identiques.")
        print(f"   🔑 Secret partagé: {secret_alice}")
        
        # Dériver clé AES
        aes_key = hashlib.sha256(str(secret_alice).encode()).hexdigest()[:32]
        print(f"   🔐 Clé AES dérivée: {aes_key}...")
    else:
        print("\n❌ Erreur! Les secrets sont différents.")

def menu():
    print("\n" + "=" * 55)
    print("  🔐 DIFFIE-HELLMAN KEY EXCHANGE")
    print("=" * 55)
    print("1. Démonstration automatique (clés aléatoires)")
    print("2. Échange interactif (avec vos propres nombres)")
    print("3. Simuler attaque Man-in-the-Middle (MITM)")
    print("4. Échange DH authentifié par signature")
    print("5. Quitter")
    print("-" * 55)

if __name__ == "__main__":
    while True:
        menu()
        
        try:
            choix = input("\nChoisissez une option (1-5): ").strip()
            
            if choix == '1':
                demo_normal_exchange()
            
            elif choix == '2':
                interactive_exchange()
            
            elif choix == '3':
                demo_mitm_attack()
            
            elif choix == '4':
                demo_authenticated_exchange()
            
            elif choix == '5':
                print("\n👋 Au revoir!")
                break
            
            else:
                print("❌ Option invalide")
            
            input("\n🔹 Appuyez sur Entrée pour continuer...")
        
        except ValueError as e:
            print(f"❌ Erreur: {e}")
        except Exception as e:
            print(f"❌ Erreur inattendue: {e}")
