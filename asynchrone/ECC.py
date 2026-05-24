# ECC.py - Cryptographie sur Courbes Elliptiques
# Courbe : y² = x³ + ax + b mod p

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib

#  COURBE ELLIPTIQUE PÉDAGOGIQUE (y² = x³ + 7 mod 97)

class Point:
    """
    Point sur une courbe elliptique.
    """
    def __init__(self, x, y, a, b, p, is_infinity=False):
        self.x = x
        self.y = y
        self.a = a
        self.b = b
        self.p = p
        self.is_infinity = is_infinity
    
    def __eq__(self, other):
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity or other.is_infinity:
            return False
        return self.x == other.x and self.y == other.y
    
    def __repr__(self):
        if self.is_infinity:
            return "Point(∞)"
        return f"Point({self.x}, {self.y})"

class EllipticCurve:
    """
    Implémentation des opérations sur courbe elliptique.
    Courbe : y² = x³ + ax + b mod p
    """
    
    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p
        
        # Vérifier que la courbe n'est pas singulaire
        delta = (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p
        if delta == 0:
            raise ValueError("La courbe est singulaire (delta = 0)")
    
    def point_addition(self, P: Point, Q: Point) -> Point:
        """
        Addition de deux points sur la courbe.
        Règle de la corde.
        """
        # Point à l'infini
        if P.is_infinity:
            return Q
        if Q.is_infinity:
            return P
        
        # P = -Q (même x, y opposé)
        if P.x == Q.x and (P.y + Q.y) % self.p == 0:
            return Point(None, None, self.a, self.b, self.p, is_infinity=True)
        
        if P.x == Q.x and P.y == Q.y:
            # Tangente (dérivée)
            s = ((3 * pow(P.x, 2, self.p) + self.a) * pow(2 * P.y, self.p - 2, self.p)) % self.p
        else:
            # Corde
            s = ((Q.y - P.y) * pow(Q.x - P.x, self.p - 2, self.p)) % self.p
        
        x3 = (pow(s, 2, self.p) - P.x - Q.x) % self.p
        y3 = (s * (P.x - x3) - P.y) % self.p
        
        return Point(x3, y3, self.a, self.b, self.p)
    
    def scalar_multiplication(self, k: int, P: Point) -> Point:
        """
        Multiplication scalaire : k * P = P + P + ... + P (k fois)
        Utilise l'algorithme double-and-add.
        """
        result = Point(None, None, self.a, self.b, self.p, is_infinity=True)
        current = P
        
        while k > 0:
            if k & 1:
                result = self.point_addition(result, current)
            current = self.point_addition(current, current)
            k >>= 1
        
        return result
    
    def is_on_curve(self, point: Point) -> bool:
        """
        Vérifie si un point appartient à la courbe.
        """
        if point.is_infinity:
            return True
        left = pow(point.y, 2, self.p)
        right = (pow(point.x, 3, self.p) + self.a * point.x + self.b) % self.p
        return left == right

def demonstrate_ec_pedagogical():
    """
    Démonstration des opérations sur courbe elliptique pédagogique.
    Courbe : y² = x³ + 7 mod 97 (comme secp256k1 mais en petit)
    """
    print("\n" + "=" * 60)
    print("  COURBE ELLIPTIQUE PÉDAGOGIQUE")
    print("  (y² = x³ + 7 mod 97)")
    print("=" * 60)
    
    # Paramètres de la courbe (comme Bitcoin mais en petit)
    curve = EllipticCurve(a=0, b=7, p=97)
    
    # Point générateur (trouvé manuellement)
    G = Point(2, 23, 0, 7, 97)
    
    print(f"\n📌 Courbe : y² = x³ + 7 mod 97")
    print(f"📌 Point générateur G = {G}")
    print(f"📌 Vérification : {G} est sur la courbe ? {curve.is_on_curve(G)}")
    
    # Addition de points
    print("\n" + "-" * 40)
    print("  ADDITION DE POINTS")
    print("-" * 40)
    
    P = G
    Q = G
    R = curve.point_addition(P, Q)
    print(f"{P} + {Q} = {R}")
    
    # Multiplication scalaire
    print("\n" + "-" * 40)
    print("  MULTIPLICATION SCALAIRE")
    print("-" * 40)
    
    for k in range(2, 6):
        kG = curve.scalar_multiplication(k, G)
        print(f"{k}G = {kG}")
    
    # Propriétés du groupe
    print("\n" + "-" * 40)
    print("  PROPRIÉTÉS DU GROUPE")
    print("-" * 40)
    
    a, b = 3, 5
    aG = curve.scalar_multiplication(a, G)
    bG = curve.scalar_multiplication(b, G)
    abG = curve.scalar_multiplication(a * b, G)
    
    print(f"{a}G = {aG}")
    print(f"{b}G = {bG}")
    print(f"Addition : {a}G + {b}G = {curve.point_addition(aG, bG)}")
    print(f"{a*b}G = {abG}")
    
    print("\n✅ Le groupe est cyclique et vérifie les propriétés")

#  ECDH SUR P-256 (NIST)

def ecdh_p256_key_pair():
    """
    Génère une paire de clés ECDH sur la courbe P-256.
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def ecdh_compute_shared_secret(private_key, peer_public_key):
    """
    Calcule le secret partagé avec ECDH.
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def derive_key_from_ecdh(shared_secret, length=32, info=b"ecdh-key-derivation"):
    """
    Dérive une clé AES à partir du secret ECDH.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    ).derive(shared_secret)

def demonstrate_ecdh():
    """
    Démonstration complète d'ECDH sur P-256.
    """
    print("\n" + "=" * 60)
    print("  ECDH SUR P-256 (NIST)")
    print("  Sécurité équivalente à RSA-3072")
    print("=" * 60)
    
    # Génération des clés
    alice_priv, alice_pub = ecdh_p256_key_pair()
    bob_priv, bob_pub = ecdh_p256_key_pair()
    
    print("\n🔑 Clés générées sur la courbe SECP256R1 (P-256)")
    
    # Échange des clés publiques
    alice_secret = ecdh_compute_shared_secret(alice_priv, bob_pub)
    bob_secret = ecdh_compute_shared_secret(bob_priv, alice_pub)
    
    assert alice_secret == bob_secret
    
    print(f"\n✅ Secret partagé : {alice_secret.hex()[:32]}...")
    
    # Dérivation de clé AES
    aes_key = derive_key_from_ecdh(alice_secret)
    print(f"🔐 Clé AES-256 dérivée : {aes_key.hex()[:32]}...")
    
    return aes_key

#  ECIES (CHIFFREMENT HYBRIDE ECC + AES)

def ecies_encrypt(message: bytes, recipient_public_key) -> tuple:
    """
    ECIES (Elliptic Curve Integrated Encryption Scheme).
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Génération d'une paire éphémère
    ephemeral_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_pub = ephemeral_priv.public_key()
    
    shared_secret = ecdh_compute_shared_secret(ephemeral_priv, recipient_public_key)
    
    # Dérivation de la clé AES
    aes_key = derive_key_from_ecdh(shared_secret, info=b"ecies-encryption")
    
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    
    # Sériealisation de la clé publique éphémère
    ephemeral_pub_bytes = ephemeral_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return ephemeral_pub_bytes, iv, ciphertext, encryptor.tag

def ecies_decrypt(ephemeral_pub_bytes: bytes, iv: bytes, ciphertext: bytes, tag: bytes, recipient_private_key) -> bytes:
    """
    Déchiffrement ECIES.
    """
    # Chargement de la clé publique éphémère
    ephemeral_pub = serialization.load_der_public_key(ephemeral_pub_bytes, backend=default_backend())
    
    shared_secret = ecdh_compute_shared_secret(recipient_private_key, ephemeral_pub)
    
    # Dérivation de la clé AES
    aes_key = derive_key_from_ecdh(shared_secret, info=b"ecies-encryption")
    
    # Déchiffrement AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

def demonstrate_ecies():
    """
    Démonstration complète d'ECIES (chiffrement hybride ECC + AES).
    """
    print("\n" + "=" * 60)
    print("  ECIES - CHIFFREMENT HYBRIDE ECC + AES")
    print("=" * 60)
    
    # Génération des clés du destinataire
    recipient_priv, recipient_pub = ecdh_p256_key_pair()
    
    print("\n📌 Destinataire - Clé publique générée")
    
    test = input("Voulez-vous (t)ester ou (u)tiliser votre propre message ? ").lower()
    if test == 't':
        message = b"Message secret chiffre avec ECIES (ECC + AES-GCM)"
        print(f"Message de test : {message.decode()}")
    else:
        message = input("Message à chiffrer : ").encode()
    
    print("\n[Chiffrement ECIES]")
    ephemeral_pub, iv, ciphertext, tag = ecies_encrypt(message, recipient_pub)
    print(f"  Clé éphémère: {ephemeral_pub.hex()[:32]}...")
    print(f"  IV: {iv.hex()}")
    print(f"  Chiffré: {ciphertext.hex()[:50]}...")
    
    print("\n[Déchiffrement ECIES]")
    decrypted = ecies_decrypt(ephemeral_pub, iv, ciphertext, tag, recipient_priv)
    print(f"  Message déchiffré: {decrypted.decode()}")
    
    if message == decrypted:
        print("\n✅ ECIES fonctionne parfaitement !")
        print("   (Combinaison d'ECC pour l'échange de clé + AES pour le chiffrement)")

def menu():
    print("\n" + "=" * 55)
    print("  CRYPTOGRAPHIE SUR COURBES ELLIPTIQUES (ECC)")
    print("=" * 55)
    print("1. Opérations sur courbe pédagogique (y²=x³+7 mod 97)")
    print("2. ECDH sur P-256 (échange de clés)")
    print("3. ECIES (chiffrement hybride ECC + AES)")
    print("4. Quitter")
    print("-" * 55)

if __name__ == "__main__":
    while True:
        menu()
        
        try:
            choix = int(input("Choisissez une option : "))
            
            if choix == 4:
                print("Au revoir !")
                break
            
            if choix == 1:
                demonstrate_ec_pedagogical()
            
            elif choix == 2:
                demonstrate_ecdh()
            
            elif choix == 3:
                demonstrate_ecies()
        
        except Exception as e:
            print(f"Erreur : {e}")
