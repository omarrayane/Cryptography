# Diffie_Hellman.py - Échange de clés Diffie-Hellman
# ============================================================

from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
import hashlib


# ============================================================
#  DIFFIE-HELLMAN STANDARD
# ============================================================

def generate_dh_parameters_secure():
    """
    Génère des paramètres DH sécurisés (groupe de 2048 bits).
    """
    # Utiliser les paramètres standards du RFC 3526 (groupe 14)
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters


def generate_dh_key_pair(parameters):
    """
    Génère une paire de clés DH.
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def compute_dh_shared_secret(private_key, peer_public_key):
    """
    Calcule le secret partagé.
    """
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret


def derive_aes_key_from_dh(shared_secret, length=32):
    """
    Dérive une clé AES à partir du secret partagé.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'dh-key-derivation',
        backend=default_backend()
    ).derive(shared_secret)


def simulate_dh_exchange():
    """
    Simule un échange DH complet entre Alice et Bob.
    """
    print("\n" + "=" * 60)
    print("  SIMULATION D'ÉCHANGE DIFFIE-HELLMAN")
    print("=" * 60)

    # Génération des paramètres publics
    parameters = generate_dh_parameters_secure()
    print(f"\n📌 Paramètres publics générés (2048 bits)")

    # Génération des clés
    alice_priv, alice_pub = generate_dh_key_pair(parameters)
    bob_priv, bob_pub = generate_dh_key_pair(parameters)

    print(f"\n🔑 Clés privées générées")
    print(f"🌐 Clés publiques échangées")

    # Calcul du secret partagé
    alice_secret = compute_dh_shared_secret(alice_priv, bob_pub)
    bob_secret = compute_dh_shared_secret(bob_priv, alice_pub)

    assert alice_secret == bob_secret

    # Dérivation de la clé AES
    aes_key = derive_aes_key_from_dh(alice_secret)

    print(f"\n✅ Secret partagé identique : {alice_secret.hex()[:32]}...")
    print(f"🔐 Clé AES-256 dérivée : {aes_key.hex()[:32]}...")

    return alice_secret, aes_key


# ============================================================
#  ATTAQUE MAN-IN-THE-MIDDLE (MITM)
# ============================================================

class MITMAttacker:
    """
    Simule un attaquant Man-in-the-Middle.
    """

    def __init__(self):
        self.parameters = generate_dh_parameters_secure()
        self.private_key_alice_fake = None
        self.private_key_bob_fake = None
        self.public_key_alice_fake = None
        self.public_key_bob_fake = None

    def intercept_and_replace(self, alice_public, bob_public):
        """
        Intercepte les clés publiques et les remplace par ses propres clés.
        """
        print("\n" + "=" * 60)
        print("  ATTAQUE MAN-IN-THE-MIDDLE (MITM)")
        print("=" * 60)

        # L'attaquant génère SES propres clés
        self.private_key_alice_fake, self.public_key_alice_fake = generate_dh_key_pair(self.parameters)
        self.private_key_bob_fake, self.public_key_bob_fake = generate_dh_key_pair(self.parameters)

        print("\n📌 Étape 1: Alice veut envoyer sa clé publique à Bob")
        print(f"   Alice envoie : {alice_public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex()[:32]}...")

        print("\n⚠️  L'attaquant intercepte et remplace par SA clé publique")
        print(f"   Attaquant envoie à Bob : {self.public_key_alice_fake.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex()[:32]}...")

        print("\n📌 Étape 2: Bob envoie sa clé publique à Alice")
        print(f"   Bob envoie : {bob_public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex()[:32]}...")

        print("\n⚠️  L'attaquant intercepte et remplace par SA clé publique")
        print(f"   Attaquant envoie à Alice : {self.public_key_bob_fake.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex()[:32]}...")

        return self.public_key_alice_fake, self.public_key_bob_fake

    def establish_sessions(self, alice_public, bob_public):
        """
        Établit deux sessions séparées avec Alice et Bob.
        """
        print("\n" + "=" * 60)
        print("  CONSÉQUENCES DE L'ATTAQUE MITM")
        print("=" * 60)

        # Session entre Alice et l'attaquant
        secret_alice_attacker = compute_dh_shared_secret(self.private_key_alice_fake, alice_public)
        # Session entre Bob et l'attaquant
        secret_bob_attacker = compute_dh_shared_secret(self.private_key_bob_fake, bob_public)

        print(f"\n🔐 Secret partagé entre Alice et l'attaquant : {secret_alice_attacker.hex()[:32]}...")
        print(f"🔐 Secret partagé entre Bob et l'attaquant   : {secret_bob_attacker.hex()[:32]}...")

        print("\n📝 L'attaquant peut maintenant :")
        print("   1. Déchiffrer tous les messages d'Alice")
        print("   2. Lire, modifier, puis rechiffrer pour Bob")
        print("   3. Faire de même dans l'autre sens")

        print("\n❌ Alice et Bob pensent communiquer directement")
        print("   Mais tout passe par l'attaquant !")

        return secret_alice_attacker, secret_bob_attacker


# ============================================================
#  ECDSA POUR AUTHENTIFIER L'ÉCHANGE DH
# ============================================================

def generate_ecdsa_keys():
    """
    Génère une paire de clés ECDSA pour l'authentification.
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def sign_dh_public_key(private_key_ecdsa, dh_public_key):
    """
    Signe la clé publique DH avec ECDSA.
    """
    der_bytes = dh_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signature = private_key_ecdsa.sign(der_bytes, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_dh_public_key(public_key_ecdsa, dh_public_key, signature):
    """
    Vérifie la signature de la clé publique DH.
    """
    der_bytes = dh_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        public_key_ecdsa.verify(signature, der_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def simulate_authenticated_dh():
    """
    Simule un échange DH authentifié par ECDSA (bloque MITM).
    """
    print("\n" + "=" * 60)
    print("  ÉCHANGE DH AUTHENTIFIÉ PAR ECDSA")
    print("=" * 60)

    # Génération des clés ECDSA pour Alice et Bob
    alice_auth_priv, alice_auth_pub = generate_ecdsa_keys()
    bob_auth_priv, bob_auth_pub = generate_ecdsa_keys()

    print("\n📌 Les clés publiques ECDSA sont échangées AVANT (hors bande ou via PKI)")

    # Échange DH normal
    parameters = generate_dh_parameters_secure()
    alice_dh_priv, alice_dh_pub = generate_dh_key_pair(parameters)
    bob_dh_priv, bob_dh_pub = generate_dh_key_pair(parameters)

    # Signature des clés DH
    alice_signature = sign_dh_public_key(alice_auth_priv, alice_dh_pub)
    bob_signature = sign_dh_public_key(bob_auth_priv, bob_dh_pub)

    print("\n✅ Alice signe sa clé DH avec ECDSA")
    print("✅ Bob signe sa clé DH avec ECDSA")

    # Vérification
    alice_verified = verify_dh_public_key(bob_auth_pub, bob_dh_pub, bob_signature)
    bob_verified = verify_dh_public_key(alice_auth_pub, alice_dh_pub, alice_signature)

    print(f"\n🔍 Alice vérifie la clé de Bob : {'✅ VALIDE' if alice_verified else '❌ INVALIDE'}")
    print(f"🔍 Bob vérifie la clé d'Alice : {'✅ VALIDE' if bob_verified else '❌ INVALIDE'}")

    if alice_verified and bob_verified:
        secret = compute_dh_shared_secret(alice_dh_priv, bob_dh_pub)
        print(f"\n🔐 Secret partagé établi de manière AUTHENTIFIÉE")
        print(f"   MITM impossible car les clés sont signées !")

    return alice_verified and bob_verified


# ============================================================
#  MENU
# ============================================================

def menu():
    print("\n" + "=" * 55)
    print("  DIFFIE-HELLMAN KEY EXCHANGE")
    print("=" * 55)
    print("1. Simuler échange DH normal")
    print("2. Simuler attaque Man-in-the-Middle (MITM)")
    print("3. Échange DH authentifié par ECDSA")
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
                simulate_dh_exchange()

            elif choix == 2:
                print("\n" + "=" * 60)
                print("  SIMULATION ATTAQUE MITM")
                print("=" * 60)

                parameters = generate_dh_parameters_secure()
                alice_priv, alice_pub = generate_dh_key_pair(parameters)
                bob_priv, bob_pub = generate_dh_key_pair(parameters)

                print(f"\n👤 Alice - Clé publique : {alice_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex()[:32]}...")
                print(f"👤 Bob   - Clé publique : {bob_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex()[:32]}...")

                attacker = MITMAttacker()
                fake_alice_pub, fake_bob_pub = attacker.intercept_and_replace(alice_pub, bob_pub)
                attacker.establish_sessions(alice_pub, bob_pub)

            elif choix == 3:
                simulate_authenticated_dh()

        except Exception as e:
            print(f"Erreur : {e}")
