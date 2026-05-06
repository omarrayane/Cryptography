# keygen.py - Génération des paires de clés RSA
# ============================================================

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os


def generate_keys(name: str, key_size: int = 2048):
    """
    Génère une paire de clés RSA pour un utilisateur.
    """
    print(f"[*] Génération de la paire de clés pour {name}...")

    # Générer les clés
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Créer le dossier si nécessaire
    os.makedirs("keys", exist_ok=True)

    # Chemins
    private_path = f"keys/{name}_private_key.pem"
    public_path = f"keys/{name}_public_key.pem"

    # Sauvegarder clé privée
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Sauvegarder clé publique
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"[+] {private_path} créée (SECRET!)")
    print(f"[+] {public_path} créée (à partager)")

    return private_key, public_key


def load_private_key(name: str):
    """Charge une clé privée depuis le dossier keys."""
    path = f"keys/{name}_private_key.pem"
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )


def load_public_key(name: str):
    """Charge une clé publique depuis le dossier keys."""
    path = f"keys/{name}_public_key.pem"
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )


def exchange_public_keys():
    """
    Simule l'échange de clés publiques entre serveur et client.
    En pratique, on copie manuellement les fichiers .pem.
    """
    print("\n" + "=" * 50)
    print("  ÉCHANGE DE CLÉS PUBLIQUES")
    print("=" * 50)
    print("\nPour que la communication fonctionne :")
    print("  1. Chaque partie génère sa paire de clés")
    print("  2. Échanger les clés PUBLIQUES (server_public.pem ↔ client_public.pem)")
    print("\n📌 Simulation d'échange :")

    # Vérifier l'existence des clés
    if os.path.exists("keys/server_public_key.pem") and os.path.exists("keys/client_public_key.pem"):
        print("   ✅ Clés publiques disponibles pour les deux parties")
        return True
    else:
        print("   ❌ Clés manquantes. Générez-les d'abord !")
        return False


if __name__ == "__main__":
    print("=" * 50)
    print("  GÉNÉRATEUR DE CLÉS RSA 2048")
    print("=" * 50)

    # Créer le dossier keys
    os.makedirs("keys", exist_ok=True)

    # Générer les clés pour server et client
    generate_keys("server")
    print()
    generate_keys("client")

    print("\n[✓] Clés générées avec succès!")
    print("\n📁 Fichiers créés dans le dossier 'keys/':")
    print("   - server_private_key.pem (secret)")
    print("   - server_public_key.pem")
    print("   - client_private_key.pem (secret)")
    print("   - client_public_key.pem")

    print("\n🚀 Prochaines étapes:")
    print("   Terminal 1: python secure_server.py")
    print("   Terminal 2: python secure_client.py")
