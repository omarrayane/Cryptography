"""
keygen.py - Génère les paires de clés RSA pour communication sécurisée
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_keys(name):
    """Génère une paire de clés RSA 2048"""
    print(f"[*] Génération de la paire de clés pour {name}...")
    
    # Générer les clés
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Chemins
    private_path = f"{name}_private_key.pem"
    public_path = f"{name}_public_key.pem"
    
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


if __name__ == "__main__":
    print("=" * 50)
    print("Générateur de clés RSA 2048")
    print("=" * 50)
    
    # Générer les clés pour server et client
    generate_keys("server")
    print()
    generate_keys("client")
    
    print("\n[✓] Clés générées avec succès!")
    print("\nFichiers créés:")
    print("  - server_private_key.pem (secret)")
    print("  - server_public_key.pem")
    print("  - client_private_key.pem (secret)")
    print("  - client_public_key.pem")
    print("\nProchaines étapes:")
    print("  1. Terminal 1: python server.py")
    print("  2. Terminal 2: python client.py")