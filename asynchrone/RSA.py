
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import time

#  GÉNÉRATION DE CLÉS RSA

def generate_rsa_key_pair(key_size: int = 2048):
    """
    Génère une paire de clés RSA.
    key_size: 512, 1024, 2048, 3072, 4096 bits
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def export_keys(private_key, public_key):
    """
    Exporte les clés au format PEM.
    """
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def rsa_encrypt_oaep(message: bytes, public_key) -> bytes:
    """
    Chiffre avec RSA-OAEP (sécurisé).
    """
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt_oaep(ciphertext: bytes, private_key) -> bytes:
    """
    Déchiffre avec RSA-OAEP.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def rsa_encrypt_raw(message: bytes, public_key) -> bytes:
    """
    RSA textbook (sans padding) - VULNÉRABLE, ne pas utiliser en production.
    """
    return public_key.encrypt(message, padding.PKCS1v15())

def hybrid_encrypt(message: bytes, rsa_public_key) -> tuple:
    """
    Chiffrement hybride :
    - Génère une clé AES aléatoire
    - Chiffre le message avec AES-GCM
    - Chiffre la clé AES avec RSA
    """
    if isinstance(message, str):
        message = message.encode('utf-8')

    # Génération clé AES
    aes_key = os.urandom(32)  # AES-256

    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    encrypted_key = rsa_encrypt_oaep(aes_key, rsa_public_key)

    return encrypted_key, iv, ciphertext, encryptor.tag

def hybrid_decrypt(encrypted_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, rsa_private_key) -> bytes:
    """
    Déchiffrement hybride.
    """
    # Déchiffrement de la clé AES avec RSA
    aes_key = rsa_decrypt_oaep(encrypted_key, rsa_private_key)

    # Déchiffrement du message avec AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

def benchmark_hybrid_vs_rsa(data_size_mb: float = 1):
    """
    Compare les performances du chiffrement hybride vs RSA pur.
    """
    print("\n" + "=" * 60)
    print(f"  BENCHMARK CHIFFREMENT HYBRIDE vs RSA")
    print(f"  (Message: {data_size_mb} Mo)")
    print("=" * 60)

    data = os.urandom(int(data_size_mb * 1024 * 1024))

    # Génération des clés RSA
    rsa_priv, rsa_pub = generate_rsa_key_pair(2048)

    small_data = os.urandom(190)  # 190 bytes max pour RSA-2048 OAEP

    start = time.time()
    rsa_encrypted = rsa_encrypt_oaep(small_data, rsa_pub)
    rsa_enc_time = time.time() - start

    start = time.time()
    rsa_decrypted = rsa_decrypt_oaep(rsa_encrypted, rsa_priv)
    rsa_dec_time = time.time() - start

    start = time.time()
    enc_key, iv, ciphertext, tag = hybrid_encrypt(data, rsa_pub)
    hybrid_enc_time = time.time() - start

    start = time.time()
    hybrid_decrypted = hybrid_decrypt(enc_key, iv, ciphertext, tag, rsa_priv)
    hybrid_dec_time = time.time() - start

    print(f"\n{'Méthode':<15} {'Taille max':<15} {'Chiffrement (s)':<18} {'Déchiffrement (s)':<18}")
    print("-" * 70)
    print(f"{'RSA seul':<15} {'190 bytes':<15} {rsa_enc_time:<18.6f} {rsa_dec_time:<18.6f}")
    print(f"{'Hybride AES+RSA':<15} {'illimitée':<15} {hybrid_enc_time:<18.6f} {hybrid_dec_time:<18.6f}")

    print(f"\n📊 Le chiffrement hybride permet de chiffrer des FICHIERS ENTIERS")
    print(f"   alors que RSA seul est limité à la taille de la clé.")

#  DÉMONSTRATION TAILLES DE CLÉ

def demonstrate_key_sizes():
    """
    Génère des clés RSA de différentes tailles.
    """
    print("\n" + "=" * 60)
    print("  RSA - COMPARAISON DES TAILLES DE CLÉ")
    print("=" * 60)

    for size in [512, 1024, 2048]:
        print(f"\n📌 Taille de clé : {size} bits")

        start = time.time()
        priv, pub = generate_rsa_key_pair(size)
        gen_time = time.time() - start

        priv_pem, pub_pem = export_keys(priv, pub)

        print(f"   - Génération : {gen_time:.4f} secondes")
        print(f"   - Clé privée : {len(priv_pem)} bytes")
        print(f"   - Clé publique: {len(pub_pem)} bytes")
        print(f"   - Taille max chiffrée (OAEP): {size//8 - 42} bytes")

def menu():
    print("\n" + "=" * 55)
    print("  RSA (Rivest-Shamir-Adleman)")
    print("=" * 55)
    print("1. Générer des clés RSA")
    print("2. Chiffrer/Déchiffrer avec RSA-OAEP")
    print("3. Chiffrement hybride RSA + AES")
    print("4. Benchmark RSA vs Hybride")
    print("5. Comparer les tailles de clés")
    print("6. Quitter")
    print("-" * 55)

if __name__ == "__main__":
    while True:
        menu()

        try:
            choix = int(input("Choisissez une option : "))

            if choix == 6:
                print("Au revoir !")
                break

            if choix == 1:
                size = int(input("Taille de clé (512, 1024, 2048, 4096) : ") or "2048")
                priv, pub = generate_rsa_key_pair(size)
                priv_pem, pub_pem = export_keys(priv, pub)

                print(f"\n✅ Clé PRIVÉE (à garder secrète) :\n{priv_pem.decode()}")
                print(f"\n✅ Clé PUBLIQUE (à partager) :\n{pub_pem.decode()}")

                # Sauvegarde
                with open(f"rsa_{size}_private.pem", "wb") as f:
                    f.write(priv_pem)
                with open(f"rsa_{size}_public.pem", "wb") as f:
                    f.write(pub_pem)
                print(f"\n💾 Clés sauvegardées dans rsa_{size}_*.pem")

            elif choix == 2:
                mode = input("Chiffrer (c) ou Déchiffrer (d) ? ").lower()
                key_file = input("Fichier de clé (.pem) : ")

                with open(key_file, "rb") as f:
                    key_data = f.read()

                if "private" in key_file:
                    priv = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())

                    if mode == 'd':
                        ciphertext_hex = input("Chiffré (hex) : ")
                        ciphertext = bytes.fromhex(ciphertext_hex)
                        plaintext = rsa_decrypt_oaep(ciphertext, priv)
                        print(f"Message déchiffré : {plaintext.decode()}")
                else:
                    pub = serialization.load_pem_public_key(key_data, backend=default_backend())

                    if mode == 'c':
                        test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                        if test == 't':
                            message = b"Message secret avec RSA-OAEP"
                            print(f"Message de test : {message.decode()}")
                        else:
                            message = input("Message à chiffrer : ").encode()

                        ciphertext = rsa_encrypt_oaep(message, pub)
                        print(f"Chiffré (hex) : {ciphertext.hex()}")

            elif choix == 3:
                test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                if test == 't':
                    message = b"Ceci est un message tres long qui peut etre chiffre via le mode hybride AES+RSA"
                    print(f"Message de test : {message.decode()}")
                else:
                    message = input("Message à chiffrer : ").encode()

                # Génération clés RSA temporaires
                rsa_priv, rsa_pub = generate_rsa_key_pair(2048)

                print("\n[Chiffrement hybride]")
                enc_key, iv, ciphertext, tag = hybrid_encrypt(message, rsa_pub)
                print(f"Clé AES chiffrée (hex) : {enc_key.hex()}")
                print(f"IV (hex) : {iv.hex()}")
                print(f"Chiffré (hex) : {ciphertext.hex()}")
                print(f"Tag (hex) : {tag.hex()}")

                print("\n[Déchiffrement hybride]")
                decrypted = hybrid_decrypt(enc_key, iv, ciphertext, tag, rsa_priv)
                print(f"Message déchiffré : {decrypted.decode()}")

            elif choix == 4:
                size = float(input("Taille en Mo (ex: 1) : ") or "1")
                benchmark_hybrid_vs_rsa(size)

            elif choix == 5:
                demonstrate_key_sizes()

        except Exception as e:
            print(f"Erreur : {e}")
