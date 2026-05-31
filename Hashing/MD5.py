# MD5.py - Message Digest 5

import hashlib
import time
import os
from collections import Counter

def md5_hash(data):
    """
    Calcule le hash MD5 d'une donnée.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()

def md5_file_hash(filename):
    """
    Calcule le hash MD5 d'un fichier.
    """
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5.update(chunk)
    return md5.hexdigest()

def avalanche_effect_md5():
    """
    Calcule l'effet avalanche : modification d'1 bit du message.
    Doit donner ≈ 50% de bits différents.
    """
    print("\n" + "=" * 60)
    print("  EFFET AVALANCHE - MD5")
    print("  (Modification d'1 bit du message)")
    print("=" * 60)

    original = b"Hello World"

    modified = bytearray(original)
    modified[0] ^= 0x01  # Modifier 1 bit

    h1 = hashlib.md5(original).digest()
    h2 = hashlib.md5(bytes(modified)).digest()

    print(f"\nMessage original : {original}")
    print(f"Message modifié  : {bytes(modified)}")
    print(f"Hash1 : {h1.hex()}")
    print(f"Hash2 : {h2.hex()}")

    # Comparaison bit à bit
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
    else:
        print(f"   ⚠️  Ratio anormal ({ratio:.2f}%)")

def benchmark_md5(sizes_mb=[1, 10, 100]):
    """
    Benchmark MD5 sur différentes tailles.
    """
    print("\n" + "=" * 60)
    print("  BENCHMARK MD5")
    print("=" * 60)

    print(f"\n{'Taille':<15} {'Temps (s)':<15} {'Débit (Mo/s)':<15}")
    print("-" * 45)

    for size_mb in sizes_mb:
        data = os.urandom(size_mb * 1024 * 1024)

        start = time.time()
        hash_result = hashlib.md5(data).hexdigest()
        elapsed = time.time() - start

        throughput = size_mb / elapsed if elapsed > 0 else 0
        print(f"{size_mb} Mo{'':<10} {elapsed:<15.4f} {throughput:<15.2f}")

def demonstrate_collision_vulnerability():
    """
    Démontre que MD5 est vulnérable aux collisions.
    """
    print("\n" + "=" * 60)
    print("  VULNÉRABILITÉ DE MD5")
    print("  (Collisions connues depuis 2004 - Wang & Yu)")
    print("=" * 60)

    # Deux messages différents qui produisent le même hash MD5
    # (exemple pédagogique - vraies collisions trouvées par Wang & Yu)

    print("\n🔴 MD5 est cassé depuis 2004 :")
    print("   - Collisions pratiques trouvées")
    print("   - Attaques par préfixe choisi (2007)")
    print("   - Génération de certificats falsifiés (2008)")
    print("\n📌 Ne plus utiliser MD5 pour la sécurité :")
    print("   - Signature numérique")
    print("   - Certificats SSL")
    print("   - Stockage de mots de passe")
    print("\n✅ Encore acceptable pour :")
    print("   - Checksums de fichiers (intégrité non critique)")
    print("   - Hachage de données non sensibles")

def menu():
    print("\n" + "=" * 50)
    print("      MD5 - MESSAGE DIGEST 5")
    print("=" * 50)
    print("1. Hacher un message")
    print("2. Hacher un fichier")
    print("3. Effet avalanche")
    print("4. Benchmark")
    print("5. Vulnérabilités MD5")
    print("6. Quitter")
    print("-" * 50)

if __name__ == "__main__":
    while True:
        menu()

        try:
            choix = int(input("Choisissez une option : "))

            if choix == 6:
                print("Au revoir !")
                break

            if choix == 1:
                test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                if test == 't':
                    message = "Hello World"
                    print(f"Message de test : {message}")
                else:
                    message = input("📝 Entrez le message : ")

                hash_result = md5_hash(message)
                print(f"\nHash MD5 (128 bits / 32 hex) : {hash_result}")
                print(f"Longueur : {len(hash_result)} caractères hex")

            elif choix == 2:
                filename = input("Nom du fichier : ")
                if os.path.exists(filename):
                    hash_result = md5_file_hash(filename)
                    print(f"\nHash MD5 de {filename} : {hash_result}")
                else:
                    print(f"❌ Fichier {filename} introuvable")

            elif choix == 3:
                avalanche_effect_md5()

            elif choix == 4:
                benchmark_md5()

            elif choix == 5:
                demonstrate_collision_vulnerability()

        except Exception as e:
            print(f"Erreur : {e}")
