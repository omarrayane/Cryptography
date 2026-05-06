# SHA512.py - Secure Hash Algorithm 2 (512 bits)
# ============================================================

import hashlib
import time
import os


def sha512_hash(data):
    """
    Calcule le hash SHA-512 d'une donnée.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha512(data).hexdigest()


def sha512_file_hash(filename):
    """
    Calcule le hash SHA-512 d'un fichier.
    """
    sha512 = hashlib.sha512()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha512.update(chunk)
    return sha512.hexdigest()


def avalanche_effect_sha512():
    """
    Calcule l'effet avalanche pour SHA-512.
    """
    print("\n" + "=" * 60)
    print("  EFFET AVALANCHE - SHA-512")
    print("=" * 60)

    original = b"Hello World"
    modified = bytearray(original)
    modified[0] ^= 0x01

    h1 = hashlib.sha512(original).digest()
    h2 = hashlib.sha512(bytes(modified)).digest()

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


def benchmark_all_hash(size_mb=100):
    """
    Benchmark complet : MD5, SHA-256, SHA-512 sur 100 Mo.
    """
    print("\n" + "=" * 60)
    print(f"  BENCHMARK HACHAGE (sur {size_mb} Mo)")
    print("=" * 60)

    data = os.urandom(size_mb * 1024 * 1024)

    results = {}

    # MD5
    start = time.time()
    hashlib.md5(data).hexdigest()
    results['MD5'] = time.time() - start

    # SHA-256
    start = time.time()
    hashlib.sha256(data).hexdigest()
    results['SHA-256'] = time.time() - start

    # SHA-512 (plus rapide sur CPU 64 bits)
    start = time.time()
    hashlib.sha512(data).hexdigest()
    results['SHA-512'] = time.time() - start

    print(f"\n{'Algorithme':<12} {'Temps (s)':<15} {'Débit (Mo/s)':<15} {'Taille sortie':<15}")
    print("-" * 60)

    for algo, elapsed in results.items():
        throughput = size_mb / elapsed if elapsed > 0 else 0
        output_size = {"MD5": "128 bits", "SHA-256": "256 bits", "SHA-512": "512 bits"}[algo]
        print(f"{algo:<12} {elapsed:<15.4f} {throughput:<15.2f} {output_size:<15}")

    # Trouver le plus rapide et le plus lent
    fastest = min(results, key=results.get)
    slowest = max(results, key=results.get)

    print(f"\n📊 Résultat sur cette machine :")
    print(f"   ✅ Le plus rapide : {fastest} ({results[fastest]:.4f}s)")
    print(f"   ⚠️  Le plus lent   : {slowest} ({results[slowest]:.4f}s)")
    print(f"\n   Note : SHA-512 est souvent plus rapide que SHA-256 sur les CPU 64 bits")


def compare_all_hash():
    """
    Compare MD5, SHA-256, SHA-512 sur le même message.
    """
    print("\n" + "=" * 60)
    print("  COMPARAISON MD5 / SHA-256 / SHA-512")
    print("=" * 60)

    test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
    if test == 't':
        message = "La cryptographie est fascinante!"
        print(f"Message de test : {message}")
    else:
        message = input("📝 Entrez le message : ")

    print(f"\n{'Algorithme':<12} {'Hash':<70} {'Taille':<10} {'Temps (µs)':<12}")
    print("-" * 105)

    data = message.encode('utf-8')

    # MD5
    start = time.perf_counter()
    md5_result = hashlib.md5(data).hexdigest()
    md5_time = (time.perf_counter() - start) * 1_000_000

    # SHA-256
    start = time.perf_counter()
    sha256_result = hashlib.sha256(data).hexdigest()
    sha256_time = (time.perf_counter() - start) * 1_000_000

    # SHA-512
    start = time.perf_counter()
    sha512_result = hashlib.sha512(data).hexdigest()
    sha512_time = (time.perf_counter() - start) * 1_000_000

    print(f"{'MD5':<12} {md5_result:<70} {'128 bits':<10} {md5_time:<12.2f}")
    print(f"{'SHA-256':<12} {sha256_result:<70} {'256 bits':<10} {sha256_time:<12.2f}")
    print(f"{'SHA-512':<12} {sha512_result:<70} {'512 bits':<10} {sha512_time:<12.2f}")


def sha512_vs_sha256_performance():
    """
    Compare spécifiquement SHA-256 vs SHA-512.
    SHA-512 peut être plus rapide sur CPU 64 bits.
    """
    print("\n" + "=" * 60)
    print("  SHA-256 vs SHA-512 (performances)")
    print("=" * 60)

    size_mb = 50
    data = os.urandom(size_mb * 1024 * 1024)

    start = time.time()
    hashlib.sha256(data).hexdigest()
    sha256_time = time.time() - start

    start = time.time()
    hashlib.sha512(data).hexdigest()
    sha512_time = time.time() - start

    ratio = sha256_time / sha512_time if sha512_time > 0 else 0

    print(f"\nSHA-256 : {sha256_time:.4f} secondes")
    print(f"SHA-512 : {sha512_time:.4f} secondes")

    if ratio > 1:
        print(f"\n📊 SHA-512 est {ratio:.2f}x PLUS RAPIDE que SHA-256 sur cette machine")
        print("   (avantage des CPU 64 bits)")
    else:
        print(f"\n📊 SHA-256 est {1/ratio:.2f}x PLUS RAPIDE que SHA-512 sur cette machine")


def menu():
    print("\n" + "=" * 50)
    print("      SHA-512 - SECURE HASH ALGORITHM")
    print("=" * 50)
    print("1. Hacher un message")
    print("2. Hacher un fichier")
    print("3. Effet avalanche")
    print("4. Comparer MD5/SHA256/SHA512")
    print("5. Benchmark 100 Mo (MD5/SHA256/SHA512)")
    print("6. SHA-256 vs SHA-512 (performance)")
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

                hash_result = sha512_hash(message)
                print(f"\nSHA-512 (512 bits / 128 hex) : {hash_result}")
                print(f"Longueur : {len(hash_result)} caractères hex")

            elif choix == 2:
                filename = input("Nom du fichier : ")
                if os.path.exists(filename):
                    hash_result = sha512_file_hash(filename)
                    print(f"\nSHA-512 de {filename} : {hash_result}")
                else:
                    print(f"❌ Fichier {filename} introuvable")

            elif choix == 3:
                avalanche_effect_sha512()

            elif choix == 4:
                compare_all_hash()

            elif choix == 5:
                benchmark_all_hash(100)

            elif choix == 6:
                sha512_vs_sha256_performance()

        except Exception as e:
            print(f"Erreur : {e}")
