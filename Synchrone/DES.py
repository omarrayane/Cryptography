# DES.py - Utilisation de pycryptodome
# ============================================================

from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import time
from PIL import Image
import numpy as np


def des_ecb_encrypt(data, key):
    """DES mode ECB."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')[:8].ljust(8, b'\x00')

    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(data, DES.block_size)
    return cipher.encrypt(padded)


def des_ecb_decrypt(ciphertext, key):
    """DES mode ECB."""
    if isinstance(key, str):
        key = key.encode('utf-8')[:8].ljust(8, b'\x00')

    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, DES.block_size).decode('utf-8')


def des_cbc_encrypt(data, key, iv=None):
    """DES mode CBC avec IV aléatoire."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')[:8].ljust(8, b'\x00')
    if iv is None:
        iv = get_random_bytes(DES.block_size)

    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    padded = pad(data, DES.block_size)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext


def des_cbc_decrypt(ciphertext, key):
    """DES mode CBC."""
    if isinstance(key, str):
        key = key.encode('utf-8')[:8].ljust(8, b'\x00')

    iv = ciphertext[:DES.block_size]
    actual_ciphertext = ciphertext[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(actual_ciphertext)
    return unpad(decrypted, DES.block_size).decode('utf-8')


def triple_des_cbc_encrypt(data, key):
    """Triple DES mode CBC."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')[:24].ljust(24, b'\x00')

    iv = get_random_bytes(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded = pad(data, DES3.block_size)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext


def triple_des_cbc_decrypt(ciphertext, key):
    """Triple DES mode CBC."""
    if isinstance(key, str):
        key = key.encode('utf-8')[:24].ljust(24, b'\x00')

    iv = ciphertext[:DES3.block_size]
    actual_ciphertext = ciphertext[DES3.block_size:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(actual_ciphertext)
    return unpad(decrypted, DES3.block_size).decode('utf-8')


def create_ecb_vulnerability_image():
    """
    Crée une image simple pour démontrer la faiblesse d'ECB.
    Les motifs restent visibles dans l'image chiffrée.
    """
    print("\n" + "=" * 60)
    print("  DÉMONSTRATION FAIBLESSE ECB")
  print("  (Les motifs restent visibles)")
    print("=" * 60)

    # Créer une image 64x64 pixels avec des motifs
    img = Image.new('RGB', (64, 64))
    pixels = img.load()

    # Motif : carré blanc sur fond noir
    for i in range(64):
        for j in range(64):
            if 16 <= i < 48 and 16 <= j < 48:
                pixels[i, j] = (255, 255, 255)  # Blanc
            elif (i // 8) % 2 == (j // 8) % 2:
                pixels[i, j] = (100, 100, 100)  # Gris
            else:
                pixels[i, j] = (0, 0, 0)  # Noir

    img.save("original_image.png")
    print("✅ Image originale créée : original_image.png")

    # Chiffrer avec ECB
    key = b"12345678"
    img_bytes = np.array(img).tobytes()

    cipher_ecb = DES.new(key, DES.MODE_ECB)
    padded = pad(img_bytes, DES.block_size)
    encrypted_ecb = cipher_ecb.encrypt(padded)

    # Reconstruire l'image chiffrée
    encrypted_array = np.frombuffer(encrypted_ecb[:64*64*3], dtype=np.uint8)
    encrypted_img = Image.frombytes('RGB', (64, 64), encrypted_array.tobytes())
    encrypted_img.save("encrypted_ecb_image.png")
    print("✅ Image chiffrée ECB créée : encrypted_ecb_image.png")
    print("   (Observez que les motifs restent VISIBLES !)")

    # Chiffrer avec CBC pour comparaison
    iv = get_random_bytes(DES.block_size)
    cipher_cbc = DES.new(key, DES.MODE_CBC, iv=iv)
    encrypted_cbc = cipher_cbc.encrypt(padded)

    encrypted_cbc_array = np.frombuffer(encrypted_cbc[:64*64*3], dtype=np.uint8)
    encrypted_cbc_img = Image.frombytes('RGB', (64, 64), encrypted_cbc_array.tobytes())
    encrypted_cbc_img.save("encrypted_cbc_image.png")
    print("✅ Image chiffrée CBC créée : encrypted_cbc_image.png")
    print("   (Aucun motif visible normalement)")


def benchmark_des_vs_3des(size_mb=1):
    """Compare les performances DES vs 3DES."""
    print("\n" + "=" * 60)
    print(f"  BENCHMARK DES vs 3DES (sur {size_mb} Mo)")
    print("=" * 60)

    data = os.urandom(size_mb * 1024 * 1024)
    des_key = b"12345678"
    tdes_key = b"123456789012345678901234"

    # DES
    start = time.time()
    cipher_des = DES.new(des_key, DES.MODE_ECB)
    encrypted_des = cipher_des.encrypt(pad(data, DES.block_size))
    des_time = time.time() - start
    print(f"DES   : {des_time:.4f} secondes (débit: {size_mb/des_time:.2f} Mo/s)")

    # 3DES
    start = time.time()
    cipher_tdes = DES3.new(tdes_key, DES3.MODE_ECB)
    encrypted_tdes = cipher_tdes.encrypt(pad(data, DES3.block_size))
    tdes_time = time.time() - start
    print(f"3DES  : {tdes_time:.4f} secondes (débit: {size_mb/tdes_time:.2f} Mo/s)")

    print(f"\n3DES est {tdes_time/des_time:.1f}x plus lent que DES")


def compare_ecb_cbc():
    """Compare ECB et CBC sur un texte."""
    print("\n" + "=" * 60)
    print("  COMPARAISON ECB vs CBC")
    print("=" * 60)

    key = b"12345678"
    iv = get_random_bytes(DES.block_size)
    plaintext = "A" * 128 + "B" * 128  # Texte répétitif

    print(f"Plaintext : {plaintext[:50]}... (répétitif)")

    # ECB
    cipher_ecb = DES.new(key, DES.MODE_ECB)
    encrypted_ecb = cipher_ecb.encrypt(pad(plaintext.encode(), DES.block_size))
    print(f"\nECB - Blocs identiques → chiffrés identiques :")
    print(f"  Premier bloc : {encrypted_ecb[:8].hex()}")
    print(f"  Deuxième bloc: {encrypted_ecb[8:16].hex()}")
    print(f"  => Les blocs identiques produisent le même chiffré!")

    # CBC
    cipher_cbc = DES.new(key, DES.MODE_CBC, iv=iv)
    encrypted_cbc = cipher_cbc.encrypt(pad(plaintext.encode(), DES.block_size))
    print(f"\nCBC - Même texte, chiffré différent :")
    print(f"  Premier bloc : {encrypted_cbc[:8].hex()}")
    print(f"  Deuxième bloc: {encrypted_cbc[8:16].hex()}")
    print(f"  => Les blocs identiques produisent des chiffrés différents!")


def menu():
    print("\n" + "=" * 50)
    print("      DES / 3DES")
    print("=" * 50)
    print("1. Chiffrer/Déchiffrer (CBC)")
    print("2. Comparer ECB vs CBC")
    print("3. Visualiser faiblesse ECB (image)")
    print("4. Benchmark DES vs 3DES")
    print("5. Quitter")
    print("-" * 50)


if __name__ == "__main__":
    while True:
        menu()

        try:
            choix = int(input("Choisissez une option : "))

            if choix == 5:
                print("Au revoir !")
                break

            if choix == 1:
                mode = input("Chiffrer (c) ou Déchiffrer (d) ? ").lower()
                key = input("🔑 Entrez la clé (8 caractères) : ")[:8]

                if mode == 'c':
                    test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                    if test == 't':
                        message = "Message secret DES"
                        print(f"Message de test : {message}")
                    else:
                        message = input("📝 Entrez le message à chiffrer : ")

                    ciphertext = des_cbc_encrypt(message, key)
                    print(f"IV + Chiffré (hex) : {ciphertext.hex()}")

                else:
                    test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                    if test == 't':
                        message = "Message secret DES"
                        ciphertext = des_cbc_encrypt(message, key)
                        print(f"IV + Chiffré de test : {ciphertext.hex()}")
                    else:
                        ciphertext_hex = input("Entrez l'IV + chiffré (hex) : ")
                        ciphertext = bytes.fromhex(ciphertext_hex)

                    decrypted = des_cbc_decrypt(ciphertext, key)
                    print(f"Message déchiffré : {decrypted}")

            elif choix == 2:
                compare_ecb_cbc()

            elif choix == 3:
                create_ecb_vulnerability_image()
                print("\n📁 Ouvrez 'encrypted_ecb_image.png' avec un visualiseur d'images")
                print("   Vous verrez que les motifs sont encore VISIBLES !")
                print("   C'est la faiblesse majeure du mode ECB.")

            elif choix == 4:
                size = float(input("Taille en Mo (ex: 1) : ") or "1")
                benchmark_des_vs_3des(size)

        except Exception as e:
            print(f"Erreur : {e}")
