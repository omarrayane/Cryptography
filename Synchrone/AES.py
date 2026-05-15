# AES.PY - Utilisation de pycryptodome
# ============================================================

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import time
from PIL import Image
import numpy as np
from collections import Counter


def aes_encrypt_ecb(data, key):
    """AES mode ECB."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')[:32].ljust(32, b'\x00')

    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(data, AES.block_size)
    return cipher.encrypt(padded)


def aes_decrypt_ecb(ciphertext, key):
    """AES mode ECB."""
    if isinstance(key, str):
        key = key.encode('utf-8')[:32].ljust(32, b'\x00')

    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, AES.block_size).decode('utf-8')


def aes_encrypt_cbc(data, key, iv=None):
    """AES mode CBC."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')[:32].ljust(32, b'\x00')
    if iv is None:
        iv = get_random_bytes(AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext


def aes_decrypt_cbc(ciphertext, key):
    """AES mode CBC."""
    if isinstance(key, str):
        key = key.encode('utf-8')[:32].ljust(32, b'\x00')

    iv = ciphertext[:AES.block_size]
    actual_ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(actual_ciphertext)
    return unpad(decrypted, AES.block_size).decode('utf-8')


def aes_encrypt_ctr(data, key, nonce=None):
    """AES mode CTR."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')[:32].ljust(32, b'\x00')
    if nonce is None:
        nonce = get_random_bytes(8)

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    return nonce + ciphertext


def aes_decrypt_ctr(ciphertext, key):
    """AES mode CTR."""
    if isinstance(key, str):
        key = key.encode('utf-8')[:32].ljust(32, b'\x00')

    nonce = ciphertext[:8]
    actual_ciphertext = ciphertext[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(actual_ciphertext).decode('utf-8')


def avalanche_effect_cbc():
    """Modifie 1 bit du IV et observe la propagation."""
    print("\n" + "=" * 60)
    print("  EFFET AVALANCHE EN MODE CBC")
    print("  (Modification d'1 bit du IV)")
    print("=" * 60)

    key = get_random_bytes(32)  # AES-256
    plaintext = b"Message super important a chiffrer avec AES-CBC"

    # Chiffrer avec IV original
    iv1 = get_random_bytes(16)
    cipher1 = AES.new(key, AES.MODE_CBC, iv=iv1)
    padded = pad(plaintext, AES.block_size)
    encrypted1 = cipher1.encrypt(padded)

    # Chiffrer avec IV modifié (1 bit de différence)
    iv2 = bytearray(iv1)
    iv2[0] ^= 0x01  # Modifier 1 bit
    cipher2 = AES.new(key, AES.MODE_CBC, iv=bytes(iv2))
    encrypted2 = cipher2.encrypt(padded)

    # Comparer bloc par bloc
    print(f"\nPlaintext : {plaintext.decode()}")
    print(f"\nTaux de bits différents par bloc :")

    for block_idx in range(len(encrypted1) // 16):
        block1 = encrypted1[block_idx*16:(block_idx+1)*16]
        block2 = encrypted2[block_idx*16:(block_idx+1)*16]

        different_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(block1, block2))
        total_bits = 16 * 8
        ratio = different_bits / total_bits * 100

        print(f"  Bloc {block_idx + 1}: {ratio:.1f}% de bits différents")

    print("\n✅ Notez que la modification d'1 bit du IV affecte TOUS les blocs!")


def nonce_reuse_ctr_attack():
    """
    Vulnérabilité nonce-reuse en mode CTR.
    Si le même nonce est utilisé pour deux messages, C1 XOR C2 = M1 XOR M2.
    """
    print("\n" + "=" * 60)
    print("  VULNÉRABILITÉ NONCE-REUSE (MODE CTR)")
    print("=" * 60)

    key = get_random_bytes(32)
    nonce = get_random_bytes(8)

    message1 = "Bonjour ceci est un message secret"
    message2 = "Ne pas divulguer cette information"

    print(f"Message 1 : {message1}")
    print(f"Message 2 : {message2}")

    # Chiffrer avec le MÊME nonce (vulnérabilité)
    cipher1 = AES.new(key, AES.MODE_CTR, nonce=nonce)
    cipher2 = AES.new(key, AES.MODE_CTR, nonce=nonce)

    encrypted1 = cipher1.encrypt(message1.encode())
    encrypted2 = cipher2.encrypt(message2.encode())

    # Attaque : C1 XOR C2 = M1 XOR M2
    xor_result = bytes(e1 ^ e2 for e1, e2 in zip(encrypted1, encrypted2))

    print(f"\nC1 XOR C2 = {xor_result.hex()[:50]}...")
    print("\nUn attaquant peut maintenant tenter de deviner les messages")
    print("en utilisant cette information (crib dragging).")

    # Petit crib dragging
    print("\n[Exemple de crib dragging]")
    print("Si on suppose que 'secret' apparaît dans message1:")

    crib = "secret"
    crib_bytes = crib.encode()

    for pos in range(len(xor_result) - len(crib_bytes)):
        recovered = bytes(xor_result[pos + i] ^ crib_bytes[i] for i in range(len(crib_bytes)))
        try:
            recovered_str = recovered.decode('utf-8')
            if all(32 <= ord(c) < 127 for c in recovered_str):
                print(f"  Position {pos}: '{recovered_str}'")
        except:
            pass


def benchmark_aes_variants(size_mb=10):
    """Compare AES-128, AES-192, AES-256."""
    print("\n" + "=" * 60)
    print(f"  BENCHMARK AES (sur {size_mb} Mo)")
    print("=" * 60)

    data = os.urandom(size_mb * 1024 * 1024)

    results = {}
    for bits, key_size in [(128, 16), (192, 24), (256, 32)]:
        key = get_random_bytes(key_size)

        start = time.time()
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        enc_time = time.time() - start

        start = time.time()
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
        dec_time = time.time() - start

        results[bits] = {
            'encrypt': enc_time,
            'decrypt': dec_time,
            'throughput': size_mb / enc_time
        }

    print(f"\n{'AES':<10} {'Chiffrement (s)':<18} {'Déchiffrement (s)':<18} {'Débit (Mo/s)':<15}")
    print("-" * 65)
    for bits, metrics in results.items():
        print(f"AES-{bits:<3} {metrics['encrypt']:<18.4f} {metrics['decrypt']:<18.4f} {metrics['throughput']:<15.2f}")

    print("\n✅ AES-128 est le plus rapide, AES-256 offre plus de sécurité")


def compare_ecb_cbc_ctr_image():
    """Chiffre une image avec différents modes."""
    print("\n" + "=" * 60)
    print("  COMPARAISON DES MODES SUR IMAGE")
    print("=" * 60)

    # Créer une image simple
    img = Image.new('RGB', (128, 128))
    pixels = img.load()

    # Motif damier
    for i in range(128):
        for j in range(128):
            if (i // 8) % 2 == (j // 8) % 2:
                pixels[i, j] = (255, 255, 255)
            else:
                pixels[i, j] = (0, 0, 0)

    img.save("original_aes.png")
    img_bytes = np.array(img).tobytes()
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    nonce = get_random_bytes(8)

    # ECB
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    padded = pad(img_bytes, AES.block_size)
    encrypted_ecb = cipher_ecb.encrypt(padded)
    enc_ecb_img = Image.frombytes('RGB', (128, 128), encrypted_ecb[:128*128*3])
    enc_ecb_img.save("aes_ecb_image.png")
    print("✅ AES-ECB: aec_ecb_image.png (motifs VISIBLES)")

    # CBC
    cipher_cbc = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_cbc = cipher_cbc.encrypt(padded)
    enc_cbc_img = Image.frombytes('RGB', (128, 128), encrypted_cbc[:128*128*3])
    enc_cbc_img.save("aes_cbc_image.png")
    print("✅ AES-CBC: aec_cbc_image.png (aucun motif visible)")

    # CTR
    cipher_ctr = AES.new(key, AES.MODE_CTR, nonce=nonce)
    encrypted_ctr = cipher_ctr.encrypt(img_bytes)
    enc_ctr_img = Image.frombytes('RGB', (128, 128), encrypted_ctr[:128*128*3])
    enc_ctr_img.save("aes_ctr_image.png")
    print("✅ AES-CTR: aec_ctr_image.png (aucun motif visible)")

    print("\n📁 Ouvrez les images :")
    print("   - ECB: motifs encore visibles (faiblesse)")
    print("   - CBC/CTR: aspect aléatoire (sécurisé)")


def menu():
    print("\n" + "=" * 50)
    print("      AES (128/192/256)")
    print("=" * 50)
    print("1. Chiffrer/Déchiffrer (CBC)")
    print("2. Comparer ECB/CBC/CTR sur image")
    print("3. Effet avalanche CBC")
    print("4. Vulnérabilité nonce-reuse CTR")
    print("5. Benchmark AES-128 vs 192 vs 256")
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
                mode = input("Chiffrer (c) ou Déchiffrer (d) ? ").lower()
                bits = input("AES-128, 192 ou 256 bits ? ") or "256"
                key_size = int(bits) // 8

                if mode == 'c':
                    test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                    if test == 't':
                        message = "Message secret avec AES"
                        print(f"Message de test : {message}")
                    else:
                        message = input("📝 Entrez le message à chiffrer : ")

                    key = get_random_bytes(key_size)
                    ciphertext = aes_encrypt_cbc(message, key)
                    print(f"IV + Chiffré (hex) : {ciphertext.hex()}")
                    print(f"Clé (hex) : {key.hex()}")

                else:
                    key_hex = input("Entrez la clé (hex) : ")
                    key = bytes.fromhex(key_hex)
                    test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()

                    if test == 't':
                        message = "Message secret avec AES"
                        ciphertext = aes_encrypt_cbc(message, key)
                        print(f"IV + Chiffré de test : {ciphertext.hex()}")
                    else:
                        ciphertext_hex = input("Entrez l'IV + chiffré (hex) : ")
                        ciphertext = bytes.fromhex(ciphertext_hex)

                    decrypted = aes_decrypt_cbc(ciphertext, key)
                    print(f"Message déchiffré : {decrypted}")

            elif choix == 2:
                compare_ecb_cbc_ctr_image()

            elif choix == 3:
                avalanche_effect_cbc()

            elif choix == 4:
                nonce_reuse_ctr_attack()

            elif choix == 5:
                size = float(input("Taille en Mo (ex: 10) : ") or "10")
                benchmark_aes_variants(size)

        except Exception as e:
            print(f"Erreur : {e}")
