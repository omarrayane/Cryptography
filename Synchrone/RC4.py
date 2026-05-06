# RC4.py - Utilisation de pycryptodome
# ============================================================

from Crypto.Cipher import ARC4
import hashlib
import os
from collections import Counter
import matplotlib.pyplot as plt


class RC4:
    """Wrapper pour RC4 de pycryptodome."""

    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode('utf-8')
        self.key = key

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        cipher = ARC4.new(self.key)
        return cipher.encrypt(data)

    def decrypt(self, data):
        return self.encrypt(data)  # RC4 est symétrique


def weak_iv_attack_demo():
    """
    Vulnérabilité WEP : IV faibles.
    Sous certaines conditions, le premier octet du keystream est corrélé à la clé.
    """
    print("\n" + "=" * 60)
    print("  VULNÉRABILITÉ WEP - IV FAIBLES")
    print("=" * 60)

    # Simulation d'une clé WEP (5 ou 13 octets)
    secret_key = b"SecretKey"

    print("\nTest avec IV faibles (commençant par 0x00, 0x01, 0x02...):")
    print("-" * 50)

    for iv_prefix in [0x00, 0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xFF]:
        # WEP utilise IV + clé
        iv = bytes([iv_prefix, 0x00, 0x00])
        full_key = iv + secret_key

        rc4 = RC4(full_key)
        keystream = rc4.encrypt(b"\x00" * 10)  # Premier octets du keystream

        print(f"IV = {iv.hex()} : premier octet keystream = 0x{keystream[0]:02x}")


def rc4_byte_bias_analysis(num_keys=1000):
    """
    Analyse du biais statistique de RC4.
    Le second octet du keystream a une probabilité légèrement plus élevée d'être 0.
    """
    print("\n" + "=" * 60)
    print("  ANALYSE DES BIAIS STATISTIQUES RC4")
    print(f"  (Test sur {num_keys} clés aléatoires)")
    print("=" * 60)

    second_byte_counts = Counter()

    for _ in range(num_keys):
        key = os.urandom(16)  # Clé aléatoire 128 bits
        rc4 = RC4(key)
        keystream = rc4.encrypt(b"\x00" * 3)  # Générer 3 octets
        second_byte_counts[keystream[1]] += 1

    print("\nDistribution du 2ème octet du keystream :")
    print("-" * 40)

    # Afficher les valeurs les plus fréquentes
    for byte_val, count in second_byte_counts.most_common(10):
        expected = num_keys / 256
        bias = (count - expected) / expected * 100
        print(f"  0x{byte_val:02x} : {count:4d} occurrences (biais: {bias:+.2f}%)")

    # Vérifier le biais vers 0
    zero_count = second_byte_counts[0]
    expected = num_keys / 256
    zero_bias = (zero_count - expected) / expected * 100
    print(f"\n✅ Biais vers 0 : {zero_bias:+.2f}% (attendu: {expected:.1f}, observé: {zero_count})")

    return second_byte_counts


def plot_rc4_bias(byte_counts, num_keys):
    """Affiche un graphique des biais RC4."""
    expected = num_keys / 256
    biases = [(byte, (count - expected) / expected * 100) for byte, count in byte_counts.items()]
    biases.sort(key=lambda x: x[1], reverse=True)

    top_10 = biases[:10]
    bytes_vals = [b[0] for b in top_10]
    bias_vals = [b[1] for b in top_10]

    plt.figure(figsize=(10, 6))
    plt.bar(bytes_vals, bias_vals, color='skyblue')
    plt.axhline(y=0, color='red', linestyle='--', linewidth=0.5)
    plt.xlabel('Octet (hex)')
    plt.ylabel('Biais (%)')
    plt.title('Biais RC4 - Top 10 des octets')
    plt.xticks(bytes_vals, [f'0x{b:02x}' for b in bytes_vals])
    plt.show()


def menu():
    print("\n" + "=" * 50)
    print("      RC4 STREAM CIPHER")
    print("=" * 50)
    print("1. Chiffrer / Déchiffrer un message")
    print("2. Vulnérabilité WEP (IV faibles)")
    print("3. Biais statistiques RC4")
    print("4. Quitter")
    print("-" * 50)


if __name__ == "__main__":
    while True:
        menu()

        try:
            choix = int(input("Choisissez une option : "))

            if choix == 4:
                print("Au revoir !")
                break

            if choix == 1:
                mode = input("Chiffrer (c) ou Déchiffrer (d) ? ").lower()
                password = input("🔑 Entrez le mot de passe : ")
                rc4 = RC4(password)

                if mode == 'c':
                    test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                    if test == 't':
                        message = "Message secret RC4"
                        print(f"Message de test : {message}")
                    else:
                        message = input("📝 Entrez le message à chiffrer : ")

                    encrypted = rc4.encrypt(message)
                    print(f"Message chiffré (hex) : {encrypted.hex()}")
                    print(f"Message chiffré (len) : {len(encrypted)} bytes")

                else:
                    test = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                    if test == 't':
                        message = "Message secret RC4"
                        encrypted = rc4.encrypt(message)
                        ciphertext_hex = encrypted.hex()
                        print(f"Message chiffré de test : {ciphertext_hex}")
                    else:
                        ciphertext_hex = input("Entrez le message chiffré (hex) : ")

                    ciphertext = bytes.fromhex(ciphertext_hex)
                    decrypted = rc4.decrypt(ciphertext)
                    print(f"Message déchiffré : {decrypted.decode('utf-8')}")

            elif choix == 2:
                weak_iv_attack_demo()

            elif choix == 3:
                num_keys = int(input("Nombre de clés à tester (ex: 10000) : ") or "10000")
                counts = rc4_byte_bias_analysis(num_keys)
                graph = input("Afficher le graphique ? (o/n) : ").lower()
                if graph == 'o':
                    plot_rc4_bias(counts, num_keys)

        except Exception as e:
            print(f"Erreur : {e}")
