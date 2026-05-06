import os

def otp_encrypt(message: str) -> tuple[bytes, bytes]:

    message_bytes = message.encode("utf-8")
    key = os.urandom(len(message_bytes))
    ciphertext = bytes(m ^ k for m, k in zip(message_bytes, key))
    return ciphertext, key

def otp_decrypt(ciphertext: bytes, key: bytes) -> str:

    message_bytes = bytes(c ^ k for c, k in zip(ciphertext, key))
    return message_bytes.decode("utf-8")


def otp_encrypt_with_key(message: str, key: bytes) -> bytes:
    """Chiffre un message avec une clé fournie (pour démonstration de vulnérabilité)."""
    message_bytes = message.encode("utf-8")
    if len(key) < len(message_bytes):
        raise ValueError("La clé est trop courte")
    return bytes(m ^ k for m, k in zip(message_bytes, key[:len(message_bytes)]))


def two_time_pad_attack(ciphertext1: bytes, ciphertext2: bytes):
    """
    Montre la vulnérabilité de réutilisation de clé OTP.
    Calcule C1 XOR C2 = M1 XOR M2.
    Retourne le XOR des deux messages.
    """
    min_len = min(len(ciphertext1), len(ciphertext2))
    xor_result = bytes(c1 ^ c2 for c1, c2 in zip(ciphertext1[:min_len], ciphertext2[:min_len]))
    return xor_result


def crib_dragging(xor_result: bytes, crib: str, position: int = 0):
    """
    Attaque crib dragging : tente de deviner une partie des messages.
    crib : mot probable dans l'un des messages (ex: "the ", "bonjour")
    position : position où essayer le crib
    """
    crib_bytes = crib.encode('utf-8')
    result = bytearray(len(crib_bytes))

    for i, cb in enumerate(crib_bytes):
        if position + i < len(xor_result):
            result[i] = xor_result[position + i] ^ cb

    return result.decode('utf-8', errors='replace')


def demonstrate_otp_vulnerability():
    """Démonstration complète de la vulnérabilité OTP avec réutilisation de clé."""
    print("\n" + "=" * 60)
    print("  DÉMONSTRATION VULNÉRABILITÉ OTP")
    print("  (Réutilisation de la même clé)")
    print("=" * 60)

    # Générer une clé unique
    key = os.urandom(50)

    message1 = "Bonjour tout le monde"
    message2 = "Message tres secret"

    print(f"\nMessage 1 : {message1}")
    print(f"Message 2 : {message2}")

    # Chiffrer avec la MÊME clé (vulnérabilité)
    cipher1 = otp_encrypt_with_key(message1, key)
    cipher2 = otp_encrypt_with_key(message2, key)

    print(f"\nCiphertext 1 : {cipher1.hex()[:32]}...")
    print(f"Ciphertext 2 : {cipher2.hex()[:32]}...")

    # Attaque : C1 XOR C2 = M1 XOR M2
    xor_result = two_time_pad_attack(cipher1, cipher2)
    print(f"\nC1 XOR C2 = {xor_result.hex()[:32]}...")

    # Crib dragging
    print("\n[Attaque crib dragging]")
    print("On suppose que 'bonjour' ou 'secret' apparaît dans un message\n")

    cribs = ["bonjour", "secret", "message", "monde", "tout"]

    for crib in cribs:
        print(f"Essai avec le crib '{crib}':")
        for pos in range(0, min(len(xor_result) - len(crib.encode()), 20)):
            result = crib_dragging(xor_result, crib, pos)
            if all(32 <= ord(c) < 127 or c == '�' for c in result):
                if any(c.isalpha() for c in result):
                    print(f"  Position {pos:2d} : {result}")
        print()


def test_otp():
    print("\n===== TEST OTP =====")

    message = "Hello World"
    print("Message clair :", message)

    ciphertext, key = otp_encrypt(message)
    print("Message chiffré :", ciphertext)
    print("Clé secrète :", key)

    decrypted = otp_decrypt(ciphertext, key)
    print("Message déchiffré :", decrypted)

    assert decrypted == message
    assert len(ciphertext) == len(message.encode())

    print("\n✔ OTP fonctionne correctement")


def menu():
    print("\n" + "=" * 50)
    print("      ONE-TIME PAD (VERNAM)")
    print("=" * 50)
    print("1. Chiffrer / Déchiffrer un message")
    print("2. Démontrer la vulnérabilité de réutilisation de clé")
    print("3. Quitter")
    print("-" * 50)


if __name__ == "__main__":
    while True:
        menu()

        try:
            choix = int(input("Choisissez une option : "))

            if choix == 3:
                print("Au revoir !")
                break

            if choix == 1:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()

                if mode == 't':
                    message = "Hello World"
                    print(f"Message de test : {message}")
                else:
                    message = input("Entrez le message : ")

                ciphertext, key = otp_encrypt(message)
                print(f"\nMessage chiffré (hex) : {ciphertext.hex()}")
                print(f"Clé (hex) : {key.hex()}")

                decrypted = otp_decrypt(ciphertext, key)
                print(f"Message déchiffré : {decrypted}")

            elif choix == 2:
                demonstrate_otp_vulnerability()

        except ValueError as e:
            print(f"Erreur : {e}")
