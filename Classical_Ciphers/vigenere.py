from collections import Counter
from math import gcd
from functools import reduce


def vigenere_encrypt(text: str, key: str) -> str:
    result = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(k) - ord('A') for k in key]

    for i, char in enumerate(text):
        if char.isalpha():
            key_index = i % key_length
            key_shift = key_as_int[key_index]

            if char.isupper():
                result += chr((ord(char) - ord('A') + key_shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') + key_shift) % 26 + ord('a'))
        else:
            result += char

    return result


def vigenere_decrypt(text: str, key: str) -> str:
    result = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(k) - ord('A') for k in key]

    for i, char in enumerate(text):
        if char.isalpha():
            key_index = i % key_length
            key_shift = key_as_int[key_index]

            if char.isupper():
                result += chr((ord(char) - ord('A') - key_shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') - key_shift) % 26 + ord('a'))
        else:
            result += char

    return result


def find_repeated_sequences(ciphertext: str, min_length: int = 3):
    """
    Test de Kasiski : trouve les séquences répétées et calcule les écarts.
    """
    ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
    sequences = {}

    for i in range(len(ciphertext) - min_length + 1):
        seq = ciphertext[i:i + min_length]
        if seq in sequences:
            sequences[seq].append(i)
        else:
            sequences[seq] = [i]

    gaps = []
    for seq, positions in sequences.items():
        if len(positions) > 1:
            for j in range(1, len(positions)):
                gaps.append(positions[j] - positions[j - 1])

    return gaps


def kasiski_key_length(ciphertext: str):
    """
    Calcule la longueur probable de la clé avec le test de Kasiski.
    """
    gaps = find_repeated_sequences(ciphertext)
    if not gaps:
        return None

    key_length = gaps[0]
    for gap in gaps[1:]:
        key_length = gcd(key_length, gap)

    return key_length if key_length > 1 else None


def split_by_key_length(ciphertext: str, key_length: int):
    """
    Découpe le texte en sous-séquences selon la longueur de la clé.
    """
    ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
    groups = [''] * key_length

    for i, char in enumerate(ciphertext):
        groups[i % key_length] += char

    return groups


def calculate_ic(text: str) -> float:
    """
    Calcule l'indice de coïncidence.
    """
    text = ''.join(c for c in text if c.isalpha())
    n = len(text)
    if n <= 1:
        return 0

    counts = Counter(text)
    ic = sum(count * (count - 1) for count in counts.values()) / (n * (n - 1))
    return ic


def find_shift_by_frequency(group: str):
    """
    Trouve le décalage pour un groupe via corrélation avec les fréquences françaises.
    On teste les 26 décalages possibles et on retient celui qui maximise
    le produit scalaire entre les fréquences observées et les fréquences de référence.
    """
    group = group.upper()
    if not group:
        return 0

    # Fréquences relatives des lettres en français
    french_freq = {
        'A': 0.0842, 'B': 0.0106, 'C': 0.0303, 'D': 0.0418, 'E': 0.1726,
        'F': 0.0112, 'G': 0.0127, 'H': 0.0092, 'I': 0.0734, 'J': 0.0031,
        'K': 0.0005, 'L': 0.0601, 'M': 0.0296, 'N': 0.0712, 'O': 0.0527,
        'P': 0.0301, 'Q': 0.0099, 'R': 0.0655, 'S': 0.0795, 'T': 0.0724,
        'U': 0.0637, 'V': 0.0164, 'W': 0.0004, 'X': 0.0045, 'Y': 0.0014,
        'Z': 0.0003
    }

    n = len(group)
    counts = Counter(group)

    best_shift = 0
    best_score = -1

    for shift in range(26):
        # Score = corrélation entre fréquences observées (après décalage inverse)
        # et fréquences de référence françaises
        score = sum(
            (counts.get(chr((ord(letter) - ord('A') + shift) % 26 + ord('A')), 0) / n)
            * french_freq[letter]
            for letter in french_freq
        )
        if score > best_score:
            best_score = score
            best_shift = shift

    return best_shift


def find_vigenere_key(ciphertext: str, key_length: int):
    """
    Trouve la clé Vigenère à partir de la longueur estimée.
    """
    groups = split_by_key_length(ciphertext, key_length)
    shifts = []

    for group in groups:
        shift = find_shift_by_frequency(group)
        shifts.append(shift)

    key = ''.join(chr(shift + ord('A')) for shift in shifts)
    return key, shifts


def vigenere_crack(ciphertext: str):
    """
    Attaque complète : trouve longueur de clé (Kasiski), puis clé, puis déchiffre.
    """
    print("\n[Test de Kasiski] Recherche de séquences répétées...")

    key_length = kasiski_key_length(ciphertext)

    if key_length:
        print(f"Longueur de clé trouvée par Kasiski : {key_length}")
    else:
        # Fallback: tester différentes longueurs par IC
        print("Kasiski n'a pas trouvé de longueur, test par IC...")

        ciphertext_clean = ''.join(c for c in ciphertext.upper() if c.isalpha())
        # Chaque groupe doit avoir au moins 8 caractères pour être statistiquement fiable
        max_length = min(20, len(ciphertext_clean) // 8)
        if max_length < 1:
            max_length = 1

        best_length = 1
        best_avg_ic = 0

        for length in range(1, max_length + 1):
            groups = split_by_key_length(ciphertext, length)
            if all(len(g) > 1 for g in groups):
                avg_ic = sum(calculate_ic(g) for g in groups) / len(groups)
                # Les groupes monoalphabétiques bien séparés ont un IC élevé (~0.074)
                if avg_ic > best_avg_ic:
                    best_avg_ic = avg_ic
                    best_length = length

        key_length = best_length
        print(f"Longueur de clé détectée par IC : {key_length}")

    key, shifts = find_vigenere_key(ciphertext, key_length)
    print(f"Clé trouvée : {key}")
    print(f"Décalages : {shifts}")

    plaintext = vigenere_decrypt(ciphertext, key)
    return plaintext, key, key_length


def menu():
    print("\n" + "=" * 50)
    print("      CHIFFREMENT DE VIGENÈRE")
    print("=" * 50)
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message")
    print("3. Attaquer un message chiffré (Kasiski + IC)")
    print("4. Quitter")
    print("-" * 50)


if __name__ == "__main__":
    TEST_CIPHERTEXT = "CLCJSGEEXJGGOETFEUUUPEIRMOOBTGGRCOAKTLCHRCODGGOTDEFVCJJFHSEFFVKHEPFRGFSVRUGMAOFMGMEVURGTETBCJJFHSEGEEFJFHFRGOTGTMCOIGSEUMEEIIHGRGEEXJGGOETFEZJGGDOONERSEURUGMAVPTCMIVFDGTSATTGNEUEEEIIHGRGNEPUQWFLGTDGVXEPRTFSRPNFBNVTCQONCJSUFNVVNGDLGGSGDRGUEEPMOVNG"

    while True:
        menu()

        try:
            choix = int(input("Choisissez une option : "))

            if choix == 4:
                print("Au revoir !")
                break

            if choix == 1:
                mode = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    message = "Bonjour le monde"
                    key = "SECRET"
                    print(f"Message de test : {message}")
                    print(f"Clé de test : {key}")
                else:
                    message = input("Entrez le message à chiffrer : ")
                    key = input("Entrez la clé (mot alphabétique) : ")

                encrypted = vigenere_encrypt(message, key)
                print(f"Message chiffré : {encrypted}")

            elif choix == 2:
                mode = input("Voulez-vous (t)ester ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    encrypted = vigenere_encrypt("Bonjour le monde", "SECRET")
                    key = "SECRET"
                    print(f"Message chiffré de test : {encrypted}")
                    print(f"Clé de test : {key}")
                else:
                    encrypted = input("Entrez le message à déchiffrer : ")
                    key = input("Entrez la clé : ")

                decrypted = vigenere_decrypt(encrypted, key)
                print(f"Message déchiffré : {decrypted}")

            elif choix == 3:
                mode = input("Voulez-vous (t)ester avec l'exemple du cours ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    ciphertext = TEST_CIPHERTEXT
                    print(f"Texte chiffré de test (longueur : {len(ciphertext)} caractères)")
                else:
                    ciphertext = input("Entrez le texte chiffré à attaquer : ")

                plaintext, key, key_length = vigenere_crack(ciphertext)

                print("\n" + "=" * 50)
                print("RÉSULTAT DE L'ATTAQUE")
                print("=" * 50)
                print(f"Longueur de clé trouvée : {key_length}")
                print(f"Clé trouvée : {key}")
                print(f"\nTexte déchiffré :")
                print(plaintext)

        except Exception as e:
            print(f"Erreur : {e}")
