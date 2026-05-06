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


def find_key_length_kasiski(ciphertext: str):
    """
    Estime la longueur de la clé avec le test de Kasiski (PGCD des écarts).
    """
    gaps = find_repeated_sequences(ciphertext)
    if not gaps:
        return None

    # Calculer le PGCD de tous les écarts
    key_length = gaps[0]
    for gap in gaps[1:]:
        key_length = gcd(key_length, gap)

    return key_length


def possible_key_lengths(ciphertext: str, max_len: int = 20):
    """
    Retourne les longueurs de clé possibles triées par probabilité.
    """
    gaps = find_repeated_sequences(ciphertext)
    if not gaps:
        return []

    all_gcds = []
    for i in range(len(gaps)):
        current_gcd = gaps[i]
        for j in range(i + 1, len(gaps)):
            current_gcd = gcd(current_gcd, gaps[j])
        if current_gcd > 1 and current_gcd <= max_len:
            all_gcds.append(current_gcd)

    # Compter les fréquences
    freq = Counter(all_gcds)
    return sorted(freq.keys(), key=lambda x: freq[x], reverse=True)[:5]


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
    Calcule l'indice de coïncidence d'un texte.
    """
    text = ''.join(c for c in text if c.isalpha())
    n = len(text)
    if n <= 1:
        return 0

    counts = Counter(text)
    ic = sum(count * (count - 1) for count in counts.values()) / (n * (n - 1))
    return ic


def find_shift_by_frequency(text: str):
    """
    Trouve le décalage pour un texte en comparant avec la distribution française.
    Fréquences françaises (ordre décroissant) : E, A, S, I, T, N, R, U, L, O, D...
    """
    text = ''.join(c for c in text if c.isalpha())
    if not text:
        return 0

    # Fréquences en français (ordre)
    french_freq_order = "EASINT RULODM".replace(" ", "")

    # Compter les lettres
    counts = Counter(text.upper())
    most_common = counts.most_common(1)[0][0]

    # La lettre la plus fréquente est probablement 'E'
    shift = (ord(most_common) - ord('E')) % 26
    return shift


def find_shift_by_ic(groups: list):
    """
    Utilise l'IC pour chaque décalage possible afin de retrouver la clé.
    """
    shifts = []

    for group in groups:
        best_shift = 0
        best_ic_diff = float('inf')
        french_ic = 0.074

        for shift in range(26):
            # Décaler le groupe
            decrypted = ''
            for char in group:
                decrypted += chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))

            ic = calculate_ic(decrypted)
            diff = abs(ic - french_ic)

            if diff < best_ic_diff:
                best_ic_diff = diff
                best_shift = shift

        shifts.append(best_shift)

    return shifts


def find_vigenere_key(ciphertext: str, key_length: int):
    """
    Trouve la clé Vigenère à partir de la longueur estimée.
    """
    groups = split_by_key_length(ciphertext, key_length)
    shifts = find_shift_by_ic(groups)
    key = ''.join(chr(shift + ord('A')) for shift in shifts)
    return key, shifts


def vigenere_crack(ciphertext: str):
    """
    Attaque complète : trouve longueur de clé, puis clé, puis déchiffre.
    """
    print("\n[Analyse Kasiski] Recherche de séquences répétées...")

    possible_lengths = possible_key_lengths(ciphertext)
    print(f"Longueurs de clé possibles : {possible_lengths}")

    if possible_lengths:
        key_length = possible_lengths[0]
        print(f"Longueur de clé choisie : {key_length}")
    else:
        # Fallback : tester différentes longueurs
        print("Impossible de déterminer par Kasiski, test des longueurs 1-10...")
        best_length = 1
        best_ic = 0

        for length in range(1, 11):
            groups = split_by_key_length(ciphertext, length)
            avg_ic = sum(calculate_ic(g) for g in groups) / len(groups)
            if avg_ic > best_ic:
                best_ic = avg_ic
                best_length = length

        key_length = best_length
        print(f"Longueur de clé détectée par IC : {key_length}")

    key, shifts = find_vigenere_key(ciphertext, key_length)
    print(f"Clé trouvée : {key}")
    print(f"Décalages : {shifts}")

    plaintext = vigenere_decrypt(ciphertext, key)
    return plaintext, key, key_length


def demonstrate_otp_relationship():
    """Démontre le lien entre Vigenère et OTP quand |K| = |M|."""
    print("\n" + "=" * 60)
    print("  LIEN VIGENÈRE - OTP")
    print("=" * 60)

    message = "BONJOURLEMONDE"
    key = "SECRETSECRETSE"

    print(f"Message : {message} (longueur = {len(message)})")
    print(f"Clé    : {key} (longueur = {len(key)})")
    print("\nQuand |K| = |M| :")
    print("- Vigenère devient équivalent à un chiffrement par décalage par caractère")
    print("- C'est conceptuellement proche de l'OTP (One-Time Pad)")
    print("- Différence : OTP utilise XOR, Vigenère utilise addition mod 26")
    print("- OTP nécessite une clé vraiment aléatoire, Vigenère utilise une clé en texte clair")

    encrypted = vigenere_encrypt(message, key)
    decrypted = vigenere_decrypt(encrypted, key)

    print(f"\nExemple :")
    print(f"  Chiffré  : {encrypted}")
    print(f"  Déchiffré: {decrypted}")


def menu():
    print("\n" + "=" * 50)
    print("      CHIFFREMENT DE VIGENÈRE")
    print("=" * 50)
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message")
    print("3. Attaquer un message chiffré (Kasiski + IC)")
    print("4. Démonstration : lien avec OTP")
    print("5. Quitter")
    print("-" * 50)


if __name__ == "__main__":
    # Texte de test pour l'attaque
    TEST_CIPHERTEXT = "CLCJSGEEXJGGOETFEUUUPEIRMOOBTGGRCOAKTLCHRCODGGOTDEFVCJJFHSEFFVKHEPFRGFSVRUGMAOFMGMEVURGTETBCJJFHSEGEEFJFHFRGOTGTMCOIGSEUMEEIIHGRGEEXJGGOETFEZJGGDOONERSEURUGMAVPTCMIVFDGTSATTGNEUEEEIIHGRGNEPUQWFLGTDGVXEPRTFSRPNFBNVTCQONCJSUFNVVNGDLGGSGDRGUEEPMOVNG"

    while True:
        menu()

        try:
            choix = int(input("Choisissez une option : "))

            if choix == 5:
                print("Au revoir !")
                break

            if choix == 1:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()

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
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()

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
                    print(f"{ciphertext[:100]}...")
                else:
                    ciphertext = input("Entrez le texte chiffré à attaquer : ")

                plaintext, key, key_length = vigenere_crack(ciphertext)

                print("\n" + "=" * 50)
                print("RÉSULTAT DE L'ATTAQUE")
                print("=" * 50)
                print(f"Longueur de clé trouvée : {key_length}")
                print(f"Clé trouvée : {key}")
                print(f"\nTexte déchiffré :")
                print(plaintext[:500] + ("..." if len(plaintext) > 500 else ""))

            elif choix == 4:
                demonstrate_otp_relationship()

        except ValueError as e:
            print(f"Erreur : {e}")
        except Exception as e:
            print(f"Erreur inattendue : {e}")
