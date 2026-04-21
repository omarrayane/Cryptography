from collections import Counter
from math import gcd
from functools import reduce


def find_repeated_sequences(ciphertext, min_length=3):
    # Trouve les séquences répétées et calcule les écarts entre leurs positions
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


def find_key_length(ciphertext):
    # Longueur probable de la clé = PGCD des écarts
    gaps = find_repeated_sequences(ciphertext)
    if not gaps:
        return None
    return reduce(gcd, gaps)


def test_multiple_key_lengths(ciphertext):
    # Retourne les longueurs de clé possibles triées par probabilité
    gaps = find_repeated_sequences(ciphertext)
    if gaps:
        gcd_values = sorted(set(reduce(gcd, gaps[i:]) for i in range(len(gaps))), reverse=True)[:5]
        print(f"Longueurs de clé possibles : {gcd_values}")
        return gcd_values
    return []


def split_text_by_key_length(text, key_length):
    # Divise le texte en groupes selon la longueur de la clé
    groups = ['' for _ in range(key_length)]
    for i, char in enumerate(text):
        groups[i % key_length] += char
    return groups


def find_caesar_shift(text_group):
    # Suppose que la lettre la plus fréquente correspond à 'E'
    letter_counts = Counter(text_group)
    most_common = letter_counts.most_common(1)[0][0]
    return (ord(most_common) - ord('E')) % 26


def find_vigenere_key(ciphertext, key_length):
    groups = split_text_by_key_length(ciphertext, key_length)
    shifts = [find_caesar_shift(g) for g in groups]
    key = ''.join(chr(ord('A') + s) for s in shifts)
    print(f"Décalages : {shifts}")
    return key


def vigenere_decrypt(ciphertext, key):
    result = []
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        shift = ord(key[i % key_length]) - ord('A')
        result.append(chr(((ord(char) - ord('A') - shift) % 26) + ord('A')))
    return ''.join(result)


if __name__ == "__main__":
    ciphertext = "CLCJSGEEXJGGOETFEUUUPEIRMOOBTGGRCOAKTLCHRCODGGOTDEFVCJJFHSEFFVKHEPFRGFSVRUGMAOFMGMEVURGTETBCJJFHSEGEEFJFHFRGOTGTMCOIGSEUMEEIIHGRGEEXJGGOETFEZJGGDOONERSEURUGMAVPTCMIVFDGTSATTGNEUEEEIIHGRGNEPUQWFLGTDGVXEPRTFSRPNFBNVTCQONCJSUFNVVNGDLGGSGDRGUEEPMOVNG"

    key_length = find_key_length(ciphertext)
    print(f"Longueur probable de la clé : {key_length}")

    possible_lengths = test_multiple_key_lengths(ciphertext)

    if key_length and key_length in possible_lengths:
        key = find_vigenere_key(ciphertext, 3)
        print(f"Clé trouvée : {key}")
        print(f"\nTexte déchiffré :\n{vigenere_decrypt(ciphertext, key)}")
    else:
        print("Impossible de déterminer la longueur de clé. Vérifiez les valeurs détectées.")
