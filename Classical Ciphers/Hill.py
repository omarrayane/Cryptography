import numpy as np


def inverse_modulaire(a: int, m: int):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def matrix_mod_inverse(matrix: np.ndarray, modulus: int) -> np.ndarray:

    det = int(round(np.linalg.det(matrix))) % modulus
    det_inv = inverse_modulaire(det, modulus)

    if det_inv is None:
        raise ValueError("La matrice n'est pas inversible modulo 26")

    size = matrix.shape[0]
    adjoint = np.zeros_like(matrix)

    for i in range(size):
        for j in range(size):
            minor = np.delete(np.delete(matrix, i, axis=0), j, axis=1)
            cofactor = round(np.linalg.det(minor)) * (-1) ** (i + j)
            adjoint[j, i] = cofactor

    inverse = (det_inv * adjoint) % modulus
    return inverse


def hill_encrypt(text: str, key_matrix: np.ndarray) -> str:

    n = key_matrix.shape[0]

    text = ''.join(c for c in text if c.isalpha()).lower()

    if len(text) % n != 0:
        text += 'x' * (n - len(text) % n)

    vectors = []
    for i in range(0, len(text), n):
        vector = [ord(text[i + j]) - ord('a') for j in range(n)]
        vectors.append(vector)

    result = ""
    for vector in vectors:
        encrypted_vector = np.dot(key_matrix, vector) % 26
        for num in encrypted_vector:
            result += chr(int(num) + ord('a'))

    return result


def hill_decrypt(text: str, key_matrix: np.ndarray) -> str:

    inverse_key = matrix_mod_inverse(key_matrix, 26)
    return hill_encrypt(text, inverse_key)


def parse_matrix(size: int) -> np.ndarray:
    print(f"Entrez la matrice clé ({size}x{size}), ligne par ligne (valeurs séparées par des espaces) :")
    rows = []
    for i in range(size):
        while True:
            try:
                row = list(map(int, input(f"  Ligne {i + 1} : ").split()))
                if len(row) != size:
                    print(f"  Erreur : entrez exactement {size} valeurs.")
                    continue
                rows.append(row)
                break
            except ValueError:
                print("  Erreur : valeurs entières requises.")
    return np.array(rows)


def afficher_menu():
    print("-" * 50)
    print("      CHIFFREMENT DE HILL")
    print("-" * 50)
    print("1. Chiffrer un texte")
    print("2. Déchiffrer un texte")
    print("3. Quitter")
    print("-" * 50)


if __name__ == "__main__":

    while True:
        afficher_menu()

        try:
            choix = int(input("Choisissez une option : "))
            print("-" * 50)

            if choix == 3:
                print("Au revoir !")
                print("-" * 50)
                break

            if choix not in [1, 2]:
                print("Option invalide.")
                continue

            size = int(input("Taille de la matrice clé (ex: 2 pour 2x2) : "))
            if size < 2:
                raise ValueError("La taille doit être au moins 2.")
            print("-" * 50)

            key_matrix = parse_matrix(size)
            print("-" * 50)

            if choix == 1:
                texte = input("Entrez le texte à chiffrer : ")
                resultat = hill_encrypt(texte, key_matrix)
                print("Texte chiffré :")
                print(resultat)

            elif choix == 2:
                texte = input("Entrez le texte à déchiffrer : ")
                resultat = hill_decrypt(texte, key_matrix)
                print("Texte déchiffré :")
                print(resultat)

            print("-" * 50)

        except ValueError as e:
            print("Erreur :", e)
            print("-" * 50)
