from typing import List, Tuple


def create_playfair_matrix(key: str) -> List[List[str]]:
    key = key.upper().replace('J', 'I')

    alphabet = []
    for char in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if char not in alphabet and char.isalpha():
            alphabet.append(char)

    matrix = []
    for i in range(0, 25, 5):
        matrix.append(alphabet[i:i + 5])

    return matrix


def find_position(matrix: List[List[str]], char: str) -> Tuple[int, int]:
    char = char.upper()
    if char == 'J':
        char = 'I'

    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j

    return -1, -1


def playfair_encrypt(text: str, key: str) -> str:
    matrix = create_playfair_matrix(key)
    text = ''.join(c for c in text.upper() if c.isalpha()).replace('J', 'I')

    pairs = []
    i = 0
    while i < len(text):
        if i == len(text) - 1 or text[i] == text[i + 1]:
            pairs.append(text[i] + 'X')
            i += 1
        else:
            pairs.append(text[i:i + 2])
            i += 2

    result = ""
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])

        if row1 == row2:
            result += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            result += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            result += matrix[row1][col2] + matrix[row2][col1]

    return result


def playfair_decrypt(text: str, key: str) -> str:
    matrix = create_playfair_matrix(key)
    text = ''.join(c for c in text.upper() if c.isalpha())

    pairs = [text[i:i + 2] for i in range(0, len(text), 2)]

    result = ""
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])

        if row1 == row2:
            result += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            result += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            result += matrix[row1][col2] + matrix[row2][col1]

    return result


def afficher_menu():
    print("-" * 50)
    print("      CHIFFREMENT DE PLAYFAIR")
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

            cle = input("Entrez la clé : ").strip()
            if not cle:
                raise ValueError("La clé ne peut pas être vide.")
            print("-" * 50)

            if choix == 1:
                texte = input("Entrez le texte à chiffrer : ")
                resultat = playfair_encrypt(texte, cle)
                print("Texte chiffré :")
                print(resultat)

            elif choix == 2:
                texte = input("Entrez le texte à déchiffrer : ")
                resultat = playfair_decrypt(texte, cle)
                print("Texte déchiffré :")
                print(resultat)

            print("-" * 50)

        except ValueError as e:
            print("Erreur :", e)
            print("-" * 50)
