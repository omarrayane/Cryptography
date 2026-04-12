import numpy as np
from typing import List, Tuple

# ======== OUTIL UTILISÉ PAR HILL (DÉJÀ VU DANS AFFINE) ========
def inverse_modulaire(a: int, m: int):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


# ======== CHIFFRE DE HILL ========
def matrix_mod_inverse(matrix: np.ndarray, modulus: int) -> np.ndarray:
    """Calcule l'inverse modulaire d'une matrice."""
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
    """Chiffrement de Hill."""
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
    """Déchiffrement de Hill."""
    inverse_key = matrix_mod_inverse(key_matrix, 26)
    return hill_encrypt(text, inverse_key)


# ======== CHIFFRE DE PLAYFAIR ========
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


# ======== TEST ========
if __name__ == "__main__":
    print("===== TEST HILL =====")
    key_matrix = np.array([[3, 3], [2, 5]])
    message = "hello world"

    encrypted = hill_encrypt(message, key_matrix)
    decrypted = hill_decrypt(encrypted, key_matrix)

    print("Original :", message)
    print("Chiffré  :", encrypted)
    print("Déchiffré:", decrypted)

    print("\n===== TEST PLAYFAIR =====")
    key = "security"

    encrypted_pf = playfair_encrypt(message, key)
    decrypted_pf = playfair_decrypt(encrypted_pf, key)

    print("Original :", message)
    print("Chiffré  :", encrypted_pf)
    print("Déchiffré:", decrypted_pf)
