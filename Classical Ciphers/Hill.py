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


if __name__ == "__main__":
    print("===== TEST HILL =====")
    key_matrix = np.array([[3, 3], [2, 5]])
    message = "hello world"

    encrypted = hill_encrypt(message, key_matrix)
    decrypted = hill_decrypt(encrypted, key_matrix)

    print("Original :", message)
    print("Chiffré  :", encrypted)
    print("Déchiffré:", decrypted)
