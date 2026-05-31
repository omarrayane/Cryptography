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

def text_to_vector(text, n):
    """Convertit un texte en vecteur de nombres (a=0,..., z=25)."""
    text = ''.join(c for c in text if c.isalpha()).lower()
    if len(text) % n != 0:
        text += 'x' * (n - len(text) % n)

    vectors = []
    for i in range(0, len(text), n):
        vector = [ord(text[i + j]) - ord('a') for j in range(n)]
        vectors.append(vector)
    return vectors, text

def hill_encrypt(text: str, key_matrix: np.ndarray) -> str:

    n = key_matrix.shape[0]
    vectors, _ = text_to_vector(text, n)

    result = ""
    for vector in vectors:
        encrypted_vector = np.dot(key_matrix, vector) % 26
        for num in encrypted_vector:
            result += chr(int(num) + ord('a'))

    return result

def hill_decrypt(text: str, key_matrix: np.ndarray) -> str:

    inverse_key = matrix_mod_inverse(key_matrix, 26)
    return hill_encrypt(text, inverse_key)

def known_plaintext_attack(plaintext, ciphertext, n):
    """
    Attaque à clair connu sur Hill.
    Récupère la matrice clé à partir de paires (plaintext, ciphertext).
    """
    vectors_p, _ = text_to_vector(plaintext, n)
    vectors_c, _ = text_to_vector(ciphertext, n)

    # Il faut au moins n paires pour résoudre
    if len(vectors_p) < n:
        raise ValueError(f"Il faut au moins {n} paires clair-chiffré, vous en avez {len(vectors_p)}")

    # Construction des matrices P et C
    P = np.array(vectors_p[:n]).T  # Transposée pour avoir les bonnes dimensions
    C = np.array(vectors_c[:n]).T

    # Récupération de la clé : K = C * P^(-1)
    try:
        P_inv = matrix_mod_inverse(P, 26)
        K = np.dot(C, P_inv) % 26
        return K
    except ValueError:
        raise ValueError("La matrice P n'est pas inversible modulo 26")

def hill_encrypt_with_padding(text, key_matrix):
    """Chiffre avec gestion automatique du padding."""
    return hill_encrypt(text, key_matrix)

def hill_decrypt_with_padding(text, key_matrix):
    """Déchiffre et retire le padding."""
    decrypted = hill_decrypt(text, key_matrix)
    # Retirer les 'x' de padding (simple, pourrait être amélioré)
    return decrypted

def test_hill():
    print("===== TEST HILL =====")

    print("\n--- Test 2x2 ---")
    key_matrix_2x2 = np.array([[3, 3], [2, 5]])
    message = "hello"

    encrypted = hill_encrypt(message, key_matrix_2x2)
    decrypted = hill_decrypt(encrypted, key_matrix_2x2)

    print(f"Original : {message}")
    print(f"Chiffré  : {encrypted}")
    print(f"Déchiffré: {decrypted}")

    print("\n--- Test Attaque à clair connu 2x2 ---")
    plaintext = "help"
    known_ciphertext = hill_encrypt(plaintext, key_matrix_2x2)

    recovered_key = known_plaintext_attack(plaintext, known_ciphertext, 2)
    print(f"Matrice clé originale :\n{key_matrix_2x2}")
    print(f"Matrice clé retrouvée :\n{recovered_key}")

    test_msg = "attack"
    encrypted_orig = hill_encrypt(test_msg, key_matrix_2x2)
    encrypted_recovered = hill_encrypt(test_msg, recovered_key)
    print(f"Chiffré avec clé originale : {encrypted_orig}")
    print(f"Chiffré avec clé retrouvée : {encrypted_recovered}")
    print(f"✅ Attaque réussie : {encrypted_orig == encrypted_recovered}")

    print("\n--- Test 3x3 ---")
    key_matrix_3x3 = np.array([[2, 4, 5], [1, 3, 6], [7, 8, 9]])
    message3 = "secret"

    encrypted3 = hill_encrypt(message3, key_matrix_3x3)
    decrypted3 = hill_decrypt(encrypted3, key_matrix_3x3)

    print(f"Original : {message3}")
    print(f"Chiffré  : {encrypted3}")
    print(f"Déchiffré: {decrypted3}")

def menu():
    print("\n" + "=" * 50)
    print("      CHIFFREMENT DE HILL")
    print("=" * 50)
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message")
    print("3. Attaque à clair connu")
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
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()

                if mode == 't':
                    message = "hello world"
                    print(f"Message de test : {message}")
                    key_matrix = np.array([[3, 3], [2, 5]])
                    print(f"Matrice clé de test :\n{key_matrix}")
                else:
                    message = input("Entrez le message à chiffrer : ")
                    n = int(input("Taille de la matrice (2 ou 3) : "))
                    print(f"Entrez la matrice {n}x{n} ligne par ligne (nombres séparés par espaces) :")
                    rows = []
                    for i in range(n):
                        row = list(map(int, input(f"Ligne {i+1} : ").split()))
                        rows.append(row)
                    key_matrix = np.array(rows)

                encrypted = hill_encrypt(message, key_matrix)
                print(f"Message chiffré : {encrypted}")

            elif choix == 2:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()

                if mode == 't':
                    key_matrix = np.array([[3, 3], [2, 5]])
                    encrypted = hill_encrypt("hello world", key_matrix)
                    print(f"Texte chiffré de test : {encrypted}")
                else:
                    encrypted = input("Entrez le message à déchiffrer : ")
                    n = int(input("Taille de la matrice (2 ou 3) : "))
                    print(f"Entrez la matrice {n}x{n} ligne par ligne :")
                    rows = []
                    for i in range(n):
                        row = list(map(int, input(f"Ligne {i+1} : ").split()))
                        rows.append(row)
                    key_matrix = np.array(rows)

                decrypted = hill_decrypt(encrypted, key_matrix)
                print(f"Message déchiffré : {decrypted}")

            elif choix == 3:
                print("\n--- Attaque à clair connu ---")
                print("Il faut au moins n paires (clair, chiffré) pour une matrice n×n")

                n = int(input("Taille de la matrice (2 ou 3) : "))
                print("\nEntrez les paires clair-chiffré :")

                plaintexts = []
                ciphertexts = []

                for i in range(n):
                    print(f"\nPaire {i+1}:")
                    p = input(f"  Texte clair (au moins {n} lettres) : ").strip()
                    c = input(f"  Texte chiffré correspondant : ").strip()
                    plaintexts.append(p)
                    ciphertexts.append(c)

                # Concaténer pour avoir assez de lettres
                full_plaintext = ''.join(plaintexts)
                full_ciphertext = ''.join(ciphertexts)

                try:
                    recovered_key = known_plaintext_attack(full_plaintext, full_ciphertext, n)
                    print(f"\n✅ Matrice clé retrouvée :\n{recovered_key}")

                    test_msg = input("\nMessage de test pour vérifier : ")
                    encrypted = hill_encrypt(test_msg, recovered_key)
                    print(f"Message chiffré avec clé retrouvée : {encrypted}")
                except ValueError as e:
                    print(f"❌ Erreur : {e}")

        except ValueError as e:
            print(f"Erreur : {e}")
