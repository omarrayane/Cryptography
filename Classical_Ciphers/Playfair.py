def create_playfair_matrix(key: str):
    """Crée la matrice 5x5 pour Playfair."""
    key = key.upper().replace('J', 'I')
    
    # Supprimer les doublons
    alphabet = []
    for char in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if char not in alphabet and char.isalpha():
            alphabet.append(char)
    
    # Créer la matrice 5x5
    matrix = []
    for i in range(0, 25, 5):
        matrix.append(alphabet[i:i + 5])
    
    return matrix


def find_position(matrix, char):
    """Trouve la position d'un caractère dans la matrice."""
    char = char.upper()
    if char == 'J':
        char = 'I'
    
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return -1, -1


def prepare_text(text):
    """Prépare le texte pour Playfair (supprime non-lettres, remplace J par I, gère doublons)."""
    text = ''.join(c for c in text.upper() if c.isalpha())
    text = text.replace('J', 'I')
    
    # Diviser en paires, insérer X entre lettres identiques
    pairs = []
    i = 0
    while i < len(text):
        if i == len(text) - 1:
            # Dernier caractère seul, ajouter X
            pairs.append(text[i] + 'X')
            i += 1
        elif text[i] == text[i + 1]:
            # Deux mêmes lettres consécutives, insérer X
            pairs.append(text[i] + 'X')
            i += 1
        else:
            pairs.append(text[i] + text[i + 1])
            i += 2
    
    return pairs


def playfair_encrypt(text: str, key: str) -> str:
    """Chiffre un texte avec Playfair."""
    matrix = create_playfair_matrix(key)
    pairs = prepare_text(text)
    
    result = ""
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        
        if row1 == row2:
            # Même ligne : décaler à droite
            result += matrix[row1][(col1 + 1) % 5]
            result += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            # Même colonne : décaler vers le bas
            result += matrix[(row1 + 1) % 5][col1]
            result += matrix[(row2 + 1) % 5][col2]
        else:
            # Rectangle : échanger les colonnes
            result += matrix[row1][col2]
            result += matrix[row2][col1]
    
    return result


def playfair_decrypt(text: str, key: str) -> str:
    """Déchiffre un texte Playfair."""
    matrix = create_playfair_matrix(key)
    text = ''.join(c for c in text.upper() if c.isalpha())
    
    # Vérifier que la longueur est paire
    if len(text) % 2 != 0:
        text += 'X'
    
    pairs = [text[i:i + 2] for i in range(0, len(text), 2)]
    
    result = ""
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        
        if row1 == row2:
            # Même ligne : décaler à gauche
            result += matrix[row1][(col1 - 1) % 5]
            result += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            # Même colonne : décaler vers le haut
            result += matrix[(row1 - 1) % 5][col1]
            result += matrix[(row2 - 1) % 5][col2]
        else:
            # Rectangle : échanger les colonnes
            result += matrix[row1][col2]
            result += matrix[row2][col1]
    
    return result


def display_matrix(matrix):
    """Affiche la matrice Playfair."""
    print("\n📊 Matrice Playfair (5x5) :")
    print("-" * 25)
    for i in range(5):
        row = " | ".join(matrix[i])
        print(f"  {row}")
    print("-" * 25)


def menu():
    print("\n" + "=" * 50)
    print("      CHIFFREMENT DE PLAYFAIR")
    print("=" * 50)
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message")
    print("3. Afficher la matrice d'une clé")
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
                    key = "security"
                    print(f"\n📝 Message de test : {message}")
                    print(f"🔑 Clé de test : {key}")
                else:
                    message = input("\n📝 Entrez le message à chiffrer : ")
                    key = input("🔑 Entrez la clé : ")
                
                # Afficher la matrice
                matrix = create_playfair_matrix(key)
                display_matrix(matrix)
                
                encrypted = playfair_encrypt(message, key)
                print(f"\n🔒 Message chiffré : {encrypted}")
                
                # Vérification
                decrypted = playfair_decrypt(encrypted, key)
                print(f"🔓 Vérification déchiffrée : {decrypted}")
            
            elif choix == 2:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()
                
                if mode == 't':
                    key = "security"
                    encrypted = playfair_encrypt("hello world", key)
                    print(f"\n🔒 Message chiffré de test : {encrypted}")
                    print(f"🔑 Clé de test : {key}")
                else:
                    encrypted = input("\n🔒 Entrez le message chiffré : ")
                    key = input("🔑 Entrez la clé : ")
                
                # Afficher la matrice
                matrix = create_playfair_matrix(key)
                display_matrix(matrix)
                
                decrypted = playfair_decrypt(encrypted, key)
                print(f"\n🔓 Message déchiffré : {decrypted}")
            
            elif choix == 3:
                key = input("\n🔑 Entrez la clé pour afficher la matrice : ")
                matrix = create_playfair_matrix(key)
                display_matrix(matrix)
                
                print("\n📌 Règles Playfair :")
                print("   - I et J sont confondus")
                print("   - X est inséré entre lettres identiques")
                print("   - X est ajouté à la fin si longueur impaire")
            
        except ValueError as e:
            print(f"Erreur : {e}")
        except Exception as e:
            print(f"Erreur inattendue : {e}")
