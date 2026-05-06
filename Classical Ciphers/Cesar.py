def cesar_encrypt(text: str, shift: int) -> str:

    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result


def cesar_decrypt(text: str, shift: int) -> str:

    return cesar_encrypt(text, -shift)


def brute_force_cesar(ciphertext: str, dictionary_words=None):
    """
    Attaque par force brute : teste les 26 clés possibles.
    Si dictionary_words est fourni, identifie automatiquement le texte français valide.
    """
    results = []
    best_match = None
    best_score = 0

    for shift in range(26):
        decrypted = cesar_decrypt(ciphertext, shift)
        results.append((shift, decrypted))

        # Détection automatique avec dictionnaire
        if dictionary_words:
            score = 0
            decrypted_lower = decrypted.lower()
            for word in dictionary_words:
                if word.lower() in decrypted_lower:
                    score += 1
            if score > best_score:
                best_score = score
                best_match = (shift, decrypted)

    return results, best_match


def calculate_ic(text):
    """Calcule l'indice de coïncidence d'un texte."""
    text = ''.join(c for c in text.lower() if c.isalpha())
    n = len(text)
    if n <= 1:
        return 0

    from collections import Counter
    counts = Counter(text)
    ic = sum(count * (count - 1) for count in counts.values()) / (n * (n - 1))
    return ic


def break_cesar_with_ic(ciphertext):
    """
    Déduit le décalage k en utilisant l'indice de coïncidence.
    L'IC du français est ~0.074.
    """
    best_shift = 0
    best_ic_diff = float('inf')
    french_ic = 0.074

    for shift in range(26):
        decrypted = cesar_decrypt(ciphertext, shift)
        ic = calculate_ic(decrypted)
        diff = abs(ic - french_ic)
        if diff < best_ic_diff:
            best_ic_diff = diff
            best_shift = shift

    return best_shift, cesar_decrypt(ciphertext, best_shift)


def afficher_menu():
    print("-" * 50)
    print("      CHIFFREMENT DE CESAR")
    print("-" * 50)
    print("1. Chiffrer un texte")
    print("2. Déchiffrer un texte")
    print("3. Attaque par force brute")
    print("4. Attaque par indice de coïncidence")
    print("5. Quitter")
    print("-" * 50)


if __name__ == "__main__":

    # Dictionnaire français simple pour l'attaque
    french_words = ["le", "la", "les", "un", "une", "de", "des", "et", "est", "dans",
                    "pour", "par", "avec", "sans", "sur", "sous", "je", "tu", "il",
                    "elle", "nous", "vous", "ils", "elles", "ce", "cette", "ces",
                    "mon", "ton", "son", "notre", "votre", "leur", "qui", "que",
                    "quoi", "dont", "ou", "mais", "donc", "car", "ni", "or"]

    while True:
        afficher_menu()

        try:
            choix = int(input("Choisissez une option : "))
            print("-" * 50)

            if choix == 5:
                print("Au revoir !")
                print("-" * 50)
                break

            if choix not in [1, 2, 3, 4]:
                print("Option invalide.")
                continue

            if choix in [1, 2]:
                shift = int(input("Entrez la clé (entier positif) : "))
                if shift < 0:
                    raise ValueError("La clé doit être positive.")
                print("-" * 50)

            if choix == 1:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    texte = "Bonjour le monde"
                    print(f"Texte de test : {texte}")
                else:
                    texte = input("Entrez le texte à chiffrer : ")
                resultat = cesar_encrypt(texte, shift)
                print("Texte chiffré :")
                print(resultat)

            elif choix == 2:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    texte = cesar_encrypt("Bonjour le monde", shift)
                    print(f"Texte de test chiffré : {texte}")
                else:
                    texte = input("Entrez le texte à déchiffrer : ")
                resultat = cesar_decrypt(texte, shift)
                print("Texte déchiffré :")
                print(resultat)

            elif choix == 3:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    ciphertext = cesar_encrypt("Bonjour le monde", 5)
                    print(f"Texte chiffré de test : {ciphertext}")
                else:
                    ciphertext = input("Entrez le texte chiffré à attaquer : ")

                print("\n[Force brute] Test des 26 clés possibles :\n")
                results, best_match = brute_force_cesar(ciphertext, french_words)

                for shift, decrypted in results:
                    print(f"Clé {shift:2d} : {decrypted[:80]}{'...' if len(decrypted) > 80 else ''}")

                if best_match:
                    print(f"\n✅ Meilleur résultat détecté (clé {best_match[0]}) : {best_match[1]}")
                else:
                    print("\n⚠️  Aucun match certain avec le dictionnaire")

            elif choix == 4:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    ciphertext = cesar_encrypt("Bonjour le monde", 8)
                    print(f"Texte chiffré de test : {ciphertext}")
                else:
                    ciphertext = input("Entrez le texte chiffré à analyser : ")

                print(f"\nIndice de coïncidence du cryptogramme : {calculate_ic(ciphertext):.4f}")

                shift, decrypted = break_cesar_with_ic(ciphertext)
                print(f"Clé trouvée par IC : {shift}")
                print(f"Texte déchiffré : {decrypted}")

            print("-" * 50)

        except ValueError as e:
            print("Erreur :", e)
            print("-" * 50)
