

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


def afficher_menu():
    print("-" * 50)
    print("      CHIFFREMENT DE CESAR")
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

            shift = int(input("Entrez la clé (entier positif) : "))
            if shift < 0:
                raise ValueError("La clé doit être positive.")
            print("-" * 50)

            if choix == 1:
                texte = input("Entrez le texte à chiffrer : ")
                resultat = cesar_encrypt(texte, shift)
                print("Texte chiffré :")
                print(resultat)

            elif choix == 2:
                texte = input("Entrez le texte à déchiffrer : ")
                resultat = cesar_decrypt(texte, shift)
                print("Texte déchiffré :")
                print(resultat)

            print("-" * 50)

        except ValueError as e:
            print("Erreur :", e)
            print("-" * 50)