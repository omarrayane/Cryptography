import math
from typing import Optional

def pgcd_manuel(a: int, b: int) -> int:
    
    while b:
        a, b = b, a % b
    return a

def inverse_modulaire_manuel(a: int, m: int) -> Optional[int]:

    if pgcd_manuel(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def affine_encrypt(text: str, a: int, b: int) -> str:

    result = ""
    for char in text:
        if char.isalpha():
            
            ascii_offset = ord('A') if char.isupper() else ord('a')
            x = ord(char) - ascii_offset
            y = (a * x + b) % 26
            result += chr(y + ascii_offset)
        else:
            result += char
    return result

def affine_decrypt(text: str, a: int, b: int) -> str:
    
    try:
        a_inv = pow(a, -1, 26)  
    except ValueError:
        raise ValueError("L'inverse n'existe pas (a et 26 ne sont pas premiers entre eux)")
        
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            y = ord(char) - ascii_offset
            x = (a_inv * (y - b)) % 26
            result += chr(x + ascii_offset)
        else:
            result += char
    return result

def main():
    print("===================================== Méthode de chiffrement Affine ================================")
    while True:
    
        print("\n\033[32m 1. Taper 1 si vous voulez chiffrer un texte \033[0m")
        print("\033[34m 2. Taper 2 si vous voulez déchiffrer un texte \033[0m")
        print("\033[33m 3. Taper q si vous voulez quittez \033[0m")
        
        choix = input("\033[37m Entrez votre choix: \033[0m").strip()
        
        if choix == '1':
            input_text = input("=> Entrez le texte à chiffrer: ")
            
            try:
                a = int(input("===> Entrez la valeur de a (doit être premier avec 26 exemple : 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25, 27, 29): "))
                while math.gcd(a, 26) != 1:
                    print("\033[31m!! La valeur de a doit être premier avec 26. Veuillez réessayer !!\033[0m")
                    a = int(input("===> Re-entrez la valeur de a (doit être premier avec 26): "))

                b = int(input("===> Entrez la valeur de b (doit être entre 0 et 25): "))
                
                texte_chiffre = affine_encrypt(input_text, a, b)
                print("Le texte chiffré est: \033[32m" + texte_chiffre + "\033[0m")
            except ValueError:
                print("\033[31m!! Veuillez entrer des nombres valides. !!\033[0m")

        elif choix == '2':
            try:
                a = int(input("===> Entrez la valeur de a utilisée pour le chiffrement (doit être premier avec 26): "))
                while math.gcd(a, 26) != 1:
                    print("\033[31m!! La valeur de a doit être premier avec 26. Veuillez réessayer !!\033[0m")
                    a = int(input("===> Re-entrez la valeur de a (doit être premier avec 26): "))
                    
                b = int(input("===> Entrez la valeur de b utilisée pour le chiffrement (doit être entre 0 et 25): "))
                input_text = input("=> Entrez le texte à déchiffrer: ")
                
                texte_dechiffre = affine_decrypt(input_text, a, b)
                print("Le texte déchiffré est: \033[34m" + texte_dechiffre + "\033[0m")
            except ValueError:
                print("\033[31m!! Veuillez entrer des nombres valides. !!\033[0m")

        elif choix.lower() == 'q':
            print("Merci d'avoir utilisé notre programme de chiffrement Affine. Au revoir!")
            break
        else:
            
            print("\033[31m!! Choix invalide. Veuillez réessayer !!\033[0m")

if __name__ == "__main__":
    main()
