# ======== CÉSAR ========
def cesar_encrypt(text: str, shift: int) -> str:
    
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            # Décaler et faire le modulo pour rester dans l'alphabet
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def cesar_decrypt(text: str, shift: int) -> str:
    """Déchiffrement de César avec un décalage donné."""
    # Pour déchiffrer, on utilise le décalage inverse
    return cesar_encrypt(text, -shift)

if __name__ == "__main__":
    SHIFT = 3

    # Lire le fichier clair
    with open("testfile.txt", "r", encoding="utf-8") as f:
        texte_clair = f.read()

    # Chiffrer
    texte_chiffre = cesar_encrypt(texte_clair, SHIFT)

    # Écrire le texte chiffré
    with open("testfile_encrypted.txt", "w", encoding="utf-8") as f:
        f.write(texte_chiffre)

    # Déchiffrer
    texte_dechiffre = cesar_decrypt(texte_chiffre, SHIFT)

    # Écrire le texte déchiffré
    with open("testfile_decrypted.txt", "w", encoding="utf-8") as f:
        f.write(texte_dechiffre)

    print("✔ Test César terminé avec succès")