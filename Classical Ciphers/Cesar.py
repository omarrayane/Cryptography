
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

if __name__ == "__main__":
    SHIFT = 3

    
    with open("testfile.txt", "r", encoding="utf-8") as f:
        texte_clair = f.read()
    texte_chiffre = cesar_encrypt(texte_clair, SHIFT)

    
    with open("testfile_encrypted.txt", "w", encoding="utf-8") as f:
        f.write(texte_chiffre)

    
    texte_dechiffre = cesar_decrypt(texte_chiffre, SHIFT)


    with open("testfile_decrypted.txt", "w", encoding="utf-8") as f:
        f.write(texte_dechiffre)

    print("✔ Test César terminé avec succès")