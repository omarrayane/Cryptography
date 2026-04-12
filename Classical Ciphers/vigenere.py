# ======== CHIFFRE DE VIGENÈRE ========

def vigenere_encrypt(text: str, key: str) -> str:
    """Chiffrement de Vigenère."""
    result = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(k) - ord('A') for k in key]

    for i, char in enumerate(text):
        if char.isalpha():
            key_index = i % key_length
            key_shift = key_as_int[key_index]

            if char.isupper():
                result += chr((ord(char) - ord('A') + key_shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') + key_shift) % 26 + ord('a'))
        else:
            result += char

    return result


def vigenere_decrypt(text: str, key: str) -> str:
    """Déchiffrement de Vigenère."""
    result = ""
    key = key.upper()
    key_length = len(key)
    key_as_int = [ord(k) - ord('A') for k in key]

    for i, char in enumerate(text):
        if char.isalpha():
            key_index = i % key_length
            key_shift = key_as_int[key_index]

            if char.isupper():
                result += chr((ord(char) - ord('A') - key_shift) % 26 + ord('A'))
            else:
                result += chr((ord(char) - ord('a') - key_shift) % 26 + ord('a'))
        else:
            result += char

    return result


# ======== TEST ========
if __name__ == "__main__":
    message = "Hello World"
    key = "KEY"

    encrypted = vigenere_encrypt(message, key)
    decrypted = vigenere_decrypt(encrypted, key)

    print("Message original :", message)
    print("Clé             :", key)
    print("Texte chiffré   :", encrypted)
    print("Texte déchiffré :", decrypted)