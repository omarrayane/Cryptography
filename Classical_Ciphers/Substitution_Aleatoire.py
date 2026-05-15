import random
import string
from typing import Dict

def generate_random_substitution() -> Dict[str, str]:
    alphabet = string.ascii_lowercase
    shuffled = list(alphabet)
    random.shuffle(shuffled)
    return {alphabet[i]: shuffled[i] for i in range(len(alphabet))}

def substitution_encrypt(text: str, substitution_table: Dict[str, str]) -> str:
    result = ""
    for char in text.lower():
        if char in substitution_table:
            result += substitution_table[char]
        else:
            result += char
    return result

def substitution_decrypt(text: str, substitution_table: Dict[str, str]) -> str:
    # Créer la table inverse pour le déchiffrement
    inverse_table = {v: k for k, v in substitution_table.items()}
    return substitution_encrypt(text, inverse_table)

if __name__ == "__main__":
    text = "HELLO WORLD"
    table = generate_random_substitution()
    print("Table de substitution :", table)

    encrypted = substitution_encrypt(text, table)
    print("Texte chiffré :", encrypted)

    decrypted = substitution_decrypt(encrypted, table)
    print("Texte déchiffré :", decrypted)   