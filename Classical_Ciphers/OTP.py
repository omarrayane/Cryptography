import os


def otp_encrypt(message: str) -> tuple:
    """
    Chiffre un message avec OTP.
    Retourne (ciphertext, key)
    """
    message_bytes = message.encode("utf-8")
    key = os.urandom(len(message_bytes))
    ciphertext = bytes(m ^ k for m, k in zip(message_bytes, key))
    return ciphertext, key


def otp_decrypt(ciphertext: bytes, key: bytes) -> str:
    """
    Déchiffre un message avec OTP.
    """
    if len(ciphertext) != len(key):
        raise ValueError("La clé doit avoir la même longueur que le ciphertext")
    message_bytes = bytes(c ^ k for c, k in zip(ciphertext, key))
    return message_bytes.decode("utf-8")


def otp_encrypt_with_key(message: str, key: bytes) -> bytes:
    """
    Chiffre avec une clé fournie (pour démonstration de vulnérabilité).
    """
    message_bytes = message.encode("utf-8")
    if len(key) < len(message_bytes):
        raise ValueError("La clé est trop courte")
    return bytes(m ^ k for m, k in zip(message_bytes, key[:len(message_bytes)]))


def two_time_pad_attack(ciphertext1: bytes, ciphertext2: bytes) -> bytes:
    """
    Calcule C1 XOR C2 = M1 XOR M2 (vulnérabilité de réutilisation de clé).
    """
    min_len = min(len(ciphertext1), len(ciphertext2))
    return bytes(c1 ^ c2 for c1, c2 in zip(ciphertext1[:min_len], ciphertext2[:min_len]))


def crib_dragging(xor_result: bytes, crib: str, position: int = 0) -> str:
    """
    Attaque crib dragging pour deviner une partie des messages.
    """
    crib_bytes = crib.encode('utf-8')
    if position + len(crib_bytes) > len(xor_result):
        return ""
    
    result = bytearray(len(crib_bytes))
    for i, cb in enumerate(crib_bytes):
        result[i] = xor_result[position + i] ^ cb
    
    return result.decode('utf-8', errors='replace')


def demonstrate_otp_vulnerability():
    """
    Démonstration de la vulnérabilité de réutilisation de clé.
    """
    print("\n" + "=" * 60)
    print("  VULNÉRABILITÉ DE RÉUTILISATION DE CLÉ OTP")
    print("=" * 60)
    
    # Même clé pour deux messages
    key = os.urandom(50)
    
    message1 = "Bonjour tout le monde"
    message2 = "Message tres secret"
    
    print(f"\nMessage 1 : {message1}")
    print(f"Message 2 : {message2}")
    print(f"\n🔑 Clé utilisée (identique) : {key.hex()[:32]}...")
    
    # Chiffrement avec la MÊME clé (vulnérabilité)
    cipher1 = otp_encrypt_with_key(message1, key)
    cipher2 = otp_encrypt_with_key(message2, key)
    
    print(f"\nCiphertext 1 : {cipher1.hex()[:32]}...")
    print(f"Ciphertext 2 : {cipher2.hex()[:32]}...")
    
    # Attaque
    xor_result = two_time_pad_attack(cipher1, cipher2)
    print(f"\nC1 XOR C2 = {xor_result.hex()[:32]}...")
    
    # Crib dragging
    print("\n[Attaque crib dragging]")
    print("On suppose que 'bonjour' apparaît dans un message\n")
    
    cribs = ["bonjour", "secret", "message", "monde", "tout"]
    
    for crib in cribs:
        print(f"Essai avec le crib '{crib}':")
        for pos in range(0, min(len(xor_result) - len(crib.encode()), 30)):
            result = crib_dragging(xor_result, crib, pos)
            if result and any(c.isalpha() for c in result):
                print(f"  Position {pos:2d} : {result}")
        print()


def menu():
    print("\n" + "=" * 50)
    print("      ONE-TIME PAD (VERNAM)")
    print("=" * 50)
    print("1. Chiffrer un message")
    print("2. Déchiffrer un message")
    print("3. Démontrer vulnérabilité de réutilisation de clé")
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
                    message = "Hello World"
                    print(f"Message de test : {message}")
                else:
                    message = input("Entrez le message à chiffrer : ")
                
                ciphertext, key = otp_encrypt(message)
                print(f"\nMessage chiffré (hex) : {ciphertext.hex()}")
                print(f"Clé (hex) : {key.hex()}")
                print(f"\n📌 Pour déchiffrer, utilisez l'option 2 avec ces valeurs.")
            
            elif choix == 2:
                mode = input("Voulez-vous (t)ester avec l'exemple précédent ou (u)tiliser vos propres valeurs ? ").lower()
                if mode == 't':
                    # Exemple simple
                    test_msg = "Test"
                    test_cipher, test_key = otp_encrypt(test_msg)
                    ciphertext_hex = test_cipher.hex()
                    key_hex = test_key.hex()
                    print(f"Exemple - Ciphertext : {ciphertext_hex}")
                    print(f"Exemple - Clé : {key_hex}")
                else:
                    ciphertext_hex = input("Entrez le ciphertext (hex) : ")
                    key_hex = input("Entrez la clé (hex) : ")
                
                try:
                    ciphertext = bytes.fromhex(ciphertext_hex)
                    key = bytes.fromhex(key_hex)
                    decrypted = otp_decrypt(ciphertext, key)
                    print(f"Message déchiffré : {decrypted}")
                except Exception as e:
                    print(f"Erreur de déchiffrement : {e}")
                    print("Assurez-vous que la clé a la même longueur que le ciphertext.")
            
            elif choix == 3:
                demonstrate_otp_vulnerability()
            
        except Exception as e:
            print(f"Erreur : {e}")
