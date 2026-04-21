import os

def otp_encrypt(message: str) -> tuple[bytes, bytes]:
    
    message_bytes = message.encode("utf-8")
    key = os.urandom(len(message_bytes))
    ciphertext = bytes(m ^ k for m, k in zip(message_bytes, key))
    return ciphertext, key

def otp_decrypt(ciphertext: bytes, key: bytes) -> str:

    message_bytes = bytes(c ^ k for c, k in zip(ciphertext, key))
    return message_bytes.decode("utf-8")

#   TEST 

if __name__ == "__main__":

    message = "Hello World"
    print("Message clair :", message)

    ciphertext, key = otp_encrypt(message)
    print("Message chiffré :", ciphertext)
    print("Clé secrète :", key)

    decrypted = otp_decrypt(ciphertext, key)
    print("Message déchiffré :", decrypted)

    assert decrypted == message
    assert len(ciphertext) == len(message.encode())

    print("✔ OTP fonctionne correctement")