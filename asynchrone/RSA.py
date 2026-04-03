import random
from math import gcd

#  Fonction pour trouver l'inverse modulaire
def mod_inverse(e, phi):
    for d in range(1, phi):
        if (d * e) % phi == 1:
            return d
    return None

#  Génération des clés
def generate_keys():
    # petits nombres premiers (exemple pédagogique)
    p = 61
    q = 53
    
    n = p * q
    phi = (p - 1) * (q - 1)

    # choisir e
    e = 17
    while gcd(e, phi) != 1:
        e += 1

    # calculer d
    d = mod_inverse(e, phi)

    return (e, n), (d, n)

#  Chiffrement
def encrypt(message, public_key):
    e, n = public_key
    return [pow(ord(char), e, n) for char in message]

#  Déchiffrement
def decrypt(cipher, private_key):
    d, n = private_key
    return ''.join([chr(pow(char, d, n)) for char in cipher])

#  Test
public_key, private_key = generate_keys()

message = input("Entrez un message à chiffrer : ")
print("Message original :", message)

encrypted = encrypt(message, public_key)
print("Message chiffré :", encrypted)

decrypted = decrypt(encrypted, private_key)
print("Message déchiffré :", decrypted)