# crypto_utils.py - Utilitaires cryptographiques
# ============================================================

import os
import json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


class CryptoTools:
    """Outils cryptographiques pour communication sécurisée"""

    @staticmethod
    def load_private_key(path):
        """Charge une clé privée RSA"""
        with open(path, "rb") as f:
            return load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

    @staticmethod
    def load_public_key(path):
        """Charge une clé publique RSA"""
        with open(path, "rb") as f:
            return load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    @staticmethod
    def sign_message(message_bytes, private_key):
        """Signe un message avec RSA-PSS"""
        return private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    @staticmethod
    def verify_signature(message_bytes, signature, public_key):
        """Vérifie une signature RSA-PSS"""
        try:
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    @staticmethod
    def encrypt_message(plaintext_bytes, peer_public_key):
        """
        Chiffre un message avec AES-256 GCM.
        Retourne (encrypted_key, nonce, ciphertext)
        """
        # Générer clé AES aléatoire
        aes_key = AESGCM.generate_key(bit_length=256)

        # Chiffrer avec AES-GCM
        cipher = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, plaintext_bytes, None)

        # Chiffrer la clé AES avec RSA-OAEP
        encrypted_key = peer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_key, nonce, ciphertext

    @staticmethod
    def decrypt_message(encrypted_key, nonce, ciphertext, rsa_private_key):
        """
        Déchiffre un message avec AES-256 GCM.
        """
        # Déchiffrer la clé AES
        aes_key = rsa_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Déchiffrer le message
        cipher = AESGCM(aes_key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)

        return plaintext


def create_secure_packet(message: str, rsa_private_key, peer_public_key) -> bytes:
    """
    Crée un paquet sécurisé (chiffré + signé).
    Format JSON avec encrypted_key, nonce, ciphertext, signature.
    """
    message_bytes = message.encode('utf-8') if isinstance(message, str) else message

    # 1. Signer le message
    signature = CryptoTools.sign_message(message_bytes, rsa_private_key)

    # 2. Chiffrer le message
    encrypted_key, nonce, ciphertext = CryptoTools.encrypt_message(
        message_bytes,
        peer_public_key
    )

    # 3. Créer le paquet JSON
    packet = {
        "encrypted_key": encrypted_key.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": signature.hex()
    }

    return json.dumps(packet).encode()


def parse_secure_packet(packet_bytes: bytes, rsa_private_key, peer_public_key) -> tuple:
    """
    Parse et vérifie un paquet sécurisé.
    Retourne (plaintext, signature_valid)
    """
    packet = json.loads(packet_bytes.decode())

    encrypted_key = bytes.fromhex(packet["encrypted_key"])
    nonce = bytes.fromhex(packet["nonce"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    signature = bytes.fromhex(packet["signature"])

    # Déchiffrer le message
    plaintext = CryptoTools.decrypt_message(
        encrypted_key, nonce, ciphertext, rsa_private_key
    )

    # Vérifier la signature
    signature_valid = CryptoTools.verify_signature(
        plaintext,
        signature,
        peer_public_key
    )

    return plaintext.decode(), signature_valid
