# secure_client.py - Client sécurisé
# ============================================================

import socket
import threading
import os
import sys
from crypto_utils import CryptoTools, create_secure_packet, parse_secure_packet


# Configuration
SERVER_HOST = 'localhost'
SERVER_PORT = 65432

# Chemins des clés (dossier keys)
CLIENT_PRIVATE_KEY = "keys/client_private_key.pem"
SERVER_PUBLIC_KEY = "keys/server_public_key.pem"


def save_message(message: str, filename: str = "client_messages.txt"):
    """Enregistre un message dans un fichier."""
    with open(filename, "a", encoding="utf-8") as f:
        f.write(message + "\n")


def receive_messages(sock, client_private_key, server_public_key):
    """Thread de réception des messages."""
    while True:
        try:
            # Réception de la taille du message
            size_data = sock.recv(4)
            if not size_data:
                print("\n[*] Serveur a fermé la connexion")
                break

            msg_size = int.from_bytes(size_data, 'big')

            # Réception du message complet
            data = b''
            while len(data) < msg_size:
                chunk = sock.recv(min(4096, msg_size - len(data)))
                if not chunk:
                    break
                data += chunk

            if not data:
                break

            # Déchiffrer et vérifier
            plaintext, signature_valid = parse_secure_packet(
                data,
                client_private_key,
                server_public_key
            )

            print(f"\n[Server]: {plaintext}")
            if signature_valid:
                print("[✓] Signature valide")
            else:
                print("[✗] SIGNATURE INVALIDE!")

            save_message(f"REÇU du serveur: {plaintext}")
            print("\n[Client]: ", end="", flush=True)

        except Exception as e:
            print(f"\n[Erreur réception]: {e}")
            break


def send_messages(sock, client_private_key, server_public_key):
    """Envoi des messages."""
    while True:
        try:
            message = input("[Client]: ")

            if message.lower() in ['exit', 'quit']:
                print("[*] Fermeture de la connexion...")
                sock.close()
                break

            if message.strip():
                # Créer le paquet sécurisé
                packet = create_secure_packet(message, client_private_key, server_public_key)

                # Envoyer la taille puis le message
                sock.sendall(len(packet).to_bytes(4, 'big'))
                sock.sendall(packet)

                save_message(f"ENVOYÉ au serveur: {message}")

        except Exception as e:
            print(f"[Erreur envoi]: {e}")
            break


def start_client():
    """Démarre le client sécurisé."""
    print("=" * 60)
    print("  CLIENT SÉCURISÉ (RSA + AES-256 GCM)")
    print("=" * 60)

    # Vérifier l'existence des clés
    if not os.path.exists(CLIENT_PRIVATE_KEY):
        print("\n❌ Clé privée du client introuvable!")
        print("   Exécutez d'abord: python keygen.py")
        return

    if not os.path.exists(SERVER_PUBLIC_KEY):
        print("\n❌ Clé publique du serveur introuvable!")
        print("   Assurez-vous que server_public_key.pem est dans le dossier keys/")
        print("   (Copiez-la depuis le serveur si nécessaire)")
        return

    try:
        # Charger les clés
        print("\n[*] Chargement des clés...")
        client_private_key = CryptoTools.load_private_key(CLIENT_PRIVATE_KEY)
        server_public_key = CryptoTools.load_public_key(SERVER_PUBLIC_KEY)
        print("[+] Clés chargées avec succès")

        # Connexion au serveur
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"\n[+] Connecté au serveur sur {SERVER_HOST}:{SERVER_PORT}")

        # Démarrer le thread de réception
        recv_thread = threading.Thread(
            target=receive_messages,
            args=(sock, client_private_key, server_public_key),
            daemon=True
        )
        recv_thread.start()

        # Envoi des messages (thread principal)
        send_messages(sock, client_private_key, server_public_key)

        # Fermeture
        sock.close()
        print("\n[*] Client arrêté")

    except ConnectionRefusedError:
        print(f"\n[!] Impossible de se connecter au serveur ({SERVER_HOST}:{SERVER_PORT})")
        print("   Vérifiez que le serveur est en écoute")
    except Exception as e:
        print(f"\n[!] Erreur: {e}")


if __name__ == "__main__":
    start_client()
