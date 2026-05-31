
import socket
import threading
import os
import sys
from crypto_utils import CryptoTools, create_secure_packet, parse_secure_packet

# Configuration
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 65432

# Chemins des clés (dossier keys)
SERVER_PRIVATE_KEY = "keys/server_private_key.pem"
CLIENT_PUBLIC_KEY = "keys/client_public_key.pem"

def save_message(message: str, filename: str = "server_messages.txt"):
    """Enregistre un message dans un fichier."""
    with open(filename, "a", encoding="utf-8") as f:
        f.write(message + "\n")

def receive_messages(conn, server_private_key, client_public_key):
    """Thread de réception des messages."""
    while True:
        try:
            # Réception de la taille du message
            size_data = conn.recv(4)
            if not size_data:
                print("\n[*] Client a fermé la connexion")
                break

            msg_size = int.from_bytes(size_data, 'big')

            # Réception du message complet
            data = b''
            while len(data) < msg_size:
                chunk = conn.recv(min(4096, msg_size - len(data)))
                if not chunk:
                    break
                data += chunk

            if not data:
                break

            plaintext, signature_valid = parse_secure_packet(
                data,
                server_private_key,
                client_public_key
            )

            print(f"\n[Client]: {plaintext}")
            if signature_valid:
                print("[✓] Signature valide")
            else:
                print("[✗] SIGNATURE INVALIDE!")

            save_message(f"REÇU du client: {plaintext}")
            print("\n[Server] (réponse): ", end="", flush=True)

        except Exception as e:
            print(f"\n[Erreur réception]: {e}")
            break

def send_messages(conn, server_private_key, client_public_key):
    """Envoi des messages."""
    while True:
        try:
            message = input("[Server] (réponse): ")

            if message.lower() in ['exit', 'quit']:
                print("[*] Fermeture de la connexion...")
                conn.close()
                break

            if message.strip():
                # Créer le paquet sécurisé
                packet = create_secure_packet(message, server_private_key, client_public_key)

                # Envoyer la taille puis le message
                conn.sendall(len(packet).to_bytes(4, 'big'))
                conn.sendall(packet)

                save_message(f"ENVOYÉ au client: {message}")

        except Exception as e:
            print(f"[Erreur envoi]: {e}")
            break

def start_server():
    """Démarre le serveur sécurisé."""
    print("=" * 60)
    print("  SERVEUR SÉCURISÉ (RSA + AES-256 GCM)")
    print("=" * 60)

    # Vérifier l'existence des clés
    if not os.path.exists(SERVER_PRIVATE_KEY):
        print("\n❌ Clé privée du serveur introuvable!")
        print("   Exécutez d'abord: python keygen.py")
        return

    if not os.path.exists(CLIENT_PUBLIC_KEY):
        print("\n❌ Clé publique du client introuvable!")
        print("   Assurez-vous que client_public_key.pem est dans le dossier keys/")
        print("   (Copiez-la depuis le client si nécessaire)")
        return

    try:
        # Charger les clés
        print("\n[*] Chargement des clés...")
        server_private_key = CryptoTools.load_private_key(SERVER_PRIVATE_KEY)
        client_public_key = CryptoTools.load_public_key(CLIENT_PUBLIC_KEY)
        print("[+] Clés chargées avec succès")

        # Créer le socket serveur
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((LISTEN_HOST, LISTEN_PORT))
        server_socket.listen(1)

        print(f"\n[*] Serveur en écoute sur {LISTEN_HOST}:{LISTEN_PORT}")
        print("[*] En attente d'un client...")

        # Accepter la connexion
        conn, addr = server_socket.accept()
        print(f"\n[+] Client connecté: {addr}")

        # Démarrer le thread de réception
        recv_thread = threading.Thread(
            target=receive_messages,
            args=(conn, server_private_key, client_public_key),
            daemon=True
        )
        recv_thread.start()

        # Envoi des messages (thread principal)
        send_messages(conn, server_private_key, client_public_key)

        # Fermeture
        conn.close()
        server_socket.close()
        print("\n[*] Serveur arrêté")

    except Exception as e:
        print(f"\n[!] Erreur: {e}")

if __name__ == "__main__":
    start_server()
