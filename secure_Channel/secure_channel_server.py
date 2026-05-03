"""
server.py - Serveur qui reçoit les messages chiffrés du client
Écoute les connexions entrantes et communique de manière bidirectionnelle
"""

import socket
import threading
import sys
from crypto_utils import CryptoTools, create_secure_packet, parse_secure_packet


# Configuration
LISTEN_HOST = '0.0.0.0'  # Écouter sur toutes les interfaces
LISTEN_PORT = 65432

SERVER_PRIVATE_KEY = "server_private_key.pem"
CLIENT_PUBLIC_KEY = "client_public_key.pem"


def save_message(message, filename="server_messages.txt"):
    """Enregistre un message dans un fichier"""
    with open(filename, "a", encoding="utf-8") as f:
        f.write(message + "\n")


def receive_messages(conn, server_private_key, client_public_key):
    """Reçoit les messages du client en continu"""
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                print("[*] Client a fermé la connexion")
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
            
            save_message(f"REÇU du client: {plaintext}", "server_messages.txt")
            print("Server: ", end="", flush=True)
        
        except Exception as e:
            print(f"\n[Erreur réception]: {e}")
            break


def send_messages(conn, server_private_key, client_public_key):
    """Envoie les messages au client"""
    while True:
        try:
            message = input("Server: ")
            
            if message.lower() == "exit":
                print("[*] Déconnexion...")
                conn.close()
                break
            
            # Créer et envoyer le paquet sécurisé
            packet = create_secure_packet(message, server_private_key, client_public_key)
            conn.sendall(packet)
            
            save_message(f"ENVOYÉ au client: {message}", "server_messages.txt")
            print("[+] Message envoyé")
        
        except Exception as e:
            print(f"[Erreur envoi]: {e}")
            break


def main():
    """Programme principal"""
    print(f"[*] Serveur écoute sur {LISTEN_HOST}:{LISTEN_PORT}")
    
    try:
        # Charger les clés
        print("[*] Chargement des clés...")
        server_private_key = CryptoTools.load_private_key(SERVER_PRIVATE_KEY)
        client_public_key = CryptoTools.load_public_key(CLIENT_PUBLIC_KEY)
        print("[+] Clés chargées")
        
        # Créer le serveur
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((LISTEN_HOST, LISTEN_PORT))
        server_socket.listen(1)
        print("[+] Serveur en écoute... En attente du client...")
        
        # Accepter la connexion du client
        conn, addr = server_socket.accept()
        print(f"[+] Client connecté: {addr}")
        
        # Thread de réception
        recv_thread = threading.Thread(
            target=receive_messages,
            args=(conn, server_private_key, client_public_key),
            daemon=True
        )
        recv_thread.start()
        
        # Envoi des messages (thread principal)
        send_messages(conn, server_private_key, client_public_key)
        
        # Fermer
        conn.close()
        server_socket.close()
    
    except FileNotFoundError as e:
        print(f"[!] Fichier manquant: {e}")
        print("   Générez les clés d'abord !")
    
    except Exception as e:
        print(f"[!] Erreur: {e}")


if __name__ == "__main__":
    main()