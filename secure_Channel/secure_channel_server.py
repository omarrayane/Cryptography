"""
server.py - Serveur qui reçoit les messages chiffrés du client
VERSION AVEC DEBUG LOGGING - Voir le chiffrement en action!
"""

import socket
import threading
import sys
from crypto_utils import CryptoTools, create_secure_packet, parse_secure_packet


# Configuration
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 65432

SERVER_PRIVATE_KEY = "server_private_key.pem"
CLIENT_PUBLIC_KEY = "client_public_key.pem"

# 🔧 DEBUG MODE - Affiche les données chiffrées
DEBUG_MODE = True


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
            
            # =========== DEBUG: AFFICHER LES DONNÉES CHIFFRÉES ===========
            if DEBUG_MODE:
                print("\n" + "=" * 70)
                print("🔍 DEBUG - DONNÉES CHIFFRÉES REÇUES")
                print("=" * 70)
                print(f"[*] Taille totale du paquet: {len(data)} bytes")
                print(f"[*] Premier 64 bytes (HEX): {data[:64].hex()}")
                print(f"[*] Premier 64 bytes (RAW): {data[:64]}")
                print("[*] → Les données NE SONT PAS lisibles (bien chiffré!)")
                print("=" * 70)
            # ============================================================
            
            plaintext, signature_valid = parse_secure_packet(
                data,
                server_private_key,
                client_public_key
            )
            
            # =========== DEBUG: AFFICHER APRÈS DÉCHIFFREMENT ===========
            if DEBUG_MODE:
                print("\n" + "=" * 70)
                print("🔓 DEBUG - APRÈS DÉCHIFFREMENT")
                print("=" * 70)
                print(f"[✓] Message déchiffré avec succès!")
                print(f"[✓] Signature: {'VALIDE ✅' if signature_valid else 'INVALIDE ❌'}")
                print(f"[*] Contenu: {plaintext}")
                print("=" * 70 + "\n")
            # ============================================================
            
            print(f"[Client]: {plaintext}")
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
            
            # =========== DEBUG: AVANT CHIFFREMENT ===========
            if DEBUG_MODE:
                print("\n" + "=" * 70)
                print("🔒 DEBUG - AVANT CHIFFREMENT")
                print("=" * 70)
                print(f"[*] Message original: '{message}'")
                print(f"[*] Taille originale: {len(message)} bytes")
                print("=" * 70)
            # ==============================================
            
            # Créer et envoyer le paquet sécurisé
            packet = create_secure_packet(message, server_private_key, client_public_key)
            
            # =========== DEBUG: APRÈS CHIFFREMENT ===========
            if DEBUG_MODE:
                print("\n" + "=" * 70)
                print("🔐 DEBUG - PAQUET CHIFFRÉ")
                print("=" * 70)
                print(f"[*] Taille après chiffrement: {len(packet)} bytes")
                print(f"[*] Overhead de chiffrement: {len(packet) - len(message)} bytes")
                print(f"[*] Premier 64 bytes (HEX): {packet[:64].hex()}")
                print(f"[*] → Les données sont illisibles (bien chiffré!)")
                print("=" * 70 + "\n")
            # ==============================================
            
            conn.sendall(packet)
            
            save_message(f"ENVOYÉ au client: {message}", "server_messages.txt")
            print("[+] Message envoyé")
        
        except Exception as e:
            print(f"[Erreur envoi]: {e}")
            break


def main():
    """Programme principal"""
    print(f"[*] Serveur écoute sur {LISTEN_HOST}:{LISTEN_PORT}")
    
    if DEBUG_MODE:
        print("\n" + "🔧 MODE DEBUG ACTIVÉ 🔧".center(70))
        print("Les données chiffrées et déchiffrées seront affichées".center(70))
        print("=" * 70 + "\n")
    
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
        print(f"[+] Client connecté: {addr}\n")
        
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