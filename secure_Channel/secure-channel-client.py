"""
client.py - Client qui envoie des messages chiffrés au serveur
VERSION AVEC DEBUG LOGGING - Voir le chiffrement en action!
"""

import socket
import threading
import sys
from crypto_utils import CryptoTools, create_secure_packet, parse_secure_packet


# Configuration
SERVER_HOST = 'localhost'  # Changez si serveur sur autre machine
SERVER_PORT = 65432

CLIENT_PRIVATE_KEY = "client_private_key.pem"
SERVER_PUBLIC_KEY = "server_public_key.pem"

# 🔧 DEBUG MODE - Affiche les données chiffrées
DEBUG_MODE = True


def save_message(message, filename="client_messages.txt"):
    """Enregistre un message dans un fichier"""
    with open(filename, "a", encoding="utf-8") as f:
        f.write(message + "\n")


def receive_messages(sock, client_private_key, server_public_key):
    """Reçoit les messages du serveur en continu"""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("[*] Serveur a fermé la connexion")
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
                client_private_key,
                server_public_key
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
            
            print(f"[Server]: {plaintext}")
            if signature_valid:
                print("[✓] Signature valide")
            else:
                print("[✗] SIGNATURE INVALIDE!")
            
            save_message(f"REÇU du serveur: {plaintext}", "client_messages.txt")
            print("Client: ", end="", flush=True)
        
        except Exception as e:
            print(f"\n[Erreur réception]: {e}")
            break


def send_messages(sock, client_private_key, server_public_key):
    """Envoie les messages au serveur"""
    while True:
        try:
            message = input("Client: ")
            
            if message.lower() == "exit":
                print("[*] Déconnexion...")
                sock.close()
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
            packet = create_secure_packet(message, client_private_key, server_public_key)
            
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
            
            sock.sendall(packet)
            
            save_message(f"ENVOYÉ au serveur: {message}", "client_messages.txt")
            print("[+] Message envoyé")
        
        except Exception as e:
            print(f"[Erreur envoi]: {e}")
            break


def main():
    """Programme principal"""
    print("[*] Client se connecte au serveur...")
    
    if DEBUG_MODE:
        print("\n" + "🔧 MODE DEBUG ACTIVÉ 🔧".center(70))
        print("Les données chiffrées et déchiffrées seront affichées".center(70))
        print("=" * 70 + "\n")
    
    try:
        # Charger les clés
        print("[*] Chargement des clés...")
        client_private_key = CryptoTools.load_private_key(CLIENT_PRIVATE_KEY)
        server_public_key = CryptoTools.load_public_key(SERVER_PUBLIC_KEY)
        print("[+] Clés chargées")
        
        # Se connecter au serveur
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connecté au serveur sur {SERVER_HOST}:{SERVER_PORT}\n")
        
        # Thread de réception
        recv_thread = threading.Thread(
            target=receive_messages,
            args=(sock, client_private_key, server_public_key),
            daemon=True
        )
        recv_thread.start()
        
        # Envoi des messages (thread principal)
        send_messages(sock, client_private_key, server_public_key)
    
    except FileNotFoundError as e:
        print(f"[!] Fichier manquant: {e}")
        print("   Générez les clés d'abord !")
    
    except ConnectionRefusedError:
        print(f"[!] Impossible de se connecter au serveur ({SERVER_HOST}:{SERVER_PORT})")
        print("   Vérifiez que le serveur est en écoute")
    
    except Exception as e:
        print(f"[!] Erreur: {e}")


if __name__ == "__main__":
    main()