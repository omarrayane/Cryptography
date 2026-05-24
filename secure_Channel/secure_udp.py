
import socket
import threading
import os
from crypto_utils import CryptoTools, create_secure_packet, parse_secure_packet

UDP_PORT = 65433
BUFFER_SIZE = 65535  # Max UDP packet size

class SecureUDPServer:
    """Serveur UDP sécurisé."""
    
    def __init__(self):
        self.sock = None
        self.running = True
    
    def start(self, host='0.0.0.0', port=UDP_PORT):
        print("=" * 60)
        print("  SERVEUR UDP SÉCURISÉ")
        print("=" * 60)
        
        # Charger les clés
        self.server_private_key = CryptoTools.load_private_key("keys/server_private_key.pem")
        self.client_public_key = CryptoTools.load_public_key("keys/client_public_key.pem")
        
        # Créer le socket UDP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        
        print(f"\n[*] Serveur UDP en écoute sur {host}:{port}")
        print("[*] En attente de messages...\n")
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                
                # Traiter le message
                plaintext, valid = parse_secure_packet(
                    data,
                    self.server_private_key,
                    self.client_public_key
                )
                
                print(f"[{addr[0]}:{addr[1]}] Message: {plaintext}")
                if valid:
                    print("  ✓ Signature valide")
                else:
                    print("  ✗ SIGNATURE INVALIDE!")
                
                # Réponse automatique
                response = f"ACK: {plaintext}"
                packet = create_secure_packet(response, self.server_private_key, self.client_public_key)
                self.sock.sendto(packet, addr)
                
            except Exception as e:
                print(f"Erreur: {e}")
    
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

class SecureUDPClient:
    """Client UDP sécurisé."""
    
    def __init__(self, server_host='localhost', server_port=UDP_PORT):
        self.server_addr = (server_host, server_port)
        self.sock = None
    
    def start(self):
        print("=" * 60)
        print("  CLIENT UDP SÉCURISÉ")
        print("=" * 60)
        
        # Charger les clés
        self.client_private_key = CryptoTools.load_private_key("keys/client_private_key.pem")
        self.server_public_key = CryptoTools.load_public_key("keys/server_public_key.pem")
        
        # Créer le socket UDP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        print(f"\n[*] Connecté au serveur UDP {self.server_addr[0]}:{self.server_addr[1]}")
        
        # Thread de réception
        recv_thread = threading.Thread(target=self._receive, daemon=True)
        recv_thread.start()
        
        # Envoi des messages
        while True:
            message = input("[Client UDP]: ")
            if message.lower() == 'exit':
                break
            
            if message.strip():
                packet = create_secure_packet(message, self.client_private_key, self.server_public_key)
                self.sock.sendto(packet, self.server_addr)
        
        self.sock.close()
    
    def _receive(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
                plaintext, valid = parse_secure_packet(
                    data,
                    self.client_private_key,
                    self.server_public_key
                )
                print(f"\n[Server UDP]: {plaintext}")
                if valid:
                    print("  ✓ Signature valide")
                print("\n[Client UDP]: ", end="", flush=True)
            except Exception as e:
                print(f"Erreur réception: {e}")
                break

def menu():
    print("\n" + "=" * 50)
    print("  COMMUNICATION SÉCURISÉE (TP6)")
    print("=" * 50)
    print("1. Démarrer le serveur TCP")
    print("2. Démarrer le client TCP")
    print("3. Démarrer le serveur UDP")
    print("4. Démarrer le client UDP")
    print("5. Quitter")
    print("-" * 50)

if __name__ == "__main__":
    while True:
        menu()
        
        choix = input("Choisissez une option : ")
        
        if choix == '1':
            from secure_server import start_server
            start_server()
        elif choix == '2':
            from secure_client import start_client
            start_client()
        elif choix == '3':
            server = SecureUDPServer()
            try:
                server.start()
            except KeyboardInterrupt:
                server.stop()
                print("\n[*] Serveur UDP arrêté")
        elif choix == '4':
            client = SecureUDPClient()
            try:
                client.start()
            except KeyboardInterrupt:
                print("\n[*] Client UDP arrêté")
        elif choix == '5':
            print("Au revoir !")
            break
        else:
            print("Option invalide")
