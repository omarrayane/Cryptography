# secure_bluetooth.py - Communication Bluetooth sécurisée (simulation)
# ============================================================
# Note: Ceci est une SIMULATION car le Bluetooth réel nécessite du matériel
#       et des bibliothèques spécifiques (PyBluez, bleak)
# ============================================================

import hashlib
import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class BluetoothDevice:
    """
    Simulation d'un périphérique Bluetooth avec chiffrement.
    Le Bluetooth réel utilise:
        - Pairing: ECDH (P-256) pour l'échange de clés
        - Encryption: AES-CCM (counter with CBC-MAC)
    """
    
    def __init__(self, name: str):
        self.name = name
        self.device_id = os.urandom(8).hex()
        self.long_term_key = None  # Clé à long terme (LTK)
        self.connection = None
        
        # Génération de la clé ECDH pour le pairing
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self) -> bytes:
        """Exporte la clé publique pour l'échange."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def pair(self, peer_device, pin_code: str = "000000"):
        """
        Simulation du pairing Bluetooth (Legacy Pairing ou Secure Simple Pairing).
        
        Bluetooth utilise:
            1. ECDH (P-256) pour l'échange de clés
            2. SHA-256 pour la dérivation
            3. Authentification via PIN ou NFC
        """
        print(f"\n[🔵 {self.name}] Tentative de pairing avec {peer_device.name}...")
        print(f"   Code PIN: {pin_code}")
        
        # Échange de clés publiques
        self.peer_public_key = peer_device.public_key
        peer_device.peer_public_key = self.public_key
        
        # Calcul du secret partagé ECDH
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_device.public_key)
        
        # Dérivation de la Long Term Key (LTK) avec PIN
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=pin_code.encode(),
            info=b"bluetooth-pairing",
            backend=default_backend()
        ).derive(shared_secret)
        
        self.long_term_key = derived
        peer_device.long_term_key = derived
        
        # Dérivation des clés de chiffrement
        self.encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"bluetooth-encrypt",
            info=self.device_id.encode(),
            backend=default_backend()
        ).derive(derived)
        peer_device.encryption_key = self.encryption_key
        
        print(f"   ✅ Pairing réussi! (LTK: {self.long_term_key.hex()[:16]}...)")
        self.connected = True
        return True
    
    def encrypt_message(self, message: str) -> bytes:
        """Chiffre un message pour Bluetooth (AES-CCM simulé par AES-GCM)."""
        if not hasattr(self, 'encryption_key'):
            raise Exception("Non pairé! Exécutez d'abord pair()")
        
        message_bytes = message.encode('utf-8')
        
        # Bluetooth utilise un compteur de paquet (packet counter)
        if not hasattr(self, '_packet_counter'):
            self._packet_counter = 0
        
        # Construire le nonce (packet counter + device ID)
        nonce = self._packet_counter.to_bytes(8, 'big') + os.urandom(4)
        
        # Chiffrement AES-GCM (simule AES-CCM du Bluetooth)
        cipher = AESGCM(self.encryption_key)
        ciphertext = cipher.encrypt(nonce, message_bytes, None)
        
        self._packet_counter += 1
        
        return nonce + ciphertext
    
    def decrypt_message(self, encrypted: bytes) -> str:
        """Déchiffre un message Bluetooth."""
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        
        cipher = AESGCM(self.encryption_key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        
        return plaintext.decode('utf-8')
    
    def send_message(self, peer_device, message: str):
        """Envoie un message à un autre périphérique Bluetooth."""
        if not hasattr(self, 'connected') or not self.connected:
            print(f"   ❌ Non connecté à {peer_device.name}")
            return
        
        encrypted = self.encrypt_message(message)
        print(f"\n📱 {self.name} → {peer_device.name}: {message}")
        print(f"   [Chiffré] {encrypted.hex()[:32]}...")
        
        # Réception simulée
        peer_device.receive_message(encrypted)
    
    def receive_message(self, encrypted: bytes):
        """Reçoit et déchiffre un message."""
        plaintext = self.decrypt_message(encrypted)
        print(f"📱 {self.name} reçu: {plaintext}")


def simulate_bluetooth_communication():
    """Simule une communication Bluetooth sécurisée entre deux appareils."""
    print("\n" + "=" * 60)
    print("  BLUETOOTH SECURE COMMUNICATION (SIMULATION)")
    print("  Protocole: ECDH (P-256) + AES-CCM (simulé AES-GCM)")
    print("=" * 60)
    
    # Création des appareils
    smartphone = BluetoothDevice("Smartphone Alice")
    headset = BluetoothDevice("Casque Bob")
    speaker = BluetoothDevice("Enceinte Charlie")
    
    print("\n📱 Appareils créés:")
    print(f"   - {smartphone.name} (ID: {smartphone.device_id[:8]}...)")
    print(f"   - {headset.name} (ID: {headset.device_id[:8]}...)")
    print(f"   - {speaker.name} (ID: {speaker.device_id[:8]}...)")
    
    # Échange des clés publiques
    smartphone.public_key = smartphone.public_key
    headset.public_key = headset.public_key
    speaker.public_key = speaker.public_key
    
    # Pairing Smartphone ↔ Casque
    smartphone.pair(headset, pin_code="123456")
    
    # Communication
    smartphone.send_message(headset, "Bonjour, audio en streaming?")
    time.sleep(0.5)
    headset.send_message(smartphone, "Oui, connexion établie!")
    time.sleep(0.5)
    smartphone.send_message(headset, "Envoi de musique... 🎵")
    
    # Pairing Casque ↔ Enceinte
    print("\n" + "-" * 40)
    headset.pair(speaker, pin_code="000000")
    headset.send_message(speaker, "Diffuser le son sur l'enceinte")
    
    print("\n" + "=" * 60)
    print("  🔒 BLUETOOTH SECURITY NOTES")
    print("=" * 60)
    print("  ✅ ECDH pour l'échange de clés (P-256)")
    print("  ✅ AES-CCM pour le chiffrement des données")
    print("  ✅ Authentification par PIN")
    print("  ⚠️  Faiblesse: PIN court (vulnérabilité aux brute force)")
    print("  ✅ Bluetooth 4.2+ : LE Secure Connections (ECC)")


def simulate_wifi_security():
    """Simule la sécurité Wi-Fi (WPA2/WPA3)."""
    print("\n" + "=" * 60)
    print("  WI-FI SECURITY SIMULATION (WPA2/WPA3)")
    print("=" * 60)
    
    # Simulation du 4-Way Handshake WPA2
    print("\n📡 WPA2 4-Way Handshake Simulation:\n")
    
    # Paramètres (comme dans le standard 802.11i)
    ssid = "WiFi_Secure"
    password = "ComplexPassword123"
    
    # PMK (Pairwise Master Key) = PBKDF2(SSID + Password)
    print(f"  1. SSID: {ssid}")
    print(f"     Mot de passe: {password}")
    
    pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32)
    print(f"     PMK (Pairwise Master Key): {pmk.hex()[:32]}...")
    
    # ANonce (Authenticator Nonce) et SNonce (Supplicant Nonce)
    anonce = os.urandom(32)
    snonce = os.urandom(32)
    print(f"  2. Échange de nonces: ANonce={anonce.hex()[:8]}..., SNonce={snonce.hex()[:8]}...")
    
    # Calcul du PTK (Pairwise Transient Key) = PRF(PMK + ANonce + SNonce + MAC)
    ptk_material = pmk + anonce + snonce
    ptk = hashlib.sha256(ptk_material).digest()
    print(f"  3. PTK (Pairwise Transient Key) calculé: {ptk.hex()[:32]}...")
    
    # Clés dérivées
    kck = ptk[:16]  # Key Confirmation Key
    kek = ptk[16:32]  # Key Encryption Key
    tek = ptk[32:48]  # Temporal Encryption Key
    
    print(f"  4. Clés dérivées:")
    print(f"     - KCK (Confirmation): {kck.hex()[:16]}...")
    print(f"     - KEK (Encryption): {kek.hex()[:16]}...")
    print(f"     - TEK (Data Encryption): {tek.hex()[:16]}...")
    
    # GTK (Group Temporal Key) pour la diffusion
    gtk = os.urandom(32)
    print(f"  5. GTK (Group Temporal Key): {gtk.hex()[:32]}...")
    
    print("\n  ✅ 4-Way Handshake terminé - Communication chiffrée établie")
    print("  🔒 Chiffrement des données: AES-CCMP (CCM Protocol)")
    
    # WPA3 vs WPA2
    print("\n📊 WPA2 vs WPA3:")
    print("   ┌────────────┬─────────────────────────┬─────────────────────────┐")
    print("   │ Fonction   │ WPA2                    │ WPA3                    │")
    print("   ├────────────┼─────────────────────────┼─────────────────────────┤")
    print("   │ Key Exchange│ 4-Way Handshake        │ SAE (Dragonfly)         │")
    print("   │ Encryption │ AES-CCMP (128 bits)    │ AES-GCMP (256 bits)     │")
    print("   │ Protection │ PSK (vulnérable brute) │ SAE (résistant offline) │")
    print("   │ Forward Secrecy│ Non               │ Oui (ECDHE)             │")
    print("   └────────────┴─────────────────────────┴─────────────────────────┘")
    
    return pmk, ptk


class WiFiAccessPoint:
    """Simulation d'un point d'accès Wi-Fi sécurisé."""
    
    def __init__(self, ssid: str, password: str, security: str = "WPA2"):
        self.ssid = ssid
        self.password = password
        self.security = security
        self.clients = []
        
        # PMK dérivé du mot de passe
        self.pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32)
    
    def authenticate_client(self, client_mac: str, client_password: str) -> bool:
        """Authentifie un client via le 4-Way Handshake simulé."""
        print(f"\n   Client {client_mac[:8]}... tente de se connecter à {self.ssid}")
        
        if client_password != self.password:
            print(f"   ❌ Mot de passe incorrect")
            return False
        
        # 4-Way Handshake simulé
        anonce = os.urandom(32)
        snonce = os.urandom(32)
        
        # Calcul du PTK
        ptk_material = self.pmk + anonce + snonce + client_mac.encode() + self.ssid.encode()
        ptk = hashlib.sha256(ptk_material).digest()
        
        print(f"   ✅ Authentification réussie!")
        print(f"   🔐 PTK établi: {ptk.hex()[:32]}...")
        
        self.clients.append({'mac': client_mac, 'ptk': ptk})
        return True
    
    def encrypt_data(self, client_mac: str, data: bytes) -> bytes:
        """Chiffre les données avec AES-CCMP."""
        for client in self.clients:
            if client['mac'] == client_mac:
                tek = client['ptk'][32:48]  # Temporal Encryption Key
                nonce = os.urandom(12)
                cipher = AESGCM(tek)
                encrypted = cipher.encrypt(nonce, data, None)
                return nonce + encrypted
        return None


def demonstrate_bluetooth_le():
    """Démonstration du Bluetooth Low Energy (BLE) sécurisé."""
    print("\n" + "=" * 60)
    print("  BLUETOOTH LOW ENERGY (BLE) SECURITY")
    print("=" * 60)
    
    print("\n📱 Bluetooth LE 4.2+ utilise:")
    print("   - LE Secure Connections (ECDH P-256)")
    print("   - AES-CCM pour le chiffrement")
    print("   - Just Works / Passkey Entry / OOB")
    
    class BLEDevice:
        def __init__(self, name, role):
            self.name = name
            self.role = role  # 'central' or 'peripheral'
            self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self.public_key = self.private_key.public_key()
            self.ltk = None
        
        def pair(self, peer):
            print(f"\n   {self.name} ({self.role}) ←→ {peer.name} ({peer.role})")
            
            # Échange de clés publiques
            shared_secret = self.private_key.exchange(ec.ECDH(), peer.public_key)
            
            # Dérivation de la LTK (Long Term Key)
            self.ltk = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=b"ble-ltk",
                info=self.name.encode() + peer.name.encode(),
                backend=default_backend()
            ).derive(shared_secret)
            peer.ltk = self.ltk
            
            print(f"   ✅ LTK établie: {self.ltk.hex()[:16]}...")
            return True
    
    # Simulation d'un central (smartphone) et d'un peripheral (capteur)
    smartphone = BLEDevice("Smartphone", "central")
    heart_rate_sensor = BLEDevice("Capteur FC", "peripheral")
    
    print("\n🔗 Pairing BLE:")
    smartphone.pair(heart_rate_sensor)
    
    print("\n📊 Données échangées (chiffrées):")
    print("   - Fréquence cardiaque: 72 bpm")
    print("   - Pas: 1245")
    print("   - Calories: 85")


def menu():
    print("\n" + "=" * 55)
    print("  COMMUNICATIONS SÉCURISÉES - Bluetooth & Wi-Fi")
    print("=" * 55)
    print("1. Simuler Bluetooth (classic) communication")
    print("2. Simuler Wi-Fi (WPA2/WPA3)")
    print("3. Simuler Bluetooth Low Energy (BLE)")
    print("4. Quitter")
    print("-" * 55)


if __name__ == "__main__":
    while True:
        menu()
        
        try:
            choix = int(input("Choisissez une option : "))
            
            if choix == 4:
                print("Au revoir !")
                break
            
            if choix == 1:
                simulate_bluetooth_communication()
            
            elif choix == 2:
                simulate_wifi_security()
            
            elif choix == 3:
                demonstrate_bluetooth_le()
            
        except Exception as e:
            print(f"Erreur: {e}")
