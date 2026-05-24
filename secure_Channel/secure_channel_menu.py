
import os
import sys

def print_banner():
    print("=" * 60)
    print("  TP6 - APPLICATIONS SÉCURISÉES")
    print("  Cryptographie appliquée aux communications")
    print("=" * 60)

def menu():
    print("\n" + "=" * 55)
    print("  CHOIX DE L'APPLICATION")
    print("=" * 55)
    print("┌─────────────────────────────────────────────────────┐")
    print("│  6.1 Sockets TCP/UDP sécurisés                      │")
    print("│     1. Serveur TCP sécurisé                          │")
    print("│     2. Client TCP sécurisé                           │")
    print("│     3. Serveur UDP sécurisé                          │")
    print("│     4. Client UDP sécurisé                           │")
    print("├─────────────────────────────────────────────────────┤")
    print("│  6.2 Bluetooth & Wi-Fi (simulation)                  │")
    print("│     5. Bluetooth Classic sécurisé                    │")
    print("│     6. Wi-Fi (WPA2/WPA3) simulation                  │")
    print("│     7. Bluetooth Low Energy (BLE)                    │")
    print("├─────────────────────────────────────────────────────┤")
    print("│  6.3 Vote électronique sécurisé                      │")
    print("│     8. Élection complète (RSA + signatures)          │")
    print("│     9. Vote homomorphique (principe)                 │")
    print("│    10. Comparatif systèmes de vote                   │")
    print("├─────────────────────────────────────────────────────┤")
    print("│    11. Quitter                                        │")
    print("└─────────────────────────────────────────────────────┘")

if __name__ == "__main__":
    while True:
        print_banner()
        menu()
        
        try:
            choix = int(input("\n👉 Choisissez une option : "))
            
            # 6.1 Sockets TCP/UDP
            if choix == 1:
                os.system("python secure_server.py")
            elif choix == 2:
                os.system("python secure_client.py")
            elif choix == 3:
                from secure_udp import SecureUDPServer
                server = SecureUDPServer()
                try:
                    server.start()
                except KeyboardInterrupt:
                    server.stop()
                    print("\n[*] Serveur UDP arrêté")
            elif choix == 4:
                from secure_udp import SecureUDPClient
                client = SecureUDPClient()
                try:
                    client.start()
                except KeyboardInterrupt:
                    print("\n[*] Client UDP arrêté")
            
            # 6.2 Bluetooth & Wi-Fi
            elif choix == 5:
                from secure_bluetooth import simulate_bluetooth_communication
                simulate_bluetooth_communication()
            elif choix == 6:
                from secure_bluetooth import simulate_wifi_security
                simulate_wifi_security()
            elif choix == 7:
                from secure_bluetooth import demonstrate_bluetooth_le
                demonstrate_bluetooth_le()
            
            # 6.3 Vote électronique
            elif choix == 8:
                from secure_voting import simulate_election
                simulate_election()
            elif choix == 9:
                from secure_voting import demonstrate_homomorphic_voting
                demonstrate_homomorphic_voting()
            elif choix == 10:
                from secure_voting import compare_voting_systems
                compare_voting_systems()
            elif choix == 11:
                print("\n👋 Au revoir !")
                break
            else:
                print("❌ Option invalide")
            
            input("\n🔹 Appuyez sur Entrée pour continuer...")
        
        except KeyboardInterrupt:
            print("\n\n👋 Au revoir !")
            break
        except Exception as e:
            print(f"❌ Erreur: {e}")
