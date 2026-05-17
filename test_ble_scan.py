import asyncio
from bleak import BleakScanner

async def scan_ble():
    print("🔍 Recherche d'appareils Bluetooth LE...")
    print("   (Assurez-vous que le Bluetooth est activé)")
    print("-" * 50)
    
    devices = await BleakScanner.discover(timeout=8)
    
    if not devices:
        print("❌ Aucun appareil BLE trouvé")
        print("   Vérifiez :")
        print("   1. Bluetooth activé sur votre PC")
        print("   2. Un appareil BLE à proximité (smartphone, montre, casque...)")
        return
    
    print(f"\n✅ {len(devices)} appareil(s) trouvé(s) :\n")
    for i, device in enumerate(devices, 1):
        name = device.name or "Sans nom"
        print(f"   {i}. {name}")
        print(f"      Adresse MAC : {device.address}")
        # RSSI n'est pas directement disponible dans cette version
        # On peut l'obtenir avec une méthode différente
        try:
            if hasattr(device, 'rssi'):
                print(f"      RSSI : {device.rssi} dBm")
        except:
            pass
        print()

if __name__ == "__main__":
    asyncio.run(scan_ble())
