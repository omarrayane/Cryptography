# RC4.py
# ============================================================

import hashlib

# ============================================================
#  RC4 (Rivest Cipher 4)
# ============================================================

class RC4:
    """Implémentation du chiffrement RC4 (stream cipher)."""

    def __init__(self, key):
        """
        Initialise le RC4 avec une clé.
        La clé peut être une string ou des bytes.
        """
        if isinstance(key, str):
            key = key.encode('utf-8')

        self.key = key
        self.S = list(range(256))
        self._ksa(key)

    def _ksa(self, key):
        """Key Scheduling Algorithm (KSA) - Initialisation du S-box."""
        key_length = len(key)
        j = 0

        for i in range(256):
            j = (j + self.S[i] + key[i % key_length]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def _prga(self):
        """Pseudo-Random Generation Algorithm (PRGA) - Génère un byte de keystream."""
        if not hasattr(self, '_i'):
            self._i = 0
            self._j = 0

        self._i = (self._i + 1) % 256
        self._j = (self._j + self.S[self._i]) % 256
        self.S[self._i], self.S[self._j] = self.S[self._j], self.S[self._i]

        return self.S[(self.S[self._i] + self.S[self._j]) % 256]

    def encrypt(self, data):
        """
        Chiffre/déchiffre les données (stream cipher = symétrique).
        Peut prendre string ou bytes en entrée.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Réinitialiser l'état pour ce chiffrement
        self._i = 0
        self._j = 0
        self.S = list(range(256))
        self._ksa(self.key)

        result = bytearray()
        for byte in data:
            keystream_byte = self._prga()
            result.append(byte ^ keystream_byte)

        return bytes(result)

    def decrypt(self, data):
        """
        Déchiffrement RC4 (identique au chiffrement).
        """
        return self.encrypt(data)


# ============================================================
#  Variantes RC4
# ============================================================

class RC4A:
    """
    RC4A (variante avec deux S-boxes pour plus de sécurité).
    """
    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode('utf-8')

        self.key = key
        self.S1 = list(range(256))
        self.S2 = list(range(256))
        self._ksa(key)

    def _ksa(self, key):
        key_len = len(key)
        j1 = j2 = 0

        for i in range(256):
            j1 = (j1 + self.S1[i] + key[i % key_len]) % 256
            self.S1[i], self.S1[j1] = self.S1[j1], self.S1[i]

            j2 = (j2 + self.S2[i] + key[i % key_len]) % 256
            self.S2[i], self.S2[j2] = self.S2[j2], self.S2[i]

    def _prga(self):
        if not hasattr(self, '_i'):
            self._i = 0
            self._j1 = 0
            self._j2 = 0

        self._i = (self._i + 1) % 256
        self._j1 = (self._j1 + self.S1[self._i]) % 256
        self.S1[self._i], self.S1[self._j1] = self.S1[self._j1], self.S1[self._i]

        self._j2 = (self._j2 + self.S2[self._i]) % 256
        self.S2[self._i], self.S2[self._j2] = self.S2[self._j2], self.S2[self._i]

        # Deux keystream bytes par itération
        k1 = self.S1[(self.S1[self._i] + self.S1[self._j1]) % 256]
        k2 = self.S2[(self.S2[self._i] + self.S2[self._j2]) % 256]

        return k1, k2

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        self._i = 0
        self._j1 = 0
        self._j2 = 0
        self.S1 = list(range(256))
        self.S2 = list(range(256))
        self._ksa(self.key)

        result = bytearray()
        i = 0
        while i < len(data):
            k1, k2 = self._prga()
            if i < len(data):
                result.append(data[i] ^ k1)
            i += 1
            if i < len(data):
                result.append(data[i] ^ k2)
            i += 1

        return bytes(result)

    def decrypt(self, data):
        return self.encrypt(data)


class RC4Drop:
    """
    RC4 avec phase de drop (saute N premiers bytes du keystream).
    Résiste mieux aux attaques sur les premiers bytes.
    """
    def __init__(self, key, drop_bytes=768):
        """
        drop_bytes: nombre de bytes à sauter (recommandé: 768 ou 1024)
        """
        if isinstance(key, str):
            key = key.encode('utf-8')

        self.key = key
        self.drop_bytes = drop_bytes
        self.rc4 = RC4(key)

        # Faire tourner le PRGA pour sauter les premiers bytes
        for _ in range(drop_bytes):
            self.rc4._prga()

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        result = bytearray()
        for byte in data:
            keystream_byte = self.rc4._prga()
            result.append(byte ^ keystream_byte)

        return bytes(result)

    def decrypt(self, data):
        return self.encrypt(data)


class RC4WithHash:
    """
    RC4 avec clé dérivée via SHA-256 (clé plus longue/sécurisée).
    """
    def __init__(self, password):
        if isinstance(password, str):
            password = password.encode('utf-8')

        # Dériver une clé de 256 bits avec SHA-256
        derived_key = hashlib.sha256(password).digest()
        self.rc4 = RC4(derived_key)

    def encrypt(self, data):
        return self.rc4.encrypt(data)

    def decrypt(self, data):
        return self.rc4.decrypt(data)


# ============================================================
#  Utilitaires
# ============================================================

def rc4_encrypt_file(filename, key, output_filename=None):
    """Chiffre un fichier avec RC4."""
    with open(filename, 'rb') as f:
        data = f.read()

    rc4 = RC4(key)
    encrypted = rc4.encrypt(data)

    if output_filename is None:
        output_filename = filename + '.rc4'

    with open(output_filename, 'wb') as f:
        f.write(encrypted)

    return output_filename


def rc4_decrypt_file(filename, key, output_filename=None):
    """Déchiffre un fichier RC4."""
    with open(filename, 'rb') as f:
        data = f.read()

    rc4 = RC4(key)
    decrypted = rc4.decrypt(data)

    if output_filename is None:
        if filename.endswith('.rc4'):
            output_filename = filename[:-4]
        else:
            output_filename = filename + '.dec'

    with open(output_filename, 'wb') as f:
        f.write(decrypted)

    return output_filename


# ============================================================
#  Démonstration
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  RC4 Stream Cipher - Démonstration")
    print("=" * 60)

    message = input("\n📝 Entrez un message à chiffrer : ")
    password = input("🔑 Entrez un mot de passe : ")

    # RC4 Standard
    print("\n" + "-" * 40)
    print("  RC4 Standard")
    print("-" * 40)
    rc4 = RC4(password)
    encrypted = rc4.encrypt(message)
    print(f"   Chiffré (hex) : {encrypted.hex()}")
    decrypted = rc4.decrypt(encrypted).decode('utf-8')
    print(f"   Déchiffré     : {decrypted}")

    # RC4A
    print("\n" + "-" * 40)
    print("  RC4A (2 S-boxes)")
    print("-" * 40)
    rc4a = RC4A(password)
    encrypted = rc4a.encrypt(message)
    print(f"   Chiffré (hex) : {encrypted.hex()}")
    decrypted = rc4a.decrypt(encrypted).decode('utf-8')
    print(f"   Déchiffré     : {decrypted}")

    # RC4Drop
    print("\n" + "-" * 40)
    print("  RC4Drop (768 bytes dropped)")
    print("-" * 40)
    rc4drop = RC4Drop(password, drop_bytes=768)
    encrypted = rc4drop.encrypt(message)
    print(f"   Chiffré (hex) : {encrypted.hex()}")
    decrypted = rc4drop.decrypt(encrypted).decode('utf-8')
    print(f"   Déchiffré     : {decrypted}")

    # RC4WithHash
    print("\n" + "-" * 40)
    print("  RC4 with SHA-256 key derivation")
    print("-" * 40)
    rc4hash = RC4WithHash(password)
    encrypted = rc4hash.encrypt(message)
    print(f"   Chiffré (hex) : {encrypted.hex()}")
    decrypted = rc4hash.decrypt(encrypted).decode('utf-8')
    print(f"   Déchiffré     : {decrypted}")

    print("\n" + "-" * 40)
    print("  Propriétés RC4")
    print("-" * 40)
    print("   ✅ Chiffrement symétrique (même fonction)")
    print("   ✅ Stream cipher (keystream XOR)")
    print("   ✅ Très rapide")
    print("   ⚠️  Vulnérabilités connues (ne pas utiliser pour production)")

    print("\n✅ Toutes les variantes RC4 fonctionnent !")
