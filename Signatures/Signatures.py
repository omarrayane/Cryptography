import hashlib
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dsa, utils
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import sympy
from typing import Tuple, Dict, Any
import time

class RSASignature:
    """Signature RSA avec PKCS#1 v1.5 et PSS"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.private_key: RSAPrivateKey = None
        self.public_key: RSAPublicKey = None
        self._generate_keys()
    
    def _generate_keys(self):
        """Génération des clés RSA"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
    
    def sign_pkcs1v15(self, message: bytes) -> bytes:
        """
        Signature avec PKCS#1 v1.5
        
        Args:
            message: Message à signer
            
        Returns:
            Signature
        """
        signature = self.private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature
    
    def verify_pkcs1v15(self, message: bytes, signature: bytes) -> bool:
        """
        Vérification avec PKCS#1 v1.5
        
        Args:
            message: Message original
            signature: Signature à vérifier
            
        Returns:
            True si la signature est valide
        """
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def sign_pss(self, message: bytes, salt_length: int = 32) -> bytes:
        """
        Signature avec PSS (Probabilistic Signature Scheme)
        
        Args:
            message: Message à signer
            salt_length: Longueur du sel
            
        Returns:
            Signature
        """
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=salt_length
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_pss(self, message: bytes, signature: bytes) -> bool:
        """
        Vérification avec PSS
        
        Args:
            message: Message original
            signature: Signature à vérifier
            
        Returns:
            True si la signature est valide
        """
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def get_keys(self) -> Dict[str, Any]:
        """Retourne les clés au format PEM"""
        private_pem = self.private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        )
        public_pem = self.public_key.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        )
        return {
            'private_key': private_pem.decode('utf-8'),
            'public_key': public_pem.decode('utf-8')
        }

class ElGamalSignature:
    """Signature ElGamal basée sur le logarithme discret"""
    
    def __init__(self, key_bits: int = 1024):
        self.key_bits = key_bits
        self.p = None
        self.g = None
        self.x = None
        self.y = None
        self._generate_keys()
    
    def _is_primitive_root(self, g: int, p: int, factors: list) -> bool:
        """
        Vérifie si g est une racine primitive modulo p
        
        Args:
            g: Nombre à tester
            p: Nombre premier
            factors: Facteurs premiers de p-1
            
        Returns:
            True si g est une racine primitive
        """
        for factor in factors:
            if pow(g, (p-1)//factor, p) == 1:
                return False
        return True
    
    def _find_primitive_root(self, p: int) -> int:
        """
        Trouve une racine primitive modulo p
        
        Args:
            p: Nombre premier
            
        Returns:
            Racine primitive
        """
        # Factorisation de p-1
        factors = set()
        phi = p - 1
        n = phi
        i = 2
        while i * i <= n:
            if n % i == 0:
                factors.add(i)
                while n % i == 0:
                    n //= i
            i += 1
        if n > 1:
            factors.add(n)
        
        # Recherche de la racine primitive
        for g in range(2, p):
            if self._is_primitive_root(g, p, list(factors)):
                return g
        return 2
    
    def _generate_prime(self, bits: int) -> int:
        """
        Génère un nombre premier de 'bits' bits
        
        Args:
            bits: Nombre de bits
            
        Returns:
            Nombre premier
        """
        return sympy.randprime(2**(bits-1), 2**bits)
    
    def _generate_keys(self):
        # Génération du nombre premier p
        self.p = self._generate_prime(self.key_bits)
        
        # Recherche du générateur
        self.g = self._find_primitive_root(self.p)
        
        # Clé privée (1 < x < p-1)
        self.x = random.randint(2, self.p - 2)
        
        # Clé publique y = g^x mod p
        self.y = pow(self.g, self.x, self.p)
    
    def hash_message(self, message: bytes) -> int:
        """
        Hachage du message avec SHA-256
        
        Args:
            message: Message à hacher
            
        Returns:
            Hash du message modulo p-1
        """
        h = hashlib.sha256(message).hexdigest()
        return int(h, 16) % (self.p - 1)
    
    def sign(self, message: bytes) -> Tuple[int, int]:
        """
        Signature ElGamal
        
        Args:
            message: Message à signer
            
        Returns:
            Tuple (r, s) de la signature
        """
        h = self.hash_message(message)
        
        while True:
            k = random.randint(1, self.p - 1)
            if sympy.gcd(k, self.p - 1) != 1:
                continue
            
            r = pow(self.g, k, self.p)
            if r == 0:
                continue
            
            k_inv = sympy.mod_inverse(k, self.p - 1)
            s = (k_inv * (h - self.x * r)) % (self.p - 1)
            
            if s != 0:
                return (r, s)
    
    def verify(self, message: bytes, r: int, s: int) -> bool:
        """
        Vérification de signature ElGamal
        
        Args:
            message: Message original
            r, s: Signature
            
        Returns:
            True si la signature est valide
        """
        # Vérification des paramètres
        if not (0 < r < self.p):
            return False
        if not (0 < s < self.p - 1):
            return False
        
        h = self.hash_message(message)
        
        # Vérification : y^r * r^s ≡ g^h (mod p)
        left = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p
        right = pow(self.g, h, self.p)
        
        return left == right
    
    def get_keys(self) -> Dict[str, Any]:
        """Retourne les clés"""
        return {
            'private_key': self.x,
            'public_key': {'p': self.p, 'g': self.g, 'y': self.y}
        }

class DSASignature:
    """Signature DSA (Digital Signature Algorithm)"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.private_key: DSAPrivateKey = None
        self.public_key: DSAPublicKey = None
        self._generate_keys()
    
    def _generate_keys(self):
        """Génération des clés DSA"""
        self.private_key = dsa.generate_private_key(key_size=self.key_size)
        self.public_key = self.private_key.public_key()
    
    def sign(self, message: bytes) -> Tuple[int, int]:
        """
        Signature DSA
        
        Args:
            message: Message à signer
            
        Returns:
            Tuple (r, s) de la signature
        """
        signature = self.private_key.sign(message, hashes.SHA256())
        # Décodage de la signature DER
        r = int.from_bytes(signature[:len(signature)//2], 'big')
        s = int.from_bytes(signature[len(signature)//2:], 'big')
        return (r, s)
    
    def verify(self, message: bytes, r: int, s: int) -> bool:
        """
        Vérification de signature DSA
        
        Args:
            message: Message original
            r, s: Signature
            
        Returns:
            True si la signature est valide
        """
        # Reconstruction de la signature DER
        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, 'big')
        s_bytes = s.to_bytes((s.bit_length() + 7) // 8, 'big')
        signature = r_bytes + s_bytes
        
        try:
            self.public_key.verify(signature, message, hashes.SHA256())
            return True
        except Exception:
            return False
    
    def get_keys(self) -> Dict[str, Any]:
        """Retourne les clés au format PEM"""
        private_pem = self.private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        )
        public_pem = self.public_key.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        )
        return {
            'private_key': private_pem.decode('utf-8'),
            'public_key': public_pem.decode('utf-8')
        }

# ECDSA (Elliptic Curve Digital Signature Algorithm)

from cryptography.hazmat.primitives.asymmetric import ec

class ECDSASignature:
    """Signature ECDSA (Elliptic Curve Digital Signature Algorithm)"""
    
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve
        self.private_key: ec.EllipticCurvePrivateKey = None
        self.public_key: ec.EllipticCurvePublicKey = None
        self._generate_keys()
    
    def _generate_keys(self):
        """Génération des clés ECDSA"""
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key = self.private_key.public_key()
    
    def sign(self, message: bytes) -> bytes:
        """Signature ECDSA"""
        signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Vérification ECDSA"""
        try:
            self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
    
    def get_keys(self) -> Dict[str, Any]:
        """Retourne les clés au format PEM"""
        private_pem = self.private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        )
        public_pem = self.public_key.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        )
        return {
            'private_key': private_pem.decode('utf-8'),
            'public_key': public_pem.decode('utf-8')
        }

def test_rsa_signature():
    """Test de la signature RSA"""
    print("\n" + "="*60)
    print("TEST RSA SIGNATURE")
    print("="*60)
    
    rsa_sig = RSASignature(key_size=2048)
    message = b"Message important a signer"
    
    print("\n--- PKCS#1 v1.5 ---")
    signature_pkcs = rsa_sig.sign_pkcs1v15(message)
    print(f"Message: {message}")
    print(f"Signature (hex): {signature_pkcs.hex()[:64]}...")
    print(f"Vérification valide: {rsa_sig.verify_pkcs1v15(message, signature_pkcs)}")
    
    bad_message = b"Message different"
    print(f"Vérification message modifié: {rsa_sig.verify_pkcs1v15(bad_message, signature_pkcs)}")
    
    print("\n--- PSS (Probabilistic Signature Scheme) ---")
    signature_pss = rsa_sig.sign_pss(message)
    print(f"Signature PSS (hex): {signature_pss.hex()[:64]}...")
    print(f"Vérification PSS: {rsa_sig.verify_pss(message, signature_pss)}")

def test_elgamal_signature():
    """Test de la signature ElGamal"""
    print("\n" + "="*60)
    print("TEST ELGAMAL SIGNATURE")
    print("="*60)
    
    # Utilisation de bits plus petits pour la démonstration
    elgamal = ElGamalSignature(key_bits=512)
    message = b"Message secret"
    
    print(f"p (premier): {elgamal.p}")
    print(f"g (générateur): {elgamal.g}")
    print(f"y = g^x mod p: {elgamal.y}")
    
    r, s = elgamal.sign(message)
    print(f"\nMessage: {message}")
    print(f"Signature: r={r}, s={s}")
    
    # Vérification
    valid = elgamal.verify(message, r, s)
    print(f"Vérification valide: {valid}")
    
    valid_bad = elgamal.verify(b"Wrong message", r, s)
    print(f"Vérification message modifié: {valid_bad}")

def test_dsa_signature():
    """Test de la signature DSA"""
    print("\n" + "="*60)
    print("TEST DSA SIGNATURE")
    print("="*60)
    
    dsa_sig = DSASignature(key_size=2048)
    message = b"Document a signer avec DSA"
    
    r, s = dsa_sig.sign(message)
    print(f"Message: {message}")
    print(f"r: {r}")
    print(f"s: {s}")
    
    # Vérification
    valid = dsa_sig.verify(message, r, s)
    print(f"Vérification valide: {valid}")
    
    valid_bad = dsa_sig.verify(b"Wrong message", r, s)
    print(f"Vérification message modifié: {valid_bad}")

def test_ecdsa_signature():
    """Test de la signature ECDSA"""
    print("\n" + "="*60)
    print("TEST ECDSA SIGNATURE")
    print("="*60)
    
    ecdsa_sig = ECDSASignature()
    message = b"Message avec signature ECDSA"
    
    signature = ecdsa_sig.sign(message)
    print(f"Message: {message}")
    print(f"Signature (hex): {signature.hex()[:64]}...")
    
    # Vérification
    valid = ecdsa_sig.verify(message, signature)
    print(f"Vérification valide: {valid}")
    
    valid_bad = ecdsa_sig.verify(b"Message hacke", signature)
    print(f"Vérification message modifié: {valid_bad}")

def benchmark_signatures():
    """Benchmark des différentes signatures"""
    print("\n" + "="*60)
    print("BENCHMARK DES SIGNATURES")
    print("="*60)
    
    message = b"X" * 1024  # Message de 1KB
    
    algorithms = {
        'RSA-2048 (PKCS)': RSASignature(2048),
        'RSA-2048 (PSS)': RSASignature(2048),
        'DSA-2048': DSASignature(2048),
        'ECDSA-P256': ECDSASignature()
    }
    
    results = {}
    
    for name, algo in algorithms.items():
        # Mesure du temps de signature
        start = time.time()
        if 'RSA' in name:
            if 'PKCS' in name:
                sig = algo.sign_pkcs1v15(message)
            else:
                sig = algo.sign_pss(message)
        elif 'DSA' in name:
            r, s = algo.sign(message)
            sig = (r, s)
        else:  # ECDSA
            sig = algo.sign(message)
        sign_time = time.time() - start
        
        # Mesure du temps de vérification
        start = time.time()
        if 'RSA' in name:
            if 'PKCS' in name:
                valid = algo.verify_pkcs1v15(message, sig)
            else:
                valid = algo.verify_pss(message, sig)
        elif 'DSA' in name:
            valid = algo.verify(message, r, s)
        else:
            valid = algo.verify(message, sig)
        verify_time = time.time() - start
        
        results[name] = {
            'sign_time': sign_time * 1000,  # en ms
            'verify_time': verify_time * 1000,
            'valid': valid
        }
    
    # Affichage des résultats
    print(f"\n{'Algorithme':<20} {'Signature (ms)':<15} {'Vérification (ms)':<15}")
    print("-" * 50)
    for name, metrics in results.items():
        print(f"{name:<20} {metrics['sign_time']:<15.4f} {metrics['verify_time']:<15.4f}")

def demonstrate_malleability():
    """Démonstration de la malléabilité d'ElGamal"""
    print("\n" + "="*60)
    print("DÉMONSTRATION DE LA MALLÉABILITÉ D'ELGAMAL")
    print("="*60)
    
    elgamal = ElGamalSignature(key_bits=512)
    
    m = 12345
    message = str(m).encode()
    
    print(f"\nMessage original: {m}")
    
    r, s = elgamal.sign(message)
    print(f"Signature originale: r={r}, s={s}")
    
    print("\n--- Propriété de malléabilité ---")
    print("ElGamal est malléable: E(M1) * E(M2) = E(M1 * M2)")
    print("Cela signifie qu'un attaquant peut modifier le chiffré")
    print("sans connaître la clé privée.")
    
    print("\nContre-mesures:")
    print("1. Utiliser un padding approprié")
    print("2. Combiner avec un hash du message")
    print("3. Utiliser DSA ou ECDSA à la place")

if __name__ == "__main__":
    print("="*60)
    print("TP5 - SIGNATURES NUMÉRIQUES")
    print("="*60)
    
    # Exécution des tests
    test_rsa_signature()
    test_elgamal_signature()
    test_dsa_signature()
    test_ecdsa_signature()
    benchmark_signatures()
    demonstrate_malleability()
    
    print("\n" + "="*60)
    print("FIN DES TESTS")
    print("="*60)
