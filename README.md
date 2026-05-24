# 🔐 Projet Cryptographie - USTHB 2025/2026

> **Une implémentation complète et pédagogique des algorithmes cryptographiques fondamentaux en Python**

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Université](https://img.shields.io/badge/USTHB-Informatique-red.svg)

## 📋 Table des matières

- [À propos du projet](#-à-propos-du-projet)
- [Fonctionnalités](#-fonctionnalités)
- [Structure du projet](#-structure-du-projet)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Contenu détaillé](#-contenu-détaillé)
- [Équipe](#-équipe)
- [Références](#-références)

---

## 🎯 À propos du projet

Ce projet est une **implémentation complète et pédagogique des principaux algorithmes cryptographiques** étudiés dans le cursus informatique. Il couvre les domaines essentiels de la cryptographie moderne, de la sécurité des données et des protocoles de communication sécurisés.

### Objectifs

- ✅ Maîtriser les **chiffrements classiques** et leurs faiblesses
- ✅ Implémenter les **algorithmes cryptographiques modernes** (symétrique/asymétrique)
- ✅ Comprendre les **fonctions de hachage** et les **signatures numériques**
- ✅ Mettre en place une **communication sécurisée** client/serveur
- ✅ Fournir une **interface graphique** intuitive pour l'apprentissage

### Contexte académique

- **Université** : Université des Sciences et de la Technologie Houari Boumediene (USTHB)
- **Faculté** : Informatique
- **Année universitaire** : 2024/2025
- **Discipline** : Cryptographie et Sécurité des Données

---

## 🚀 Fonctionnalités

Le projet propose une architecture modulaire organisée en **7 domaines cryptographiques** :

### 1. **Chiffrements Classiques** (`Classical_Ciphers/`)

Implémentations des chiffrements historiques avec cryptanalyse intégrée :

| Algorithme                 | Type                           | Description                                |
| -------------------------- | ------------------------------ | ------------------------------------------ |
| **César**                  | Substitution mono-alphabétique | Décalage fixe des lettres                  |
| **Affine**                 | Chiffrement affine             | Fonction linéaire : E(x) = (ax + b) mod 26 |
| **Vigenère**               | Polyalphabétique               | Clé répétée pour chiffrement intelligent   |
| **Hill**                   | Chiffrement matriciel          | Multiplication matricielle modulo 26       |
| **Playfair**               | Digraphique                    | Matrice 5×5 basée sur un mot-clé           |
| **OTP**                    | One-Time Pad                   | Seul chiffrement théoriquement incassable  |
| **Substitution Aléatoire** | Substitution simple            | Table de substitution aléatoire            |

**Cryptanalyse incluse :**

-  **Analyse Fréquentielle** : Histogramme et comparaison avec les fréquences du français
-  **Indice de Coïncidence** : Détermine la longueur de la clé Vigenère
-  **Test de Kasiski** : Identifie la période d'une clé Vigenère

### 2. **Chiffrement Symétrique** (`Synchrone/`)

Chiffrements modernes par bloc et flux :

- **DES** : Data Encryption Standard (bloc de 64 bits, clé de 56 bits)
- **2DES et 3DES** : Renforcement du DES par double/triple chiffrement
- **DESX** : Variante améliorée du DES
- **AES** : Advanced Encryption Standard avec modes ECB, CBC, CTR
- **AES Finalists** : Autres candidats au concours AES (Twofish, Serpent, Blowfish)
- **RC4** : Chiffrement par flux (stream cipher)

### 3. **Chiffrement Asymétrique** (`asynchrone/`)

Cryptographie à clé publique pour l'échange de clés et le chiffrement :

- **RSA** : Chiffrement/Déchiffrement et signature numérique
- **Diffie-Hellman** : Protocole d'échange de clés sécurisé
- **ElGamal** : Schéma de chiffrement basé sur le problème du logarithme discret
- **ECC (Elliptic Curve Cryptography)** : Cryptographie sur courbes elliptiques

### 4. **Fonctions de Hachage** (`Hashing/`)

Algorithmes de hachage cryptographique :

- **MD5** : 128 bits (rapidité, collisions trouvées)
- **SHA-256** : 256 bits (sûr, recommandé)
- **SHA-512** : 512 bits (haute sécurité)
- **HMAC** : Hash-based Message Authentication Code pour l'authentification

### 5. **Signatures Numériques** (`Signatures/`)

Authentification et intégrité des messages :

- RSA-PSS (RSA Probabilistic Signature Scheme)
- ElGamal Signature
- DSA (Digital Signature Algorithm)
- ECDSA (Elliptic Curve DSA)

### 6. **Canal de Communication Sécurisé** (`secure_Channel/`)

Implémentation complète d'une communication chiffrée :

- **Serveur TCP** : Accepte les connexions client
- **Chiffrement hybride** : RSA pour l'échange de clés + AES-GCM pour les données
- **Authentification** : Signatures numériques pour l'intégrité
- **Protocole sécurisé** : Échange de clés de session et chiffrement des messages

### 7. **Interfaces Utilisateur**

- **GUI (gui.py)** : Interface graphique Tkinter pour tester les algorithmes
- **Web GUI (web_gui.py)** : Interface web Flask/HTML/CSS/JavaScript
- **Backend Server (backend_server.py)** : Serveur API pour les opérations cryptographiques

---

## 📁 Structure du projet

```
Cryptography/
│
├── 📄 README.md                          # Ce fichier
├── 📄 requirements.txt                   # Dépendances Python
├── 📄 rapport.tex                        # Rapport technique complet (LaTeX)
├── 📄 gui.py                             # Interface graphique Tkinter
├── 📄 web_gui.py                         # Interface web Flask
├── 📄 backend_server.py                  # Serveur API
│
├── 📂 Classical_Ciphers/                 # Chiffrements classiques
│   ├── Cesar.py
│   ├── affine.py
│   ├── vigenere.py
│   ├── Hill.py
│   ├── Playfair.py
│   ├── OTP.py
│   ├── Substitution_Aleatoire.py
│   ├── AnalyseFrequentielle.py           # Cryptanalyse
│   ├── IndiceDeCoincidence.py            # Cryptanalyse
│   ├── TestDeKasiski.py                  # Cryptanalyse
│   └── rail_fence_cipher.py
│
├── 📂 Synchrone/                         # Chiffrement symétrique
│   ├── DES.py
│   ├── AES.py
│   ├── AES_Finalists.py
│   └── RC4.py
│
├── 📂 asynchrone/                        # Chiffrement asymétrique
│   ├── RSA.py
│   ├── ElGamal.py
│   ├── Diffie_Hellman.py
│   ├── ECC.py
│   ├── elgamal_api.py
│   └── (versions asynchrones pour les protocoles réseau)
│
├── 📂 Hashing/                           # Fonctions de hachage
│   ├── MD5.py
│   ├── SHA256.py
│   ├── SHA512.py
│   └── HMAC.py
│
├── 📂 Signatures/                        # Signatures numériques
│   └── Signatures.py                     # RSA, ElGamal, DSA, ECDSA
│
├── 📂 secure_Channel/                    # Communication sécurisée
│   ├── secure_channel_server.py          # Serveur TCP sécurisé
│   ├── secure-channel-client.py          # Client TCP sécurisé
│   ├── secure_udp.py                     # Variante UDP
│   ├── secure_bluetooth.py               # Communication Bluetooth sécurisée
│   ├── secure_voting.py                  # Application : vote électronique sécurisé
│   ├── crypto_utils.py                   # Utilitaires cryptographiques
│   ├── keygen.py                         # Génération de clés
│   ├── secure_channel_menu.py            # Menu interactif
│   ├── keys/                             # Dossier pour les clés générées
│   ├── client_messages.txt               # Historique des messages clients
│   └── server_messages.txt               # Historique des messages serveurs
│
├── 📂 static/                            # Ressources web
│   ├── index.html                        # Page d'accueil
│   ├── style.css                         # Feuille de styles
│   └── app.js                            # Logique JavaScript
│
└── 📄 test.html / test_ble_scan.py       # Tests divers

```

---

## 💾 Installation

### Prérequis

- **Python** 3.10 ou plus récent
- **pip** (gestionnaire de paquets Python)
- Système d'exploitation : Windows, Linux ou macOS

### Étapes d'installation

#### 1. Cloner ou télécharger le repository

```bash
cd Cryptography
```

#### 2. Créer un environnement virtuel (recommandé)

**Sous Windows :**

```powershell
python -m venv .venv
.venv\Scripts\Activate
```

**Sous Linux/macOS :**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

**Dépendances requises :**

```
cryptography>=41.0.0     # Bibliothèque cryptographique haute performance
pycryptodome             # Implémentations cryptographiques supplémentaires
Pillow                   # Traitement d'images
numpy                    # Calculs numériques et algèbre linéaire
matplotlib               # Génération de graphiques et histogrammes
sympy                    # Calculs mathématiques symboliques
```

---

##  Utilisation

### 1️⃣ Interface Graphique (GUI)

Pour une expérience **interactive et pédagogique** :

```bash
python gui.py
```

**Fonctionnalités :**

- Menu déroulant pour sélectionner chaque algorithme
- Entrée de texte clair et de clés
- Affichage du texte chiffré/déchiffré en temps réel
- Visualisation des résultats

### 2️⃣ Interface Web

Pour une **expérience moderne et accessible** via navigateur :

```bash
python web_gui.py
```

Puis ouvrez votre navigateur sur `http://localhost:5000`

**Fonctionnalités :**

- Interface responsive et moderne
- Sélection des algorithmes par catégorie
- Chiffrement/Déchiffrement instantané
- Téléchargement des résultats

### 3️⃣ Exécution directe des scripts

Chaque script Python est **exécutable indépendamment** :

```bash
# Chiffrements classiques
python "Classical_Ciphers/Cesar.py"
python "Classical_Ciphers/vigenere.py"
python "Classical_Ciphers/Playfair.py"

# Chiffrement symétrique
python "Synchrone/AES.py"
python "Synchrone/DES.py"

# Chiffrement asymétrique
python "asynchrone/RSA.py"
python "asynchrone/ElGamal.py"
python "asynchrone/Diffie_Hellman.py"

# Cryptanalyse
python "Classical_Ciphers/AnalyseFrequentielle.py"
python "Classical_Ciphers/TestDeKasiski.py"
```

### 4️⃣ Communication Sécurisée Client/Serveur

Pour tester le **canal de communication chiffré** :

**Terminal 1 (Serveur) :**

```bash
python "secure_Channel/secure_channel_server.py"
```

**Terminal 2 (Client) :**

```bash
python "secure_Channel/secure-channel-client.py"
```

Le serveur acceptera les connexions du client avec chiffrement automatique.

---

## 📚 Contenu détaillé

### Chiffrements Classiques

#### **César (Cesar.py)**

- Substitution simple avec décalage fixe
- Vulnérable à l'attaque par brute-force (26 clés possibles)
- **Formule** : E(x) = (x + k) mod 26

#### **Affine (affine.py)**

- Utilise une fonction affine : E(x) = (ax + b) mod 26
- Condition : gcd(a, 26) = 1
- Calcul de l'inverse modulaire avec l'algorithme d'Euclide

#### **Vigenère (vigenere.py)**

- Chiffrement polyalphabétique utilisant un mot-clé
- Bien plus sûr que César
- Vulnérable au **Test de Kasiski** et à l'**Indice de Coïncidence**

#### **Hill (Hill.py)**

- Utilise l'algèbre matricielle
- Clé = matrice inversible mod 26
- Déchiffrement via matrice inverse

#### **Playfair (Playfair.py)**

- Chiffre les **bigrammes** (paires de lettres)
- Matrice 5×5 générée à partir d'une clé
- Trois règles de chiffrement : même ligne/colonne/rectangle

#### **One-Time Pad (OTP.py)**

- **Théoriquement incassable** si la clé est vraiment aléatoire
- Clé de même longueur que le message
- Chiffrement par XOR bit à bit

### Cryptanalyse

#### **Analyse Fréquentielle (AnalyseFrequentielle.py)**

- Compare la fréquence des lettres du texte chiffré
- Fréquences théoriques du français intégrées
- Génère un histogramme comparatif avec matplotlib

#### **Indice de Coïncidence (IndiceDeCoincidence.py)**

- Mesure la probabilité que deux lettres aléatoires soient identiques
- Formule : IC = Σ n_i(n_i - 1) / N(N-1)
- Permet de déterminer la **longueur de la clé Vigenère**

#### **Test de Kasiski (TestDeKasiski.py)**

- Trouve les répétitions dans un texte chiffré
- Les distances entre répétitions sont multiples de la longueur de clé
- Aide à casser le chiffrement Vigenère

### Chiffrement Symétrique

#### **DES (Synchrone/DES.py)**

- Data Encryption Standard
- Bloc de 64 bits, clé de 56 bits effectifs
- 16 tours de Feistel
- ⚠️ **Obsolète** : remplacé par AES

#### **AES (Synchrone/AES.py)**

- Advanced Encryption Standard (Rijndael)
- Bloc de 128 bits, clés de 128/192/256 bits
- Opérations : SubBytes, ShiftRows, MixColumns, AddRoundKey
- Modes ECB, CBC, CTR supportés
- ✅ **Standard moderne et sûr**

#### **RC4 (Synchrone/RC4.py)**

- Chiffrement par flux (stream cipher)
- Rapide mais faible en sécurité
- ⚠️ **À éviter** pour les nouvelles applications

### Chiffrement Asymétrique

#### **RSA (asynchrone/RSA.py)**

- Basé sur la factorisation de grands entiers
- Chiffrement : C ≡ M^e (mod n)
- Déchiffrement : M ≡ C^d (mod n)
- Signature : Hash signé avec clé privée
- Taille de clé recommandée : 2048 bits minimum

#### **ElGamal (asynchrone/ElGamal.py)**

- Basé sur le problème du logarithme discret
- Meilleur pour les signatures numériques
- Plus flexible que RSA pour certains protocoles

#### **Diffie-Hellman (asynchrone/Diffie_Hellman.py)**

- **Protocole d'échange de clés**
- Permet à deux parties d'établir une clé secrète commune
- Base de nombreux protocoles modernes (TLS, SSH)

#### **ECC (asynchrone/ECC.py)**

- Elliptic Curve Cryptography
- Sécurité équivalente à RSA avec clés plus courtes
- Efficace en termes de performances

### Fonctions de Hachage

#### **MD5 (Hashing/MD5.py)**

- Sortie 128 bits
- ⚠️ **Obsolète** : collisions trouvées en 2004
- À éviter pour la sécurité

#### **SHA-256 (Hashing/SHA256.py)**

- Sortie 256 bits
- Cryptographiquement sûr
- ✅ **Standard industriel**

#### **SHA-512 (Hashing/SHA512.py)**

- Sortie 512 bits
- Sécurité maximale
- Utilisé pour les applications critiques

#### **HMAC (Hashing/HMAC.py)**

- Hash-based Message Authentication Code
- Authentification + Intégrité
- Formule : HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))

### Signatures Numériques

#### **RSA Signature (Signatures/Signatures.py)**

- Signe le hash du message avec clé privée
- Vérification avec clé publique

#### **ECDSA**

- Elliptic Curve Digital Signature Algorithm
- Plus efficace que RSA pour les signatures

### Communication Sécurisée

#### **Serveur/Client (secure_Channel/)**

- Architecture client/serveur en Python
- Échange de clés RSA
- Chiffrement AES-GCM des données
- Signatures numériques pour l'intégrité

#### **Protocole hybride :**

1. **Phase 1** : Échange de clés publiques (RSA)
2. **Phase 2** : Client génère clé de session et l'envoie chiffrée
3. **Phase 3** : Communication sécurisée avec AES-GCM

---

## 👥 Équipe

| Nom                         
| ---------------------------
| **Daoud Omar Rayane**         
| **Likou Yani Anis**          
| **Benchetioui Ahmed Ayoub**  

**Institution** : Université des Sciences et de la Technologie Houari Boumediene (USTHB)  
**Faculté** : Informatique  
**Année** : 2025/2026

---

## 📖 Documentation

- **Rapport Technique Complet** : Voir `rapport.tex` (document LaTeX avec code commenté)
- **Fichiers individuels** : Chaque script contient des docstrings et commentaires détaillés

---

## 🔗 Références

### Ressources académiques

- [NIST Special Publication 800-38B - Recommendation for Block Cipher Modes of Operation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf)
- [RFC 3394 - AES Key Wrap Algorithm](https://tools.ietf.org/html/rfc3394)
- [FIPS 197 - Advanced Encryption Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

### Bibliographie

- **Stallings, W.** (2017). _Cryptography and Network Security: Principles and Practice_ (7th Edition)
- **Menezes, A., van Oorschot, P., & Vanstone, S.** (1996). _Handbook of Applied Cryptography_
- **Ferguson, N., & Schneier, B.** (2003). _Practical Cryptography_

### Outils et bibliothèques utilisées

- [cryptography.io](https://cryptography.io) - Bibliothèque cryptographique Python
- [PyCryptodome](https://www.dlitz.net/software/pycryptodome/) - Implémentations cryptographiques
- [NumPy](https://numpy.org) - Calculs numériques
- [Matplotlib](https://matplotlib.org) - Visualisation


##  Contribution

Les suggestions et améliorations sont bienvenues. Pour signaler un problème ou proposer une amélioration, contactez l'équipe pédagogique.

---

**Dernière mise à jour** : Mai 2026  
**Université** : USTHB - Faculté d'Informatique
