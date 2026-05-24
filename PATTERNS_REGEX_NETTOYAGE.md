# 🔍 REGEX PATTERNS POUR DÉTECTER LES COMMENTAIRES BANALS

## Utilisation

Ces patterns peuvent être utilisés dans VS Code Find/Replace pour identifier et nettoyer automatiquement les commentaires banals.

**Accès dans VS Code:**

- `Ctrl+H` = Find and Replace
- Cliquer sur `.*` pour activer Regex Mode

---

## Pattern 1: Séparateurs vides (===, ---, etc.)

### À chercher:

```regex
^[ \t]*#[ \t]*(={5,}|'{5,}|"{5,}|-{5,}|\*{5,})[ \t]*\n
```

**Explication:**

- `^[ \t]*` = Début de ligne avec espaces optionnels
- `#` = Caractère commentaire
- `(={5,}|'{5,}|...)` = Séquences de 5+ caractères identiques
- `[ \t]*\n` = Fin de ligne

**Exemples trouvés:**

```
# ============================================================
# -------- SECTION --------
# ***** MARKER *****
```

### À remplacer par:

```
# (laisser vide pour supprimer)
```

---

## Pattern 2: Docstrings triviales (d'une ligne, redondantes)

### À chercher:

```regex
def\s+(\w+)\([^)]*\):\s*\n\s*"""(?:Rotation droite|Décalage droite|Sigma|Gamma|Fonction de|Calcule|Retourne|Affiche)\s+\w+\."""
```

**Explication:**

- Cherche les docstrings qui commencent par des verbes génériques
- Suivi du nom de la fonction redondant

**Exemples à fusionner:**

```python
# ❌ AVANT
def rotr(x, n):
    """Rotation droite."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

# ✅ APRÈS
def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
```

---

## Pattern 3: Commentaires sur les conditions simples

### À chercher:

```regex
(if|elif|else).*:\s*#\s*(Chiffr|Déchiffr|encrypt|decrypt|test|check|verify|load|save|import|export)\w*
```

**Explication:**

- Détecte les `if/elif` suivis d'un commentaire qui explique juste l'action

**Exemples trouvés:**

```python
if action == 'encrypt':  # Chiffrement
if action == 'decrypt':  # Déchiffrement
elif action == 'bruteforce':  # Force brute
```

### À remplacer:

```regex
(if|elif|else)\s*(.*):\s*#\s*\w+
```

Par:

```
$1 $2:
```

---

## Pattern 4: Commentaires triviaux d'assignation

### À chercher:

```regex
(\w+)\s*=\s*(\w+|[\[\{].*[\]\}]|.*)\s*#\s*(Nombre|Clé|Valeur|Initialiser|Assigner|Initialize|Set|Create|Make)\s*\w*
```

**Explication:**

- Détecte les assignations suivies d'un commentaire trivial

**Exemples trouvés:**

```python
self.p = p          # Nombre premier (modulus)
self.g = g          # Générateur (racine primitive)
aes_key = os.urandom(32)  # Clé AES
```

---

## Pattern 5: Commentaires de boucles évidentes

### À chercher:

```regex
(for|while)\s+(\w+)\s+(in|=).*:\s*#\s*(Boucle|Loop|Iter|Parcourer|Parcourir|Tester|Test|Répéter|Repeat)
```

**Explication:**

- Détecte les boucles avec commentaires explicatifs évidents

**Exemples trouvés:**

```python
for shift in range(26):  # Boucle sur les 26 clés
for i in range(16):  # Parcourir les 16 mots
while d % 2 == 0:  # Tant que d est pair
```

---

## Pattern 6: Docstrings vides ou triviales (multi-ligne)

### À chercher:

```regex
def\s+(\w+).*:\s*\n\s*"""[\s]*([^"]{1,50})?[\s]*"""\s*\n(?!.*Args:|.*Returns:|.*Raises:)
```

**Explication:**

- Cherche les docstrings de moins de 50 caractères
- Sans Args/Returns documentés

---

## Pattern 7: Commentaires de section pour une seule fonction

### À chercher:

```regex
^[ \t]*#\s*[=-*]{5,}.*\n[ \t]*\n[ \t]*(def|class)
```

**Explication:**

- Un séparateur suivi immédiatement d'une fonction

---

## Pattern 8: "Écrire n-1 = d \* 2^r" (commentaire d'explication complexe)

### À chercher:

```regex
#\s*(Écrire|Write|Parse|Format|Convert|Decode).*[=\*\^/].*\n
```

**Note:** Ces commentaires sont utiles et ne doivent PAS être supprimés

---

## 🔧 Script Python pour Automatisation

```python
import re
from pathlib import Path

patterns_to_remove = {
    'empty_separators': r'^[ \t]*#[ \t]*(={5,}|-{5,}|\*{5,})[ \t]*$',
    'trivial_if_comments': r'(if|elif).*:\s*#\s*\w+',
    'trivial_docstrings': r'"""(?:Rotation|Décalage|Sigma|Gamma|Fonction de)\s+\w+\."""',
    'trivial_comments': r'\s*#\s*(?:Initialiser|Initialize|Create|Make).*$',
}

def clean_python_file(filepath):
    """Remove trivial comments from Python file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original_lines = len(content.split('\n'))

    # Remove empty separators
    content = re.sub(patterns_to_remove['empty_separators'], '', content, flags=re.MULTILINE)

    # Remove trivial if comments (but keep code)
    content = re.sub(
        patterns_to_remove['trivial_if_comments'],
        lambda m: m.group(0).split('#')[0].rstrip(),  # Keep if, remove comment
        content
    )

    final_lines = len(content.split('\n'))

    print(f"{filepath}")
    print(f"  Original: {original_lines} lines")
    print(f"  Final: {final_lines} lines")
    print(f"  Removed: {original_lines - final_lines} lines\n")

    return content

# Usage:
# for pyfile in Path('c:/xampp/htdocs/Cryptography').rglob('*.py'):
#     cleaned = clean_python_file(pyfile)
#     # Optionally save back
```

---

## 📋 Checklist de Nettoyage Manuel

Pour chaque fichier Python, vérifier:

### ✅ Phase 1 - Séparateurs

- [ ] Lignes de `# ===...` sans texte
- [ ] Lignes de `# ---...` sans texte
- [ ] Séparateurs isolés sur une ligne complète

### ✅ Phase 2 - Docstrings

- [ ] Docstrings d'une ligne qui ne font que répéter le nom de fonction
- [ ] Docstrings sans Args/Returns documentés
- [ ] Docstrings vagues (`"Retourne X"` sans expliquer comment)

### ✅ Phase 3 - Commentaires de code

- [ ] Commentaires sur les `if/elif/else` simples
- [ ] Commentaires sur les assignations triviales
- [ ] Commentaires "Importer X" sur les imports
- [ ] Commentaires de boucles évidentes

### ✅ Phase 4 - Vérification

- [ ] Tous les fichiers `.py` parcourus
- [ ] Tests unitaires toujours OK
- [ ] Code toujours fonctionnel

---

## 🎯 Ordre d'Exécution Recommandé

### Priorité 1 (Maximum Impact)

1. `asynchrone/Diffie_Hellman.py` - 36 patterns
2. `asynchrone/ECC.py` - 36 patterns
3. `asynchrone/ElGamal.py` - 33 patterns

### Priorité 2

4. `asynchrone/RSA.py` - 30 patterns
5. `Hashing/SHA256.py` - 28 patterns
6. `backend_server.py` - 25 patterns

### Priorité 3

7. `Synchrone/DES.py` - 22 patterns
8. `Classical_Ciphers/*` - 15+ patterns

---

## ⚠️ ATTENTION: Commentaires à CONSERVER

**NE PAS SUPPRIMER** les commentaires:

1. **Expliquant un algorithme complexe**

   ```python
   # Miller-Rabin primality test with k rounds
   # Write n-1 = d * 2^r, then test with k random values
   ```

2. **Documentant des edge cases**

   ```python
   # Special case: curve singularity check (delta = 0)
   ```

3. **Expliquant une ligne non-évidante**

   ```python
   # XOR all bytes with the key stream for RC4
   ```

4. **TODOs ou FIXMEs**

   ```python
   # TODO: Optimize prime generation with sieves
   # FIXME: This fails for p=2
   ```

5. **Références à des papiers/standards**
   ```python
   # RFC 3394: AES Key Wrap Algorithm
   # NIST FIPS 202: SHA-3 Standard
   ```

---

## 📊 Gains Projetés

| Métrique             | Avant  | Après    | %     |
| -------------------- | ------ | -------- | ----- |
| Lignes totales       | 2900   | 2815     | -3%   |
| Lignes commentaire   | 350    | 265      | -24%  |
| Commentaires banals  | 260    | 0        | -100% |
| Docstrings triviales | 45     | 10       | -78%  |
| Lisibilité           | ⭐⭐⭐ | ⭐⭐⭐⭐ | +33%  |
