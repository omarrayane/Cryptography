def cesar_encrypt(text: str, shift: int) -> str:
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result


def cesar_decrypt(text: str, shift: int) -> str:
    return cesar_encrypt(text, -shift)


def brute_force_cesar(ciphertext: str):
    """
    Attaque par force brute : teste les 26 clés possibles.
    """
    results = []
    for shift in range(26):
        decrypted = cesar_decrypt(ciphertext, shift)
        results.append((shift, decrypted))
    return results


def detect_language(text: str) -> tuple:
    """
    Détecte si un texte est en français ou en anglais.
    Retourne (score_fr, score_en, langue_detectee)
    """
    text_lower = text.lower()
    
    # Mots français très courants
    french_words = [
        "le", "la", "les", "un", "une", "de", "des", "du", "et", "est",
        "dans", "pour", "par", "avec", "sans", "sur", "sous", "je", "tu",
        "il", "elle", "nous", "vous", "ils", "elles", "ce", "cette",
        "ces", "mon", "ton", "son", "notre", "votre", "leur", "qui",
        "que", "quoi", "dont", "ou", "mais", "donc", "car", "ni", "or",
        "au", "aux", "du", "des", "en", "y", "on", "nous", "vous",
        "c'est", "j'ai", "t'es", "il est", "elle est"
    ]
    
    # Mots anglais très courants
    english_words = [
        "the", "and", "to", "of", "a", "an", "in", "for", "on", "with",
        "that", "is", "was", "it", "are", "be", "this", "have", "from",
        "or", "but", "not", "by", "at", "can", "all", "will", "would",
        "could", "should", "they", "we", "you", "he", "she", "it", "them",
        "hello", "world", "hope", "doing", "well", "are", "please",
        "thank", "good", "bad", "nice", "great", "love", "hate"
    ]
    
    # Compter les mots présents
    score_fr = 0
    score_en = 0
    
    for word in french_words:
        if f" {word} " in f" {text_lower} " or text_lower.startswith(f"{word} ") or text_lower.endswith(f" {word}"):
            score_fr += 1
    
    for word in english_words:
        if f" {word} " in f" {text_lower} " or text_lower.startswith(f"{word} ") or text_lower.endswith(f" {word}"):
            score_en += 1
    
    # Détection de mots courts communs aux deux langues
    # Ces mots sont forts indicateurs
    french_specific = ["est", "dans", "pour", "avec", "les", "des", "du", "que", "qui"]
    english_specific = ["the", "and", "of", "to", "in", "for", "that", "is", "are"]
    
    for word in french_specific:
        if f" {word} " in f" {text_lower} ":
            score_fr += 2  # Bonus pour mots spécifiquement français
    
    for word in english_specific:
        if f" {word} " in f" {text_lower} ":
            score_en += 2  # Bonus pour mots spécifiquement anglais
    
    # Déterminer la langue
    if score_fr > score_en and score_fr > 0:
        language = "français"
    elif score_en > score_fr and score_en > 0:
        language = "anglais"
    elif score_fr == score_en and score_fr > 0:
        language = "indéterminé (mixte)"
    else:
        language = "inconnu (score=0)"
    
    return score_fr, score_en, language


def break_cesar_auto(ciphertext: str) -> tuple:
    """
    Attaque automatique : trouve la meilleure clé en testant toutes les clés
    et en choisissant celle qui donne le meilleur score de langue.
    """
    results = brute_force_cesar(ciphertext)
    
    best_shift = None
    best_text = None
    best_score = 0
    best_lang = ""
    
    for shift, decrypted in results:
        score_fr, score_en, lang = detect_language(decrypted)
        total_score = score_fr + score_en
        
        if total_score > best_score:
            best_score = total_score
            best_shift = shift
            best_text = decrypted
            best_lang = lang
    
    # Si aucun score trouvé (texte trop court ou pas de mots), utiliser l'IC
    if best_score == 0:
        best_shift, best_text = break_cesar_with_ic(ciphertext)
        best_lang = "détecté par IC"
    
    return best_shift, best_text, best_score, best_lang


def indice_coincidence(text: str) -> float:
    """
    Calcule l'indice de coïncidence d'un texte.
    IC français ≈ 0.074, anglais ≈ 0.066
    """
    from collections import Counter
    text = ''.join(c for c in text.lower() if c.isalpha())
    n = len(text)
    if n <= 1:
        return 0
    
    counts = Counter(text)
    ic = sum(count * (count - 1) for count in counts.values()) / (n * (n - 1))
    return ic


def break_cesar_with_ic(ciphertext: str) -> tuple:
    """
    Déduit le décalage k en utilisant l'indice de coïncidence.
    """
    best_shift = 0
    best_ic_diff = float('inf')
    french_ic = 0.074
    
    for shift in range(26):
        decrypted = cesar_decrypt(ciphertext, shift)
        ic = indice_coincidence(decrypted)
        diff = abs(ic - french_ic)
        if diff < best_ic_diff:
            best_ic_diff = diff
            best_shift = shift
    
    return best_shift, cesar_decrypt(ciphertext, best_shift)


def afficher_menu():
    print("-" * 60)
    print("      CHIFFREMENT DE CESAR")
    print("-" * 60)
    print("1. Chiffrer un texte")
    print("2. Déchiffrer un texte")
    print("3. Attaque par force brute (avec détection auto FR/EN)")
    print("4. Attaque par indice de coïncidence")
    print("5. Quitter")
    print("-" * 60)


if __name__ == "__main__":
    while True:
        afficher_menu()

        try:
            choix = int(input("Choisissez une option : "))
            print("-" * 60)

            if choix == 5:
                print("Au revoir !")
                break

            if choix not in [1, 2, 3, 4]:
                print("Option invalide.")
                continue

            if choix in [1, 2]:
                shift = int(input("Entrez la clé (entier positif) : "))
                if shift < 0:
                    raise ValueError("La clé doit être positive.")
                print("-" * 60)

            if choix == 1:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    texte = "Bonjour le monde"
                    print(f"Texte de test : {texte}")
                else:
                    texte = input("Entrez le texte à chiffrer : ")
                resultat = cesar_encrypt(texte, shift)
                print("\n📝 Texte chiffré :")
                print(resultat)

            elif choix == 2:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    texte = cesar_encrypt("Bonjour le monde", shift)
                    print(f"Texte de test chiffré : {texte}")
                else:
                    texte = input("Entrez le texte à déchiffrer : ")
                resultat = cesar_decrypt(texte, shift)
                print("\n📝 Texte déchiffré :")
                print(resultat)

            elif choix == 3:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    # Exemple en anglais
                    ciphertext = cesar_encrypt("hello world hope you are doing well", 4)
                    print(f"Texte chiffré de test (anglais) : {ciphertext}")
                    print("\n" + "=" * 60)
                else:
                    ciphertext = input("Entrez le texte chiffré à attaquer : ")
                
                print("\n[Force brute] Test des 26 clés possibles :\n")
                results = brute_force_cesar(ciphertext)
                
                for shift, decrypted in results:
                    print(f"Clé {shift:2d} : {decrypted}")
                
                print("\n" + "=" * 60)
                print("🔍 DÉTECTION AUTOMATIQUE (Français/Anglais) :\n")
                
                best_shift, best_text, best_score, best_lang = break_cesar_auto(ciphertext)
                print(f"✅ Clé la plus probable : {best_shift}")
                print(f"✅ Langue détectée : {best_lang}")
                print(f"✅ Score de confiance : {best_score}")
                print(f"\n📄 Message déchiffré :")
                print(f"   {best_text}")

            elif choix == 4:
                mode = input("Voulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    ciphertext = cesar_encrypt("Bonjour le monde", 8)
                    print(f"Texte chiffré de test : {ciphertext}")
                else:
                    ciphertext = input("Entrez le texte chiffré à analyser : ")
                
                ic = indice_coincidence(ciphertext)
                print(f"\n📊 Indice de coïncidence du cryptogramme : {ic:.4f}")
                print(f"   Références : Français ≈ 0.074 | Anglais ≈ 0.066")
                
                shift, decrypted = break_cesar_with_ic(ciphertext)
                print(f"\n✅ Clé trouvée par IC : {shift}")
                print(f"✅ Texte déchiffré : {decrypted}")

            print("-" * 60)

        except ValueError as e:
            print("Erreur :", e)
            print("-" * 60)
        except KeyboardInterrupt:
            print("\nAu revoir !")
            break
