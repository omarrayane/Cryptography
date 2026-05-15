from math import gcd
from collections import Counter
from functools import reduce


def find_repeated_sequences(ciphertext, min_length=3):
    """
    Trouve les séquences répétées et calcule les écarts entre leurs positions.
    """
    ciphertext = ''.join(c for c in ciphertext.upper() if c.isalpha())
    sequences = {}
    
    for i in range(len(ciphertext) - min_length + 1):
        seq = ciphertext[i:i + min_length]
        if seq in sequences:
            sequences[seq].append(i)
        else:
            sequences[seq] = [i]
    
    gaps = []
    for seq, positions in sequences.items():
        if len(positions) > 1:
            for j in range(1, len(positions)):
                gaps.append(positions[j] - positions[j - 1])
    
    return gaps, sequences


def find_key_length(ciphertext):
    """
    Longueur probable de la clé = PGCD des écarts.
    """
    gaps, _ = find_repeated_sequences(ciphertext)
    if not gaps:
        return None
    
    key_length = gaps[0]
    for gap in gaps[1:]:
        key_length = gcd(key_length, gap)
    
    return key_length if key_length > 1 else None


def test_multiple_key_lengths(ciphertext, max_len=20):
    """
    Retourne les longueurs de clé possibles triées par probabilité.
    """
    gaps, sequences = find_repeated_sequences(ciphertext)
    if not gaps:
        return []
    
    # Calculer les PGCD de différentes combinaisons
    all_gcds = []
    n = len(gaps)
    for i in range(min(n, 10)):
        for j in range(i+1, min(n, 10)):
            g = gcd(gaps[i], gaps[j])
            if 1 < g <= max_len:
                all_gcds.append(g)
    
    # Compter les fréquences
    freq = Counter(all_gcds)
    return sorted(freq.keys(), key=lambda x: freq[x], reverse=True)[:5]


def afficher_sequences(ciphertext):
    """
    Affiche les séquences répétées trouvées.
    """
    gaps, sequences = find_repeated_sequences(ciphertext, min_length=3)
    
    print("\n" + "=" * 60)
    print("  TEST DE KASISKI - Séquences répétées")
    print("=" * 60)
    
    print("\n📌 Séquences trouvées :")
    for seq, positions in sequences.items():
        if len(positions) > 1:
            print(f"   '{seq}' : positions {positions} (écarts = {', '.join(str(positions[j] - positions[j-1]) for j in range(1, len(positions)))})")
    
    print(f"\n📊 Écarts : {gaps}")
    
    key_length = find_key_length(ciphertext)
    if key_length:
        print(f"\n✅ Longueur de clé probable (PGCD) : {key_length}")
    else:
        print("\n⚠️ Impossible de déterminer une longueur de clé unique")
    
    possible = test_multiple_key_lengths(ciphertext)
    if possible:
        print(f"📌 Autres longueurs possibles : {possible}")


def menu():
    print("\n" + "=" * 50)
    print("      TEST DE KASISKI")
    print("=" * 50)
    print("1. Analyser un texte chiffré")
    print("2. Quitter")
    print("-" * 50)


if __name__ == "__main__":
    # Exemple de texte chiffré Vigenère pour test
    TEST_CIPHERTEXT = "CLCJSGEEXJGGOETFEUUUPEIRMOOBTGGRCOAKTLCHRCODGGOTDEFVCJJFHSEFFVKHEPFRGFSVRUGMAOFMGMEVURGTETBCJJFHSEGEEFJFHFRGOTGTMCOIGSEUMEEIIHGRGEEXJGGOETFEZJGGDOONERSEURUGMAVPTCMIVFDGTSATTGNEUEEEIIHGRGNEPUQWFLGTDGVXEPRTFSRPNFBNVTCQONCJSUFNVVNGDLGGSGDRGUEEPMOVNG"
    
    while True:
        menu()
        
        try:
            choix = int(input("Choisissez une option : "))
            
            if choix == 2:
                print("Au revoir !")
                break
            
            if choix == 1:
                mode = input("Voulez-vous (t)ester avec l'exemple ou (u)tiliser votre propre texte ? ").lower()
                if mode == 't':
                    ciphertext = TEST_CIPHERTEXT
                    print(f"\nTexte chiffré de test (longueur : {len(ciphertext)} caractères)")
                else:
                    ciphertext = input("Entrez le texte chiffré à analyser : ")
                
                afficher_sequences(ciphertext)
            
        except Exception as e:
            print(f"Erreur : {e}")
