import unicodedata
import string
from collections import Counter


def normalize_text(text):
    """Supprime les accents et met en minuscules."""
    text = unicodedata.normalize('NFD', text)
    return ''.join(c for c in text if unicodedata.category(c) != 'Mn').lower()


def indice_coincidence(text):
    """
    IC = sum(n_i * (n_i - 1)) / (N * (N - 1))
    """
    text = normalize_text(text)
    letters = [c for c in text if c in string.ascii_lowercase]
    N = len(letters)

    if N <= 1:
        return 0

    counts = Counter(letters)
    somme = sum(n * (n - 1) for n in counts.values())
    return somme / (N * (N - 1))


def analyser_texte():
    """Interface interactive pour analyser un texte."""
    print("\n" + "=" * 50)
    print("  INDICE DE COÏNCIDENCE")
    print("=" * 50)
    
    mode = input("\nVoulez-vous (t)ester avec un exemple ou (u)tiliser votre propre texte ? ").lower()
    
    if mode == 't':
        texte = "La Cryptographie est l'art de coder et decoder des messages. C'est une discipline fascinante qui remonte à l'Antiquité."
        print(f"\nTexte de test : {texte[:100]}...")
    else:
        texte = input("\nEntrez le texte à analyser : ")
    
    ic = indice_coincidence(texte)
    print(f"\n📊 Indice de coïncidence : {ic:.4f}")
    
    print("\n📌 Références :")
    print("   - Français : ≈ 0.074")
    print("   - Anglais  : ≈ 0.066")
    print("   - Aléatoire: ≈ 0.038")
    
    if 0.07 < ic < 0.08:
        print("\n✅ Ce texte ressemble à du français (IC proche de 0.074)")
    elif ic > 0.08:
        print("\n⚠️ IC élevé → texte très répétitif ou langue particulière")
    else:
        print("\n⚠️ IC bas → texte court, aléatoire, ou chiffré")


if __name__ == '__main__':
    analyser_texte()
