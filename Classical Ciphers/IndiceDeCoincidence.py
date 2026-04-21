import unicodedata
import string
from collections import Counter


def normalize_text(text):
    # Supprime les accents et met en minuscules
    text = unicodedata.normalize('NFD', text)
    return ''.join(c for c in text if unicodedata.category(c) != 'Mn').lower()


def indice_coincidence(text):
    # IC = sum(n_i * (n_i - 1)) / (N * (N - 1))
    text = normalize_text(text)
    letters = [c for c in text if c in string.ascii_lowercase]
    N = len(letters)

    if N <= 1:
        return 0

    counts = Counter(letters)
    somme = sum(n * (n - 1) for n in counts.values())
    return somme / (N * (N - 1))


if __name__ == '__main__':
    texte = "La Cryptographie est l'art de coder et décoder des messages. C'est une discipline fascinante qui remonte à l'Antiquité."
    ic = indice_coincidence(texte)
    print(f"Indice de coïncidence : {ic:.4f}")
