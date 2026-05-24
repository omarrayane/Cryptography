import unicodedata
import string
from collections import Counter
import matplotlib.pyplot as plt
import numpy as np

# Fréquences théoriques des lettres en français (en %)
FRENCH_FREQ = {
    'A': 7.636, 'B': 0.901, 'C': 3.260, 'D': 3.669, 'E': 14.715, 'F': 1.066,
    'G': 0.866, 'H': 0.737, 'I': 7.529, 'J': 0.613, 'K': 0.049, 'L': 5.456,
    'M': 2.968, 'N': 7.095, 'O': 5.796, 'P': 2.521, 'Q': 1.362, 'R': 6.693,
    'S': 7.948, 'T': 7.244, 'U': 6.311, 'V': 1.838, 'W': 0.049, 'X': 0.427,
    'Y': 0.128, 'Z': 0.326
}

def normalize_text(text):
    # Supprime les accents et met en minuscules
    text = unicodedata.normalize('NFD', text)
    return ''.join(c for c in text if unicodedata.category(c) != 'Mn').lower()

def analyse_frequentielle(texte):
    texte = normalize_text(texte)
    lettres = [c for c in texte if c in string.ascii_lowercase]
    total = len(lettres)

    if total == 0:
        print("Aucune lettre trouvée dans le texte.")
        return {}

    compte = Counter(lettres)
    frequences = {l: (compte[l] / total) * 100 for l in compte}

    print("Fréquence des lettres :")
    for l, f in sorted(frequences.items(), key=lambda x: x[1], reverse=True):
        print(f"  {l}: {f:.2f}%")

    return frequences

def plot_histogramme(freq_obs, french_freq):
    lettres = list(string.ascii_uppercase)
    obs = [freq_obs.get(l.lower(), 0) for l in lettres]
    exp = [french_freq.get(l, 0) for l in lettres]

    x = np.arange(len(lettres))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x - width / 2, obs, width, label='Observé', color='skyblue')
    ax.bar(x + width / 2, exp, width, label='Théorique', color='lightgreen')

    ax.set_ylabel('Fréquence (%)')
    ax.set_title('Comparaison des fréquences : Observé vs Théorique')
    ax.set_xticks(x)
    ax.set_xticklabels(lettres)
    ax.legend()

    plt.tight_layout()
    plt.show()

if __name__ == '__main__':
    texte = "XINVLTFWRVNTTQPIKIDKPYAVATPIFWQVEMRPPIYWYEBZZXRGFQZRQIELZRAIQAOEAWZWEVRIDMYYZIDQBYRIZAPGHVUALRGPQAPGUEZOPWQMZNZVZEFQZRFIXTPTRVYMEHRKMZLRGMDTLGBRRQOIAXUIWMGIPMDHBRZMPWFIZATFYIEOCEPIMLPWNPSWCMGLYMDHRGTQQJEIYMYXNZMVNIFPQAOSARQMDWBRFBCEAWRWCQRIEMYJBVYIEWVPXQDMOPQACIAHMVEMZTAADMOPQTPYEEOKPWCEDLPWCIDAZRAIEVZRNYFWCMFIQANIYEQAETNVFQNYYMQZPQRRFKCYPMMTOEAWPMDHBQMQYIFXQTDUHIXMDXEEZALGGMAVDJVRMVNMRVQAWIFGAUXYAMOIEMBREUPHVGMTPWRXXMDIPLMVRIFHUVQSEQMBTSAWBMCWBRZMWPRW"

    freq_obs = analyse_frequentielle(texte)
    plot_histogramme(freq_obs, FRENCH_FREQ)
