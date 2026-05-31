from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER

doc = SimpleDocTemplate(
    "test.pdf",
    pagesize=A4,
    rightMargin=1.8*cm, leftMargin=1.8*cm,
    topMargin=2*cm, bottomMargin=2*cm
)

styles = getSampleStyleSheet()
story = []

# ── Custom styles ──────────────────────────────────────────────
H1 = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=16, textColor=colors.HexColor('#1a1a5e'), spaceAfter=6)
H2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#0d47a1'), spaceAfter=4, spaceBefore=10)
H3 = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=11, textColor=colors.HexColor('#1565c0'), spaceAfter=3, spaceBefore=6)
BODY = ParagraphStyle('BODY', parent=styles['Normal'], fontSize=9, spaceAfter=3, leading=13)
CODE = ParagraphStyle('CODE', parent=styles['Code'], fontSize=8.5, backColor=colors.HexColor('#f3f3f3'),
                      borderPad=4, leading=12, spaceAfter=4)
NOTE = ParagraphStyle('NOTE', parent=styles['Normal'], fontSize=8.5, textColor=colors.HexColor('#555555'),
                      leftIndent=10, spaceAfter=4, leading=12)
WARN = ParagraphStyle('WARN', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#b71c1c'),
                      leftIndent=10, spaceAfter=4, leading=12)

TH = [
    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a237e')),
    ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
    ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
    ('FONTSIZE',   (0,0), (-1,-1), 8),
    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#e8eaf6')]),
    ('GRID', (0,0), (-1,-1), 0.4, colors.HexColor('#9fa8da')),
    ('PADDING', (0,0), (-1,-1), 4),
    ('VALIGN', (0,0), (-1,-1), 'TOP'),
]

def h(lvl, txt):
    story.append(Paragraph(txt, [H1,H2,H3][lvl-1]))

def p(txt):
    story.append(Paragraph(txt, BODY))

def note(txt):
    story.append(Paragraph(f'💬 {txt}', NOTE))

def warn(txt):
    story.append(Paragraph(f'⚠️  {txt}', WARN))

def tip(txt):
    story.append(Paragraph(f'💡 {txt}', NOTE))

def code(txt):
    story.append(Paragraph(txt, CODE))

def sp(n=1):
    story.append(Spacer(1, n*0.3*cm))

def hr():
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#9fa8da'), spaceAfter=4))

def table(data, col_widths=None):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(TH))
    story.append(t)
    sp()

# ══════════════════════════════════════════════════════
#  CONTENU
# ══════════════════════════════════════════════════════

h(1, "Rapport de Test & Guide d'Enregistrement — Classical Ciphers")
p("Objectif : Tester EXCLUSIVEMENT les chiffrements classiques (Classical Ciphers) devant la caméra.")
warn("Durée estimée : ~10-15 minutes.")
hr()

# ── Avant de commencer ──────────────────────────────────
h(2, "⚙️  Avant de commencer")
p("Ouvre un terminal dans le dossier crypto/ et garde-le à l'écran.")
code("cd C:\\Users\\HP\\OneDrive\\Bureau\\crypto")
sp()

# ══════════════════════════════════════════════════════
h(2, "PARTIE 1 — Chiffrements Classiques (Classical_Ciphers/)")

# ── César ────────────────────────────────────────────
h(3, "1.1 — César   (Cesar.py)")
code("python Classical_Ciphers/Cesar.py")
table(
    [["Étape","Action","Entrées à taper","Résultat attendu"],
     ["①","Chiffrer","Option 1 → Clé 3 → Mode u → cryptographie","fubswrjudsklh"],
     ["②","Déchiffrer","Option 2 → Clé 3 → Mode u → fubswrjudsklh","cryptographie"],
     ["③","Force brute","Option 3 → Mode u → fubswrjudsklh","26 clés affichées, ✅ clé 3"],
     ["④","Indice coïncidence","Option 4 → Mode t","IC ≈ 0.074, clé trouvée"],
     ["⑤","Quitter","Option 5","—"]],
    col_widths=[1.2*cm, 2.5*cm, 6.5*cm, 5*cm]
)
note("César décale chaque lettre de k positions. Ici k=3 → 'c' devient 'f'. La force brute teste les 26 clés.")

# ── Affine ───────────────────────────────────────────
h(3, "1.2 — Affine   (affine.py)")
code("python Classical_Ciphers/affine.py")
table(
    [["Étape","Action","Entrées à taper","Résultat attendu"],
     ["①","Chiffrer","Option 1 → securite → a=5 → b=8","ucsepwzc"],
     ["②","Déchiffrer","Option 2 → a=5 → b=8 → ucsepwzc","securite"],
     ["③","Quitter","q","—"]],
    col_widths=[1.2*cm, 2.5*cm, 6.5*cm, 5*cm]
)
note("Affine : y = (a·x + b) mod 26. a doit être premier avec 26.")

# ── Vigenère ─────────────────────────────────────────
h(3, "1.3 — Vigenère   (vigenere.py)")
code("python Classical_Ciphers/vigenere.py")
table(
    [["Étape","Action","Entrées à taper","Résultat attendu"],
     ["①","Chiffrer","Option 1 → Mode u → securite → clé crypto","uvajkwvv"],
     ["②","Déchiffrer","Option 2 → Mode u → uvajkwvv → clé crypto","securite"],
     ["③","Attaque Kasiski","Option 3 → Mode t","Longueur + clé trouvées"],
     ["④","Lien OTP","Option 4","Démonstration affichée"],
     ["⑤","Quitter","Option 5","—"]],
    col_widths=[1.2*cm, 2.5*cm, 6.5*cm, 5*cm]
)
note("Vigenère : clé répétitive. Kasiski trouve la longueur par séquences répétées, puis IC retrouve chaque lettre.")

# ── OTP ──────────────────────────────────────────────
h(3, "1.4 — OTP / Vernam   (OTP.py)")
code("python Classical_Ciphers/OTP.py")
table(
    [["Étape","Action","Entrées à taper","Résultat attendu"],
     ["①","Chiffrer/Déchiffrer","Option 1 → Mode u → cryptographie","chiffré hex + déchiffré = cryptographie"],
     ["②","Two-time pad","Option 2","C1⊕C2 = M1⊕M2, crib dragging visible"],
     ["③","Quitter","Option 3","—"]],
    col_widths=[1.2*cm, 2.5*cm, 6.5*cm, 5*cm]
)
note("OTP = XOR avec clé aussi longue que le message. Sécurité parfaite si clé utilisée UNE SEULE fois.")

# ── Hill ─────────────────────────────────────────────
h(3, "1.5 — Hill   (Hill.py)")
code("python Classical_Ciphers/Hill.py")
table(
    [["Étape","Action","Entrées à taper","Résultat attendu"],
     ["①","Chiffrer","Option 1 → Mode t","hello world chiffré, matrice [[3,3],[2,5]]"],
     ["②","Déchiffrer","Option 2 → Mode t","retour à helloworld"],
     ["③","Attaque clair connu","Option 3 → Taille 2 → paire (help / hiat)","Matrice clé [[3, 3], [2, 5]] retrouvée ✅"],
     ["④","Quitter","Option 4","—"]],
    col_widths=[1.2*cm, 3.2*cm, 5.8*cm, 5*cm]
)
note("Hill : multiplication matricielle mod 26. Attaque clair connu : K = C · P⁻¹.")

# ── Playfair ──────────────────────────────────────────
h(3, "1.6 — Playfair   (Playfair.py)")
code("python Classical_Ciphers/Playfair.py")
p("Script de test automatique (pas de menu). Ce qui s'affiche :")
table(
    [["Message","Clé","Chiffré","Déchiffré"],
     ["hello world","security","FUOQMPXNSPHQ","HELXLOWORLDX"]],
    col_widths=[3.5*cm, 3.5*cm, 5*cm, 4*cm]
)
note("Playfair travaille sur des bigrammes dans une grille 5×5. J et I sont fusionnés.")
sp()

# ── Hill et Playfair (Combiné) ─────────────────────────
h(3, "1.6 bis — Hill et Playfair combinés   (Hill_et_playfair.py)")
code("python Classical_Ciphers/Hill_et_playfair.py")
p("Script qui exécute les deux chiffrements séquentiellement.")
table(
    [["Chiffrement","Message","Clé/Matrice","Chiffré"],
     ["Hill","hello world","[[3, 3], [2, 5]]","hiozeipjql"],
     ["Playfair","hello world","security","FUOQMPXNSPHQ"]],
    col_widths=[3*cm, 3*cm, 5*cm, 4.5*cm]
)
note("Ce script démontre l'implémentation des deux algorithmes en utilisant NumPy pour l'inversion matricielle de Hill.")
sp()
# ── Rail Fence ───────────────────────────────────────
h(3, "1.7 — Rail Fence   (rail_fence_cipher.py)")
code("python Classical_Ciphers/rail_fence_cipher.py")
p("Script de test automatique (pas de menu). Ce qui s'affiche :")
table(
    [["Message","Rails","Chiffré","Déchiffré"],
     ["HELLO WORLD","3","HOREL OLLWD","HELLO WORLD"]],
    col_widths=[3.5*cm, 3*cm, 5*cm, 4.5*cm]
)
note("Rail Fence : transposition zigzag sur N rails, lecture ligne par ligne.")
sp()

# ── Analyse Fréquentielle ─────────────────────────────
h(3, "1.8 — Analyse Fréquentielle   (AnalyseFrequentielle.py)")
code("python Classical_Ciphers/AnalyseFrequentielle.py")
p("Script automatique : analyse un long texte chiffré et affiche un histogramme (Observé vs Théorique).")
table(
    [["Ce qui s'affiche","Valeur / Description"],
     ["Fréquence de chaque lettre","Ex: z: 6.32%, x: 5.87%, ..."],
     ["Histogramme matplotlib","Barres bleues (observé) vs vertes (fréquences françaises théoriques)"],
     ["Interprétation","Si la courbe est plate → chiffrement poly-alphabétique"]],
    col_widths=[5*cm, 10.2*cm]
)
note("L'analyse fréquentielle exploite le fait que certaines lettres (E, A, S en français) apparaissent plus souvent. Un chiffrement monoalphabétique conserve cette distribution.")
sp()

# ── Indice de Coïncidence ──────────────────────────────
h(3, "1.9 — Indice de Coïncidence   (IndiceDeCoincidence.py)")
code("python Classical_Ciphers/IndiceDeCoincidence.py")
table(
    [["Étape","Action","Entrées à taper","Résultat attendu"],
     ["①","Test automatique","t","IC ≈ 0.074 (texte français)"],
     ["②","Texte aléatoire court","u → « aaabbbccc »","IC plus élevé (répétitions)"],
     ["③","Texte chiffré César","u → fubswrjudsklh","IC ≈ 0.065-0.074 (mono-alpha)"]],
    col_widths=[1.2*cm, 3*cm, 6*cm, 5*cm]
)
note("IC = sum(n_i*(n_i-1)) / (N*(N-1)). Français ~ 0.074, Anglais ~ 0.066, Aléatoire ~ 0.038. Un IC bas indique un chiffrement poly-alphabétique.")
sp()

# ── Substitution Aléatoire ────────────────────────────
h(3, "1.10 — Substitution Aléatoire   (Substitution_Aleatoire.py)")
code("python Classical_Ciphers/Substitution_Aleatoire.py")
p("Script automatique : génère une table de substitution aléatoire, chiffre et déchiffre « HELLO WORLD ».")
table(
    [["Ce qui s'affiche","Exemple"],
     ["Table de substitution","{'a': 'x', 'b': 'm', ...} (26 mappages aléatoires)"],
     ["Texte chiffré","Variable à chaque exécution (ex: NKZZB ABCZS)"],
     ["Texte déchiffré","HELLO WORLD (retrouvé via table inverse)"]],
    col_widths=[5*cm, 10.2*cm]
)
note("Substitution monoalphabétique : 26! = 4×10^26 clés possibles. Vulnérable à l'analyse fréquentielle mais résistant à la force brute pure.")
sp()

# ── Test de Kasiski ────────────────────────────────────
h(3, "1.11 — Test de Kasiski   (TestDeKasiski.py)")
code("python Classical_Ciphers/TestDeKasiski.py")
table(
    [["Étape","Action","Entrées à taper","Résultat attendu"],
     ["①","Analyser exemple","Option 1 → t","Séquences répétées + PGCD → longueur clé trouvée"],
     ["②","Quitter","Option 2","—"]],
    col_widths=[1.2*cm, 3*cm, 6*cm, 5*cm]
)
note("Kasiski : cherche les trigrammes répétés dans le texte chiffré. Les écarts entre répétitions sont multiples de la longueur de clé. Le PGCD donne la longueur probable.")
sp()

# ══════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════
hr()
h(2, "Ordre suggere pour l'enregistrement")
table(
    [["#","Fichier","Durée est."],
     ["1","Classical_Ciphers/Cesar.py","3 min"],
     ["2","Classical_Ciphers/affine.py","2 min"],
     ["3","Classical_Ciphers/vigenere.py","2 min"],
     ["4","Classical_Ciphers/OTP.py","2 min"],
     ["5","Classical_Ciphers/Hill.py","2 min"],
     ["6","Classical_Ciphers/Playfair.py","1 min"],
     ["7","Classical_Ciphers/Hill_et_playfair.py","1.5 min"],
     ["8","Classical_Ciphers/rail_fence_cipher.py","1 min"],
     ["9","Classical_Ciphers/AnalyseFrequentielle.py","1 min"],
     ["10","Classical_Ciphers/IndiceDeCoincidence.py","1 min"],
     ["11","Classical_Ciphers/Substitution_Aleatoire.py","1 min"],
     ["12","Classical_Ciphers/TestDeKasiski.py","2 min"]],
    col_widths=[1.2*cm, 10*cm, 4*cm]
)

h(2, "Phrases cles a prononcer")
table(
    [["Script","Phrase clé à dire à l'oral"],
     ["César","Decalage de k positions, force brute a 26 essais"],
     ["Affine","Chiffrement mathematique y = (a x + b) mod 26"],
     ["Vigenere","Cle repetitive, Kasiski trouve la longueur de cle"],
     ["OTP","Securite parfaite si la cle est utilisee une seule fois"],
     ["Hill","Multiplication matricielle mod 26, attaque clair connu"],
     ["Playfair","Chiffrement par paires de lettres sur une grille 5x5"],
     ["Hill+Playfair","Démonstration des deux chiffrements avec numpy"],
     ["Rail Fence","Transposition en zigzag sur N rails"],
     ["Analyse Freq.","Distribution des lettres trahit le chiffrement monoalphabetique"],
     ["IC","IC proche de 0.074 = francais, proche de 0.038 = aleatoire"],
     ["Substitution","26! cles possibles mais vulnerable a l'analyse frequentielle"],
     ["Kasiski","PGCD des ecarts entre trigrammes repetes = longueur de cle"]],
    col_widths=[4*cm, 11.2*cm]
)

tip("Laisse chaque résultat s'afficher complètement avant de continuer.")
sp()

# ── Build ────────────────────────────────────────────
doc.build(story)
print("OK - test.pdf genere avec succes (version Classical Ciphers uniquement)")
