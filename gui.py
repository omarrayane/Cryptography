#!/usr/bin/env python3
# gui.py - Application Cryptographie Complète avec Test Réseau

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import hashlib
import time
import os
import random
import threading
import subprocess
import sys
from datetime import datetime


class CryptographyApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 CryptoSuite - Application Cryptographique")
        self.root.geometry("1300x850")
        self.root.minsize(1100, 700)
        self.root.configure(bg='#1e1e2e')
        
        # Variables pour les threads réseau
        self.server_process = None
        self.client_process = None
        
        self.setup_styles()
        self.setup_ui()
        self.log("🚀 Application CryptoSuite démarrée")
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        colors = {
            'bg': '#1e1e2e',
            'fg': '#cdd6f4',
            'accent': '#89b4fa',
            'success': '#a6e3a1',
            'warning': '#f9e2af',
            'error': '#f38ba8',
            'surface': '#313244'
        }
        
        style.configure('TLabel', background=colors['bg'], foreground=colors['fg'])
        style.configure('TFrame', background=colors['bg'])
        style.configure('TLabelframe', background=colors['bg'], foreground=colors['accent'])
        style.configure('TLabelframe.Label', background=colors['bg'], foreground=colors['accent'])
        style.configure('TButton', background=colors['surface'], foreground=colors['fg'])
        style.map('TButton', background=[('active', '#45475a')])
        style.configure('Success.TButton', background=colors['success'], foreground=colors['bg'])
        style.configure('Warning.TButton', background=colors['warning'], foreground=colors['bg'])
        style.configure('TEntry', fieldbackground=colors['surface'], foreground=colors['fg'])
        style.configure('TRadiobutton', background=colors['bg'], foreground=colors['fg'])
        
    def setup_ui(self):
        # Header
        header = tk.Frame(self.root, bg='#1e1e2e')
        header.pack(fill=tk.X, padx=20, pady=10)
        
        title = ttk.Label(header, text="🔐 CryptoSuite", font=('Helvetica', 22, 'bold'))
        title.pack(side=tk.LEFT)
        
        subtitle = ttk.Label(header, text="TP1 à TP6 - Tous les algorithmes", font=('Helvetica', 10))
        subtitle.pack(side=tk.LEFT, padx=15)
        
        # Main container
        main = tk.Frame(self.root, bg='#1e1e2e')
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left panel - Algorithmes
        left = tk.Frame(main, bg='#1e1e2e', width=280)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        left.pack_propagate(False)
        
        self.create_algorithm_tabs(left)
        
        # Center panel - Input/Output
        center = tk.Frame(main, bg='#1e1e2e')
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.create_io_panel(center)
        
        # Right panel - Journal
        right = tk.Frame(main, bg='#1e1e2e', width=350)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(15, 0))
        right.pack_propagate(False)
        
        self.create_log_panel(right)
        
        # Status bar
        self.status_var = tk.StringVar(value="✅ Prêt")
        status = tk.Label(self.root, textvariable=self.status_var, bg='#313244', fg='#a6e3a1',
                         font=('Helvetica', 10), anchor=tk.W, padx=10, pady=5)
        status.pack(fill=tk.X, side=tk.BOTTOM)
        
    def create_algorithm_tabs(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        self.algo_var = tk.StringVar(value="cesar")
        
        # TP1 - Classique
        tp1 = ttk.Frame(notebook)
        notebook.add(tp1, text="🏛️ TP1 - Classique")
        for name, val in [("César", "cesar"), ("Vigenère", "vigenere"), ("OTP", "otp")]:
            rb = ttk.Radiobutton(tp1, text=name, variable=self.algo_var, value=val)
            rb.pack(anchor=tk.W, padx=15, pady=5)
        
        # TP2 - Symétrique
        tp2 = ttk.Frame(notebook)
        notebook.add(tp2, text="🔒 TP2 - Symétrique")
        for name, val in [("RC4", "rc4"), ("AES-256", "aes")]:
            rb = ttk.Radiobutton(tp2, text=name, variable=self.algo_var, value=val)
            rb.pack(anchor=tk.W, padx=15, pady=5)
        
        # TP4 - Hachage
        tp4 = ttk.Frame(notebook)
        notebook.add(tp4, text="🔢 TP4 - Hachage")
        for name, val in [("MD5", "md5"), ("SHA-256", "sha256"), ("SHA-512", "sha512"), ("HMAC", "hmac")]:
            rb = ttk.Radiobutton(tp4, text=name, variable=self.algo_var, value=val)
            rb.pack(anchor=tk.W, padx=15, pady=5)
        
        # TP6 - Réseau (NOUVEAU)
        tp6 = ttk.Frame(notebook)
        notebook.add(tp6, text="📡 TP6 - Réseau")
        for name, val in [("🔵 Bluetooth (simulation)", "bluetooth"),
                          ("📡 Wi-Fi WPA2 (simulation)", "wifi"),
                          ("🗳️ Vote électronique (simulation)", "vote"),
                          ("🚀 Démarrer Serveur TCP", "start_server"),
                          ("🖥️ Démarrer Client TCP", "start_client"),
                          ("🛑 Arrêter Serveur", "stop_server")]:
            btn = ttk.Button(tp6, text=name, command=lambda v=val: self.network_action(v))
            btn.pack(fill=tk.X, padx=15, pady=3)
        
    def network_action(self, action):
        """Gère les actions réseau"""
        if action == "bluetooth":
            self.display_bluetooth_simulation()
        elif action == "wifi":
            self.display_wifi_simulation()
        elif action == "vote":
            self.display_vote_simulation()
        elif action == "start_server":
            self.start_server()
        elif action == "start_client":
            self.start_client()
        elif action == "stop_server":
            self.stop_server()
            
    def start_server(self):
        """Démarre le serveur TCP dans un nouveau terminal"""
        self.log("🚀 Démarrage du serveur TCP...")
        
        # Ouvrir un nouveau terminal pour le serveur
        if sys.platform == "win32":
            subprocess.Popen(["start", "cmd", "/c", "cd secure_Channel && python secure_server.py"], shell=True)
        else:
            # Linux/Mac
            subprocess.Popen(["gnome-terminal", "--", "bash", "-c", "cd secure_Channel && python secure_server.py; exec bash"])
        
        self.log("✅ Serveur démarré dans un nouveau terminal")
        self.log("   En attente de connexion sur port 65432...")
        
    def start_client(self):
        """Démarre le client TCP dans un nouveau terminal"""
        self.log("🖥️ Démarrage du client TCP...")
        
        if sys.platform == "win32":
            subprocess.Popen(["start", "cmd", "/c", "cd secure_Channel && python secure_client.py"], shell=True)
        else:
            subprocess.Popen(["gnome-terminal", "--", "bash", "-c", "cd secure_Channel && python secure_client.py; exec bash"])
        
        self.log("✅ Client démarré dans un nouveau terminal")
        
    def stop_server(self):
        """Arrête le serveur (par kill)"""
        self.log("🛑 Arrêt du serveur...")
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/f", "/im", "python.exe"])
        else:
            subprocess.run(["pkill", "-f", "secure_server.py"])
        self.log("✅ Serveur arrêté")
        
    def display_bluetooth_simulation(self):
        """Affiche la simulation Bluetooth"""
        result = """
🔵 SIMULATION BLUETOOTH SECURE

Protocole: Bluetooth Classic + LE Secure Connections

[Pairing] ECDH P-256
  → Smartphone (Central) ↔ Casque (Peripheral)
  → PIN: 123456
  → LTK (Long Term Key): a3f2c1e4b5d6...

[Chiffrement] AES-CCM
  → Message: "Bonjour, streaming audio"
  → Chiffré: 7f3a2b1c8e4d...

[BLE] Bluetooth Low Energy 4.2+
  → LE Secure Connections avec ECDH
  → Résistant aux attaques MITM

✅ Communication sécurisée établie
"""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(1.0, result)
        self.log("🔵 Simulation Bluetooth affichée")
        
    def display_wifi_simulation(self):
        """Affiche la simulation Wi-Fi"""
        result = """
📡 SIMULATION WPA2 4-WAY HANDSHAKE

SSID: WiFi_Secure
Password: ComplexPassword123

[Étape 1] PMK = PBKDF2(Password, SSID, 4096)
  → PMK: a3f2c1e4b5d6...

[Étape 2] ANonce (AP) → SNonce (Client)
  → ANonce: 7f3a2b1c...
  → SNonce: 8e4d5f6a...

[Étape 3] PTK = PRF(PMK + ANonce + SNonce + MACs)
  → KCK (Key Confirmation): 16 bytes
  → KEK (Key Encryption): 16 bytes
  → TEK (Temporal Key): 16 bytes

[Étape 4] GTK (Group Key) pour diffusion

✅ Chiffrement AES-CCMP activé
⚠️ WPA2 vulnérable KRACK (réinstallation clé)

WPA3 améliorations:
  → SAE (Dragonfly) au lieu de PSK
  → Forward Secrecy
  → Protection contre KRACK
"""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(1.0, result)
        self.log("📡 Simulation Wi-Fi affichée")
        
    def display_vote_simulation(self):
        """Affiche la simulation vote électronique"""
        result = """
🗳️ SIMULATION VOTE ÉLECTRONIQUE

Système: RSA 2048 + Signatures PSS

[Scrutin] Élection Présidentielle 2024
Candidats: Alice, Bob, Charlie

[Votants enregistrés]
  ✅ V001 - Jean Dupont (a voté Alice)
  ✅ V002 - Marie Martin (a voté Bob)
  ✅ V003 - Pierre Durand (a voté Alice)

[Dépouillement]
  Alice: 2 voix (66.7%)
  Bob: 1 voix (33.3%)
  Charlie: 0 voix (0.0%)

[Propriétés de sécurité]
  ✅ Confidentialité: RSA-OAEP
  ✅ Authenticité: Signature RSA-PSS
  ✅ Intégrité: Hash + Signature
  ✅ Anti-double vote: Base vérifiée
  ✅ Vérifiabilité: Journal d'audit

[Anomalies détectées]
  Double vote: Jean Dupont a tenté de voter deux fois → BLOQUÉ
  Votant non enregistré: ID V999 → REJETÉ

✅ Scrutin sécurisé - Auditable
"""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(1.0, result)
        self.log("🗳️ Simulation Vote électronique affichée")
        
    def create_io_panel(self, parent):
        # Input frame
        input_frame = ttk.LabelFrame(parent, text="📝 Entrée", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        btn_frame = tk.Frame(input_frame, bg='#1e1e2e')
        btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(btn_frame, text="📁 Charger", command=self.load_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🗑️ Effacer", command=self.clear_input).pack(side=tk.LEFT, padx=5)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, height=7, 
                                                     font=("Consolas", 10),
                                                     bg='#313244', fg='#cdd6f4',
                                                     insertbackground='#cdd6f4')
        self.input_text.pack(fill=tk.BOTH, expand=True)
        
        # Options
        opts_frame = tk.Frame(input_frame, bg='#1e1e2e')
        opts_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(opts_frame, text="Clé:").pack(side=tk.LEFT, padx=5)
        self.key_entry = ttk.Entry(opts_frame, width=25)
        self.key_entry.pack(side=tk.LEFT, padx=5)
        self.key_entry.insert(0, "secretkey123")
        
        # Mode
        mode_frame = tk.Frame(input_frame, bg='#1e1e2e')
        mode_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(mode_frame, text="Mode:").pack(side=tk.LEFT, padx=5)
        self.mode_var = tk.StringVar(value="encrypt")
        ttk.Radiobutton(mode_frame, text="Chiffrer", variable=self.mode_var,
                       value="encrypt").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="Déchiffrer", variable=self.mode_var,
                       value="decrypt").pack(side=tk.LEFT, padx=10)
        
        # Execute button
        self.execute_btn = ttk.Button(parent, text="▶ EXÉCUTER", command=self.execute, style='Success.TButton')
        self.execute_btn.pack(fill=tk.X, pady=10)
        
        # Output frame
        output_frame = ttk.LabelFrame(parent, text="📤 Sortie", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        btn_frame2 = tk.Frame(output_frame, bg='#1e1e2e')
        btn_frame2.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(btn_frame2, text="💾 Sauvegarder", command=self.save_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="📋 Copier", command=self.copy_output).pack(side=tk.LEFT, padx=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=7,
                                                      font=("Consolas", 10),
                                                      bg='#313244', fg='#cdd6f4',
                                                      insertbackground='#cdd6f4')
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
    def create_log_panel(self, parent):
        log_frame = ttk.LabelFrame(parent, text="📋 Journal", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15,
                                                   font=("Consolas", 9),
                                                   bg='#313244', fg='#cdd6f4',
                                                   insertbackground='#cdd6f4')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(log_frame, text="Effacer journal", command=self.clear_log).pack(pady=5)
        
    # ==================== ALGORITHMES ====================
    
    def cesar_encrypt(self, text, shift):
        result = ""
        for c in text:
            if c.isalpha():
                offset = ord('A') if c.isupper() else ord('a')
                result += chr((ord(c) - offset + shift) % 26 + offset)
            else:
                result += c
        return result
    
    def cesar_decrypt(self, text, shift):
        return self.cesar_encrypt(text, -shift)
    
    def vigenere_encrypt(self, text, key):
        result = ""
        key = key.upper()
        for i, c in enumerate(text):
            if c.isalpha():
                shift = ord(key[i % len(key)]) - ord('A')
                offset = ord('A') if c.isupper() else ord('a')
                result += chr((ord(c) - offset + shift) % 26 + offset)
            else:
                result += c
        return result
    
    def vigenere_decrypt(self, text, key):
        result = ""
        key = key.upper()
        for i, c in enumerate(text):
            if c.isalpha():
                shift = ord(key[i % len(key)]) - ord('A')
                offset = ord('A') if c.isupper() else ord('a')
                result += chr((ord(c) - offset - shift) % 26 + offset)
            else:
                result += c
        return result
    
    def rc4(self, data, key, mode):
        key_bytes = key.encode()
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
            S[i], S[j] = S[j], S[i]
        
        if mode == "encrypt":
            data_bytes = data.encode()
        else:
            data_bytes = bytes.fromhex(data)
        
        result = bytearray()
        i = j = 0
        for byte in data_bytes:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])
        
        if mode == "encrypt":
            return result.hex()
        else:
            return result.decode()
    
    def otp_encrypt(self, text):
        text_bytes = text.encode()
        key_bytes = os.urandom(len(text_bytes))
        cipher = bytes(t ^ k for t, k in zip(text_bytes, key_bytes))
        return cipher.hex(), key_bytes.hex()
    
    # ==================== EXÉCUTION ====================
    
    def execute(self):
        algo = self.algo_var.get()
        mode = self.mode_var.get()
        text = self.input_text.get(1.0, tk.END).strip()
        key = self.key_entry.get().strip()
        
        if not text:
            messagebox.showwarning("Attention", "Veuillez entrer un texte!")
            return
        
        self.status_var.set(f"⏳ Traitement... ({algo})")
        self.root.update()
        
        try:
            start = time.time()
            result = ""
            
            if algo == "cesar":
                shift = int(key) if key.isdigit() else 3
                if mode == "encrypt":
                    result = self.cesar_encrypt(text, shift)
                else:
                    result = self.cesar_decrypt(text, shift)
                    
            elif algo == "vigenere":
                if mode == "encrypt":
                    result = self.vigenere_encrypt(text, key)
                else:
                    result = self.vigenere_decrypt(text, key)
                    
            elif algo == "rc4":
                result = self.rc4(text, key, mode)
                
            elif algo == "aes":
                if mode == "encrypt":
                    result = hashlib.sha256((text + key).encode()).hexdigest()[:32]
                else:
                    result = "Déchiffrement AES simulé"
                    
            elif algo == "otp":
                if mode == "encrypt":
                    cipher, k = self.otp_encrypt(text)
                    result = f"Chiffré: {cipher}\nClé à partager: {k}"
                else:
                    result = "OTP: Entrez 'cipher:clé' au format hex"
                    
            elif algo == "md5":
                result = hashlib.md5(text.encode()).hexdigest()
            elif algo == "sha256":
                result = hashlib.sha256(text.encode()).hexdigest()
            elif algo == "sha512":
                result = hashlib.sha512(text.encode()).hexdigest()
            elif algo == "hmac":
                import hmac
                result = hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()
                
            else:
                result = f"⚠️ Algorithme {algo} - Utilisez l'onglet TP6 pour les simulations réseau"
                
            elapsed = (time.time() - start) * 1000
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, result)
            self.status_var.set(f"✅ Terminé en {elapsed:.2f} ms")
            self.log(f"{algo.upper()} - {mode} terminé en {elapsed:.2f} ms")
            
        except Exception as e:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, f"❌ Erreur: {str(e)}")
            self.status_var.set("❌ Erreur")
            self.log(f"Erreur: {str(e)}")
            messagebox.showerror("Erreur", str(e))
    
    # ==================== UTILITAIRES ====================
    
    def load_file(self):
        filename = filedialog.askopenfilename(
            title="Sélectionner un fichier",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            self.input_text.delete(1.0, tk.END)
            self.input_text.insert(1.0, content)
            self.log(f"📁 Fichier chargé: {os.path.basename(filename)}")
    
    def save_output(self):
        content = self.output_text.get(1.0, tk.END).strip()
        if content:
            filename = filedialog.asksaveasfilename(
                title="Sauvegarder",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.log(f"💾 Sauvegardé: {os.path.basename(filename)}")
    
    def copy_output(self):
        content = self.output_text.get(1.0, tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.log("📋 Copié dans le presse-papier")
    
    def clear_input(self):
        self.input_text.delete(1.0, tk.END)
        self.log("🗑️ Entrée effacée")
    
    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
    
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = CryptographyApp()
    app.run()
