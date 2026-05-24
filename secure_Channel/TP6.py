#!/usr/bin/env python3
"""
TP 6 — Application Sécurisée Complète
=======================================
Ex 6.1 : Sockets TCP  — RSA-OAEP (échange de clé) + AES-256-GCM (chiffrement)
Ex 6.2 : Bluetooth     — ECDH P-256 (pairing) + AES-GCM/CCM (données) + MITM
Ex 6.3 : UDP Chat      — ECDH P-256 (handshake) + AES-256-GCM (messages)
Ex 6.4 : Vote          — Paillier (homomorphique), anti-double-vote, dépouillement

Dépendances : pip install cryptography
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import os
import time
import random
from math import gcd
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# ═══════════════════════════════════════════════════════════
#  PAILLIER CRYPTOSYSTEM (textbook)
# ═══════════════════════════════════════════════════════════

def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def _modinv(a, m):
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("Pas d'inverse modulaire")
    return x % m

def _lcm(a, b):
    return a * b // gcd(a, b)

def _is_prime(n, k=20):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True

def _gen_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << bits - 1) | 1
        if _is_prime(n):
            return n

class Paillier:
    """Chiffrement homomorphique additif de Paillier (textbook)."""

    def __init__(self):
        self.pub = None   # (n, g)
        self.priv = None  # (lam, mu)

    def gen_keys(self, bits=512):
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        while q == p:
            q = _gen_prime(bits // 2)
        n = p * q
        n2 = n * n
        lam = _lcm(p - 1, q - 1)
        g = n + 1                         # choix simplifié
        gl = pow(g, lam, n2)
        l_gl = (gl - 1) // n
        mu = _modinv(l_gl, n)
        self.pub = (n, g)
        self.priv = (lam, mu)
        return self.pub, self.priv

    def encrypt(self, m):
        n, g = self.pub
        n2 = n * n
        while True:
            r = random.randrange(1, n)
            if gcd(r, n) == 1:
                break
        return (pow(g, m, n2) * pow(r, n, n2)) % n2

    def decrypt(self, c):
        lam, mu = self.priv
        n, _ = self.pub
        n2 = n * n
        l = (pow(c, lam, n2) - 1) // n
        return (l * mu) % n

    def hadd(self, c1, c2):
        """E(m1) · E(m2) mod n² = E(m1 + m2)   [homomorphic addition]"""
        n, _ = self.pub
        return (c1 * c2) % (n * n)

# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════

def _ecdh_keypair():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub  = priv.public_key()
    return priv, pub

def _ecdh_shared(priv, peer_pub_bytes):
    peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub_bytes)
    raw = priv.exchange(ECDH(), peer_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=None, info=b"TP6_AES",
                backend=default_backend()).derive(raw)

def _pub_bytes(pub_key):
    return pub_key.public_bytes(serialization.Encoding.X962,
                                serialization.PublicFormat.UncompressedPoint)

def _aes_enc(key, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

def _aes_dec(key, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)

def _send(sock, data: bytes):
    sock.sendall(len(data).to_bytes(4, 'big') + data)

def _recv(sock) -> bytes:
    raw = sock.recv(4)
    if not raw:
        raise ConnectionError("Connexion fermée")
    n = int.from_bytes(raw, 'big')
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée")
        buf += chunk
    return buf

# ═══════════════════════════════════════════════════════════
#  MAIN APP
# ═══════════════════════════════════════════════════════════

class TP6App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("TP 6 — Application Sécurisée Complète")
        self.root.geometry("1260x830")
        self.root.minsize(1100, 700)
        self.root.configure(bg='#1e1e2e')

        # State
        self.tcp_server_running  = False
        self.udp_server_running  = False
        self.tcp_client_sock     = None
        self.tcp_client_aes      = None
        self.udp_client_sock     = None
        self.udp_client_aes      = None
        self.udp_client_srv_addr = None

        self.paillier = Paillier()
        self.voters   = {}         # vid -> {name, voted}
        self.enc_tally = {}        # candidate -> cumul chiffré
        self.candidates = ["Alice", "Bob", "Charlie"]

        self._setup_styles()
        self._setup_ui()

    # ── Styles ───────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use('clam')
        bg, fg, acc = '#1e1e2e', '#cdd6f4', '#89b4fa'
        surf = '#313244'
        s.configure('TNotebook',         background=bg, borderwidth=0)
        s.configure('TNotebook.Tab',     background=surf, foreground=fg, padding=[12, 5])
        s.map('TNotebook.Tab',
              background=[('selected', acc)],
              foreground=[('selected', bg)])
        s.configure('TFrame',            background=bg)
        s.configure('TLabel',            background=bg, foreground=fg)
        s.configure('TLabelframe',       background=bg, foreground=acc)
        s.configure('TLabelframe.Label', background=bg, foreground=acc,
                    font=('Helvetica', 10, 'bold'))
        s.configure('TButton',           background=surf, foreground=fg)
        s.map('TButton', background=[('active', '#45475a')])
        s.configure('G.TButton', background='#a6e3a1', foreground=bg)
        s.configure('R.TButton', background='#f38ba8', foreground=bg)
        s.configure('Y.TButton', background='#f9e2af', foreground=bg)
        s.configure('TEntry',    fieldbackground=surf, foreground=fg,
                    insertcolor=fg)
        s.configure('TCombobox', fieldbackground=surf, foreground=fg)
        s.configure('TRadiobutton', background=bg, foreground=fg)

    # ── Root UI ──────────────────────────────────────────
    def _setup_ui(self):
        hdr = tk.Frame(self.root, bg='#181825', pady=8)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="🔐 TP 6 — Application Sécurisée Complète",
                 font=('Helvetica', 17, 'bold'),
                 bg='#181825', fg='#89b4fa').pack(side=tk.LEFT, padx=20)
        tk.Label(hdr, text="TCP · Bluetooth · UDP · Vote Homomorphique",
                 font=('Helvetica', 10), bg='#181825', fg='#a6adc8').pack(side=tk.LEFT)

        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        t1 = ttk.Frame(nb); nb.add(t1, text="📡  6.1 — TCP Sécurisé")
        t2 = ttk.Frame(nb); nb.add(t2, text="🔵  6.2 — Bluetooth")
        t3 = ttk.Frame(nb); nb.add(t3, text="📶  6.3 — UDP Chat")
        t4 = ttk.Frame(nb); nb.add(t4, text="🗳️  6.4 — Vote Homomorphique")

        self._build_tcp(t1)
        self._build_bt(t2)
        self._build_udp(t3)
        self._build_vote(t4)

        self.status_var = tk.StringVar(value="✅ Prêt")
        tk.Label(self.root, textvariable=self.status_var,
                 bg='#313244', fg='#a6e3a1',
                 font=('Consolas', 9), anchor=tk.W,
                 padx=10, pady=3).pack(fill=tk.X, side=tk.BOTTOM)

    # ────────────────────────────────────────────────────────────────
    #  WIDGET HELPERS
    # ────────────────────────────────────────────────────────────────
    def _make_log(self, parent, height=18):
        log = scrolledtext.ScrolledText(
            parent, height=height, font=('Consolas', 9),
            bg='#181825', fg='#cdd6f4', wrap=tk.WORD, state=tk.DISABLED)
        log.pack(fill=tk.BOTH, expand=True, pady=4)
        return log

    def _log(self, widget, msg, tag=None):
        """Thread-safe log append."""
        def _w():
            widget.config(state=tk.NORMAL)
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            widget.insert(tk.END, f"[{ts}]  {msg}\n")
            widget.see(tk.END)
            widget.config(state=tk.DISABLED)
        self.root.after(0, _w)

    def _set_status(self, msg):
        self.root.after(0, lambda: self.status_var.set(msg))

    # ════════════════════════════════════════════════════════════════
    #  EXERCICE 6.1 — TCP SÉCURISÉ
    #    1. Serveur génère RSA-2048 → envoie clé publique PEM
    #    2. Client génère AES-256 → chiffre avec RSA-OAEP → envoie
    #    3. Les deux utilisent AES-256-GCM pour tous les messages
    # ════════════════════════════════════════════════════════════════
    def _build_tcp(self, parent):
        pw = tk.PanedWindow(parent, orient=tk.HORIZONTAL,
                            bg='#1e1e2e', sashwidth=5, sashrelief=tk.FLAT)
        pw.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # ── Serveur ─────────────────────────────────
        sf = ttk.LabelFrame(pw, text="🖥️  Serveur — Alice", padding=8)
        pw.add(sf, width=580)

        sc = tk.Frame(sf, bg='#1e1e2e'); sc.pack(fill=tk.X, pady=4)
        ttk.Label(sc, text="Port:").pack(side=tk.LEFT)
        self.tcp_srv_port = tk.StringVar(value="65432")
        ttk.Entry(sc, textvariable=self.tcp_srv_port, width=7).pack(side=tk.LEFT, padx=4)
        self.btn_tcp_start = ttk.Button(sc, text="▶ Démarrer Serveur",
                                         style='G.TButton',
                                         command=self.tcp_start_server)
        self.btn_tcp_start.pack(side=tk.LEFT, padx=6)
        self.btn_tcp_stop = ttk.Button(sc, text="⏹ Arrêter", style='R.TButton',
                                        command=self.tcp_stop_server, state=tk.DISABLED)
        self.btn_tcp_stop.pack(side=tk.LEFT)
        self.tcp_srv_log = self._make_log(sf)

        # ── Client ──────────────────────────────────
        cf = ttk.LabelFrame(pw, text="💻  Client — Bob", padding=8)
        pw.add(cf, width=580)

        cc = tk.Frame(cf, bg='#1e1e2e'); cc.pack(fill=tk.X, pady=4)
        ttk.Label(cc, text="Host:").pack(side=tk.LEFT)
        self.tcp_cli_host = tk.StringVar(value="127.0.0.1")
        ttk.Entry(cc, textvariable=self.tcp_cli_host, width=14).pack(side=tk.LEFT, padx=4)
        ttk.Label(cc, text="Port:").pack(side=tk.LEFT)
        self.tcp_cli_port = tk.StringVar(value="65432")
        ttk.Entry(cc, textvariable=self.tcp_cli_port, width=7).pack(side=tk.LEFT, padx=4)
        ttk.Button(cc, text="🔗 Connecter + Handshake RSA",
                   command=self.tcp_connect).pack(side=tk.LEFT, padx=6)

        mc = tk.Frame(cf, bg='#1e1e2e'); mc.pack(fill=tk.X, pady=4)
        self.tcp_msg_var = tk.StringVar(value="Bonjour Alice, message sécurisé !")
        ttk.Entry(mc, textvariable=self.tcp_msg_var, width=38).pack(side=tk.LEFT, padx=4)
        ttk.Button(mc, text="📨 Envoyer (AES-256-GCM)",
                   command=self.tcp_send).pack(side=tk.LEFT)

        self.tcp_cli_log = self._make_log(cf)

    # ── TCP Server ──────────────────────────────────
    def tcp_start_server(self):
        port = int(self.tcp_srv_port.get())
        self.tcp_server_running = True
        self.btn_tcp_start.config(state=tk.DISABLED)
        self.btn_tcp_stop.config(state=tk.NORMAL)
        self._set_status(f"🟢 Serveur TCP en écoute :{port}")
        threading.Thread(target=self._tcp_server, args=(port,), daemon=True).start()

    def _tcp_server(self, port):
        log = self.tcp_srv_log
        self._log(log, f"🚀 Serveur TCP démarré sur :{port}")
        self._log(log, "🔑 Génération des clés RSA-2048 …")

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                         backend=default_backend())
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

        self._log(log, f"✅ RSA-2048 prêt (n = {hex(priv.public_key().public_numbers().n)[:30]}…)")
        self._log(log, "⏳ En attente d'une connexion …")

        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(('0.0.0.0', port))
            srv.listen(1)
            srv.settimeout(120)
            self._tcp_srv_sock = srv

            conn, addr = srv.accept()
            self._log(log, f"🔗 Connexion de {addr}")

            # ── Handshake ──────────────────────────
            # 1. Envoyer clé publique RSA
            _send(conn, pub_pem)
            self._log(log, "📤 Clé publique RSA envoyée")

            # 2. Recevoir AES-256 chiffrée avec RSA-OAEP
            enc_aes = _recv(conn)
            aes_key = priv.decrypt(
                enc_aes,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None))
            self._log(log, f"🔑 Clé AES-256 reçue & déchiffrée : {aes_key.hex()[:32]}…")
            self._log(log, "✅ Canal sécurisé établi — AES-256-GCM actif\n")

            conn.settimeout(5)
            aesgcm = AESGCM(aes_key)
            while self.tcp_server_running:
                try:
                    blob = _recv(conn)
                    pt = _aes_dec(aes_key, blob)
                    self._log(log, f"📨 Chiffré  : {blob[:20].hex()}… ({len(blob)} o)")
                    self._log(log, f"🔓 Clair    : « {pt.decode()} »")
                    # ACK
                    ack = f"✅ Message reçu et authentifié".encode()
                    _send(conn, _aes_enc(aes_key, ack))
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.tcp_server_running:
                        self._log(log, f"⚠️  {e}")
                    break

            conn.close()
            srv.close()
        except Exception as e:
            if self.tcp_server_running:
                self._log(log, f"❌ {e}")
        self._log(log, "🔴 Serveur arrêté")

    def tcp_stop_server(self):
        self.tcp_server_running = False
        self.btn_tcp_start.config(state=tk.NORMAL)
        self.btn_tcp_stop.config(state=tk.DISABLED)
        try:
            self._tcp_srv_sock.close()
        except Exception:
            pass

    # ── TCP Client ──────────────────────────────────
    def tcp_connect(self):
        host = self.tcp_cli_host.get()
        port = int(self.tcp_cli_port.get())
        threading.Thread(target=self._tcp_client_handshake,
                         args=(host, port), daemon=True).start()

    def _tcp_client_handshake(self, host, port):
        log = self.tcp_cli_log
        try:
            self._log(log, f"🔗 Connexion vers {host}:{port} …")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            self.tcp_client_sock = s
            self._log(log, "✅ Connecté")

            # 1. Recevoir clé publique RSA
            pub_pem = _recv(s)
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            pub_key = load_pem_public_key(pub_pem, backend=default_backend())
            self._log(log, f"📥 Clé publique RSA reçue :")
            self._log(log, f"   {pub_pem.decode().splitlines()[1][:60]}…")

            # 2. Générer AES-256, chiffrer avec RSA-OAEP, envoyer
            aes_key = os.urandom(32)
            enc_aes = pub_key.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None))
            _send(s, enc_aes)
            self._log(log, f"🔑 Clé AES-256 : {aes_key.hex()[:32]}…")
            self._log(log, f"📤 Clé AES chiffrée RSA-OAEP envoyée ({len(enc_aes)} o)")
            self._log(log, "✅ Canal sécurisé établi — AES-256-GCM actif\n")

            self.tcp_client_aes = aes_key
            self._set_status("✅ TCP connecté — AES-256-GCM actif")

            # Écouter les ACK
            s.settimeout(60)
            while True:
                try:
                    blob = _recv(s)
                    pt = _aes_dec(aes_key, blob)
                    self._log(log, f"✉️  Serveur : {pt.decode()}")
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as e:
            self._log(log, f"❌ {e}")

    def tcp_send(self):
        if not self.tcp_client_aes or not self.tcp_client_sock:
            messagebox.showwarning("Attention", "Connectez-vous d'abord !")
            return
        msg = self.tcp_msg_var.get()
        blob = _aes_enc(self.tcp_client_aes, msg.encode())
        self._log(self.tcp_cli_log, f"📤 Envoi  : « {msg} »")
        self._log(self.tcp_cli_log, f"   Chiffré : {blob[:20].hex()}… ({len(blob)} o)")
        try:
            _send(self.tcp_client_sock, blob)
        except Exception as e:
            self._log(self.tcp_cli_log, f"❌ {e}")

    # ════════════════════════════════════════════════════════════════
    #  EXERCICE 6.2 — BLUETOOTH
    #    ECDH P-256 → LTK via HKDF → AES-128-GCM (≈ AES-CCM)
    # ════════════════════════════════════════════════════════════════
    def _build_bt(self, parent):
        info = ttk.LabelFrame(parent, text="ℹ️  Protocole Bluetooth Secure Simple Pairing (SSP)", padding=8)
        info.pack(fill=tk.X, padx=10, pady=6)
        tk.Label(info,
                 text=("Bluetooth 4.2+ LE Secure Connections : ECDH P-256 pour l'échange de clés\n"
                       "puis AES-CCM 128 bits pour le chiffrement + MIC d'intégrité.\n"
                       "Le Numeric Comparison bloque les attaques MITM passives."),
                 justify=tk.LEFT, bg='#1e1e2e', fg='#a6adc8',
                 font=('Helvetica', 10)).pack(anchor=tk.W)

        ctrl = ttk.LabelFrame(parent, text="🎛️  Simulation", padding=10)
        ctrl.pack(fill=tk.X, padx=10, pady=4)

        r1 = tk.Frame(ctrl, bg='#1e1e2e'); r1.pack(fill=tk.X)
        ttk.Label(r1, text="Appareil A :").pack(side=tk.LEFT, padx=4)
        self.bt_dev_a = tk.StringVar(value="Samsung Galaxy S24")
        ttk.Entry(r1, textvariable=self.bt_dev_a, width=22).pack(side=tk.LEFT)
        ttk.Label(r1, text="  Appareil B :").pack(side=tk.LEFT, padx=10)
        self.bt_dev_b = tk.StringVar(value="Sony WH-1000XM5")
        ttk.Entry(r1, textvariable=self.bt_dev_b, width=22).pack(side=tk.LEFT)

        r2 = tk.Frame(ctrl, bg='#1e1e2e'); r2.pack(fill=tk.X, pady=4)
        ttk.Label(r2, text="Message :").pack(side=tk.LEFT, padx=4)
        self.bt_msg = tk.StringVar(value="Streaming audio LDAC 24 bit/96 kHz")
        ttk.Entry(r2, textvariable=self.bt_msg, width=46).pack(side=tk.LEFT)

        r3 = tk.Frame(ctrl, bg='#1e1e2e'); r3.pack(fill=tk.X, pady=4)
        ttk.Button(r3, text="🔵 Pairing ECDH",
                   command=self.bt_pairing).pack(side=tk.LEFT, padx=4)
        ttk.Button(r3, text="🔒 Chiffrer (AES-CCM)",
                   command=self.bt_encrypt).pack(side=tk.LEFT, padx=4)
        ttk.Button(r3, text="⚠️ Attaque MITM",
                   command=self.bt_mitm).pack(side=tk.LEFT, padx=4)
        ttk.Button(r3, text="🗑️ Effacer",
                   command=self._clear_bt_log).pack(side=tk.LEFT, padx=4)

        self.bt_log = self._make_log(parent, height=22)
        self.bt_ltk = None

    def _clear_bt_log(self):
        self.bt_log.config(state=tk.NORMAL)
        self.bt_log.delete(1.0, tk.END)
        self.bt_log.config(state=tk.DISABLED)

    def bt_pairing(self):
        a, b = self.bt_dev_a.get(), self.bt_dev_b.get()
        threading.Thread(target=self._bt_pairing_thread, args=(a, b), daemon=True).start()

    def _bt_pairing_thread(self, a, b):
        log = self.bt_log
        sep = "━" * 52

        def L(m): self._log(log, m)

        L(sep)
        L("🔵  BLUETOOTH SECURE SIMPLE PAIRING — ECDH P-256")
        L(sep)
        L(f"  A : {a}    B : {b}")
        L("")
        time.sleep(0.2)

        # PHASE 1 — Capabilities
        L("┌─ PHASE 1 : Échange de capacités ─────────────────")
        L(f"  {a} → DisplayYesNo")
        L(f"  {b} → NoInputNoOutput")
        L("  Mode sélectionné : Just Works (pas de PIN)")
        time.sleep(0.3)

        # PHASE 2 — ECDH
        L("")
        L("┌─ PHASE 2 : Génération des clés ECDH P-256 ───────")
        priv_a, pub_a = _ecdh_keypair()
        priv_b, pub_b = _ecdh_keypair()
        pb_a = _pub_bytes(pub_a)
        pb_b = _pub_bytes(pub_b)
        L(f"  PKa = {pb_a.hex()[:48]}…")
        time.sleep(0.2)
        L(f"  PKb = {pb_b.hex()[:48]}…")
        time.sleep(0.3)

        # PHASE 3 — Secret partagé
        L("")
        L("┌─ PHASE 3 : Secret partagé DHKey ─────────────────")
        sh_a = priv_a.exchange(ECDH(), pub_b)
        sh_b = priv_b.exchange(ECDH(), pub_a)
        L(f"  DHKey_A = ska × PKb = {sh_a.hex()[:40]}…")
        L(f"  DHKey_B = skb × PKa = {sh_b.hex()[:40]}…")
        L(f"  Identiques : {'✅ OUI' if sh_a == sh_b else '❌ NON'}")
        time.sleep(0.3)

        # PHASE 4 — LTK via HKDF
        L("")
        L("┌─ PHASE 4 : Dérivation LTK (HKDF-SHA256) ─────────")
        ltk = HKDF(algorithm=hashes.SHA256(), length=16,
                   salt=None, info=b"BT_LTK",
                   backend=default_backend()).derive(sh_a)
        L(f"  LTK = {ltk.hex()}")
        L(f"  Chiffrement : AES-CCM 128 bits")
        L(f"  Intégrité   : MIC 64 bits")
        time.sleep(0.2)

        L("")
        L("✅ Pairing terminé — Lien Bluetooth sécurisé établi")
        self.bt_ltk = ltk

    def bt_encrypt(self):
        if not self.bt_ltk:
            messagebox.showwarning("Attention", "Effectuez d'abord le Pairing !")
            return
        msg = self.bt_msg.get()
        log = self.bt_log
        self._log(log, "")
        self._log(log, "┌─ CHIFFREMENT AES-CCM (simulé par AES-GCM) ────────")
        self._log(log, f"  Clair   : « {msg} »")
        blob = _aes_enc(self.bt_ltk + self.bt_ltk, msg.encode())  # 32-byte key from 16-byte LTK
        self._log(log, f"  Nonce   : {blob[:12].hex()}")
        self._log(log, f"  Chiffré : {blob[12:].hex()[:40]}…")
        self._log(log, f"  MIC     : {blob[-4:].hex()}  (4 derniers octets du tag GCM)")
        pt = _aes_dec(self.bt_ltk + self.bt_ltk, blob)
        self._log(log, f"  Déchiffré : « {pt.decode()} »  ✅ MIC vérifié")

    def bt_mitm(self):
        a, b = self.bt_dev_a.get(), self.bt_dev_b.get()
        log = self.bt_log
        threading.Thread(target=self._bt_mitm_thread, args=(a, b, log), daemon=True).start()

    def _bt_mitm_thread(self, a, b, log):
        def L(m): self._log(log, m)
        L("")
        L("━" * 52)
        L("⚠️   SIMULATION ATTAQUE MITM BLUETOOTH")
        L("━" * 52)
        L(f"  Eve intercepte la liaison {a} ↔ {b}")
        time.sleep(0.3)
        L("")
        L("  [A → Eve]  PKa interceptée")
        L("  [Eve → B]  PKeve_AB envoyée à la place de PKa")
        L("  [B → Eve]  PKb interceptée")
        L("  [Eve → A]  PKeve_BA envoyée à la place de PKb")
        time.sleep(0.3)
        L("")
        L("  Eve établit :")
        L("    DHKey_AE = sk_eve × PKa  (session avec A)")
        L("    DHKey_BE = sk_eve × PKb  (session avec B)")
        L("  → Eve déchiffre, ré-chiffre chaque paquet !")
        time.sleep(0.3)
        L("")
        L("┌─ CONTRE-MESURE — Numeric Comparison ──────────────")
        pin_a = random.randint(0, 999999)
        pin_e = random.randint(0, 999999)
        L(f"  Code affiché sur {a} : {pin_a:06d}")
        L(f"  Code forgé par Eve  : {pin_e:06d}")
        match = pin_a == pin_e
        L(f"  Correspondance : {'✅ (attaque ratée — 1 chance sur 10⁶)' if not match else '❌ (collision accidentelle rare)'}")
        L(f"  → L'utilisateur voit des codes différents et REFUSE  ✅")
        L("✅ MITM bloqué par Numeric Comparison")

    # ════════════════════════════════════════════════════════════════
    #  EXERCICE 6.3 — UDP CHAT SÉCURISÉ
    #  Protocole : ECDH P-256 one-shot handshake → AES-256-GCM
    # ════════════════════════════════════════════════════════════════
    def _build_udp(self, parent):
        pw = tk.PanedWindow(parent, orient=tk.HORIZONTAL,
                            bg='#1e1e2e', sashwidth=5)
        pw.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Serveur
        sf = ttk.LabelFrame(pw, text="🖥️  Serveur UDP — Alice", padding=8)
        pw.add(sf, width=560)

        sc = tk.Frame(sf, bg='#1e1e2e'); sc.pack(fill=tk.X, pady=4)
        ttk.Label(sc, text="Port:").pack(side=tk.LEFT)
        self.udp_srv_port = tk.StringVar(value="65433")
        ttk.Entry(sc, textvariable=self.udp_srv_port, width=7).pack(side=tk.LEFT, padx=4)
        self.btn_udp_start = ttk.Button(sc, text="▶ Démarrer", style='G.TButton',
                                         command=self.udp_start_server)
        self.btn_udp_start.pack(side=tk.LEFT, padx=5)
        self.btn_udp_stop = ttk.Button(sc, text="⏹ Arrêter", style='R.TButton',
                                        command=self.udp_stop_server, state=tk.DISABLED)
        self.btn_udp_stop.pack(side=tk.LEFT)
        self.udp_srv_log = self._make_log(sf)

        # Client
        cf = ttk.LabelFrame(pw, text="💻  Client UDP — Bob", padding=8)
        pw.add(cf, width=560)

        cc = tk.Frame(cf, bg='#1e1e2e'); cc.pack(fill=tk.X, pady=4)
        ttk.Label(cc, text="Host:").pack(side=tk.LEFT)
        self.udp_cli_host = tk.StringVar(value="127.0.0.1")
        ttk.Entry(cc, textvariable=self.udp_cli_host, width=14).pack(side=tk.LEFT, padx=4)
        ttk.Label(cc, text="Port:").pack(side=tk.LEFT)
        self.udp_cli_port = tk.StringVar(value="65433")
        ttk.Entry(cc, textvariable=self.udp_cli_port, width=7).pack(side=tk.LEFT, padx=4)
        ttk.Button(cc, text="🤝 Handshake ECDH",
                   command=self.udp_handshake).pack(side=tk.LEFT, padx=5)

        mc = tk.Frame(cf, bg='#1e1e2e'); mc.pack(fill=tk.X, pady=4)
        self.udp_msg_var = tk.StringVar(value="Salut Alice, datagramme UDP chiffré !")
        ttk.Entry(mc, textvariable=self.udp_msg_var, width=36).pack(side=tk.LEFT, padx=4)
        ttk.Button(mc, text="📨 Envoyer",
                   command=self.udp_send).pack(side=tk.LEFT)
        self.udp_cli_log = self._make_log(cf)

    # ── UDP Server ──────────────────────────────────
    def udp_start_server(self):
        port = int(self.udp_srv_port.get())
        self.udp_server_running = True
        self.btn_udp_start.config(state=tk.DISABLED)
        self.btn_udp_stop.config(state=tk.NORMAL)
        self._set_status(f"🟢 Serveur UDP en écoute :{port}")
        threading.Thread(target=self._udp_server, args=(port,), daemon=True).start()

    def _udp_server(self, port):
        log = self.udp_srv_log
        self._log(log, f"🚀 Serveur UDP démarré sur :{port}")
        self._log(log, "🔑 Génération des clés ECDH P-256 …")

        priv, pub = _ecdh_keypair()
        pb = _pub_bytes(pub)
        self._log(log, f"   PKserver = {pb.hex()[:48]}…")
        self._log(log, "⏳ En attente du handshake …")

        srv_aes = {}  # addr -> aes_key
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(('0.0.0.0', port))
            s.settimeout(1)
            self._udp_srv_sock = s

            while self.udp_server_running:
                try:
                    data, addr = s.recvfrom(4096)
                except socket.timeout:
                    continue

                if data[:6] == b'HELLO:':
                    client_pb = data[6:]
                    aes = _ecdh_shared(priv, client_pb)
                    srv_aes[addr] = aes
                    s.sendto(b'HELLO:' + pb, addr)
                    self._log(log, f"🤝 Handshake ECDH avec {addr}")
                    self._log(log, f"   AES-256 = {aes.hex()[:32]}…")
                    self._log(log, "✅ Canal sécurisé UDP — AES-256-GCM actif")

                elif data[:4] == b'MSG:' and addr in srv_aes:
                    blob = data[4:]
                    try:
                        pt = _aes_dec(srv_aes[addr], blob)
                        self._log(log, f"📨 De {addr} (chiffré) : {blob[:16].hex()}…")
                        self._log(log, f"🔓 Clair : « {pt.decode()} »")
                        ack = _aes_enc(srv_aes[addr], "ACK ✅ reçu et vérifié".encode())
                        s.sendto(b'ACK:' + ack, addr)
                    except Exception as e:
                        self._log(log, f"⚠️  Déchiffrement échoué : {e}")

            s.close()
        except Exception as e:
            if self.udp_server_running:
                self._log(log, f"❌ {e}")
        self._log(log, "🔴 Serveur UDP arrêté")

    def udp_stop_server(self):
        self.udp_server_running = False
        self.btn_udp_start.config(state=tk.NORMAL)
        self.btn_udp_stop.config(state=tk.DISABLED)
        try:
            self._udp_srv_sock.close()
        except Exception:
            pass

    # ── UDP Client ──────────────────────────────────
    def udp_handshake(self):
        host = self.udp_cli_host.get()
        port = int(self.udp_cli_port.get())
        threading.Thread(target=self._udp_handshake, args=(host, port), daemon=True).start()

    def _udp_handshake(self, host, port):
        log = self.udp_cli_log
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            self.udp_client_sock = s
            self.udp_client_srv_addr = (host, port)

            priv, pub = _ecdh_keypair()
            pb = _pub_bytes(pub)
            self._log(log, f"🤝 Handshake ECDH → {host}:{port}")
            self._log(log, f"   PKclient = {pb.hex()[:48]}…")

            s.sendto(b'HELLO:' + pb, (host, port))
            data, _ = s.recvfrom(4096)

            if data[:6] == b'HELLO:':
                srv_pb = data[6:]
                aes = _ecdh_shared(priv, srv_pb)
                self.udp_client_aes = aes
                self._log(log, f"   PKserver = {srv_pb.hex()[:48]}…")
                self._log(log, f"   AES-256  = {aes.hex()[:32]}…")
                self._log(log, "✅ Canal sécurisé UDP — AES-256-GCM actif")
                self._set_status("✅ UDP connecté — AES-256-GCM actif")

            # Écouter ACK
            s.settimeout(60)
            while True:
                try:
                    data, _ = s.recvfrom(4096)
                    if data[:4] == b'ACK:':
                        pt = _aes_dec(self.udp_client_aes, data[4:])
                        self._log(log, f"✉️  Serveur : {pt.decode()}")
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as e:
            self._log(log, f"❌ {e}")

    def udp_send(self):
        if not self.udp_client_aes:
            messagebox.showwarning("Attention", "Effectuez d'abord le Handshake ECDH !")
            return
        msg = self.udp_msg_var.get()
        blob = _aes_enc(self.udp_client_aes, msg.encode())
        self._log(self.udp_cli_log, f"📤 Envoi  : « {msg} »")
        self._log(self.udp_cli_log,
                  f"   Chiffré : {blob[:16].hex()}…  ({len(blob)} octets)")
        try:
            self.udp_client_sock.sendto(b'MSG:' + blob, self.udp_client_srv_addr)
        except Exception as e:
            self._log(self.udp_cli_log, f"❌ {e}")

    # ════════════════════════════════════════════════════════════════
    #  EXERCICE 6.4 — VOTE ÉLECTRONIQUE HOMOMORPHIQUE (PAILLIER)
    #  Propriété : E(m1) · E(m2) = E(m1 + m2) mod n²
    #  Garanties : confidentialité, intégrité, anti-double-vote,
    # ════════════════════════════════════════════════════════════════
    def _build_vote(self, parent):
        main = tk.Frame(parent, bg='#1e1e2e')
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # ── Colonne gauche : config + vote ──────────
        left = tk.Frame(main, bg='#1e1e2e')
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        # Config Paillier
        kg = ttk.LabelFrame(left, text="🔑  Clés Paillier", padding=8)
        kg.pack(fill=tk.X)

        kf = tk.Frame(kg, bg='#1e1e2e'); kf.pack(fill=tk.X)
        ttk.Label(kf, text="Taille (bits) :").pack(side=tk.LEFT)
        self.paillier_bits = tk.StringVar(value="512")
        ttk.Combobox(kf, textvariable=self.paillier_bits,
                     values=["256", "512", "1024"],
                     width=6, state='readonly').pack(side=tk.LEFT, padx=4)
        ttk.Button(kf, text="⚙️ Générer",
                   command=self.vote_gen_keys).pack(side=tk.LEFT, padx=8)

        self.vote_key_info = tk.Label(
            kg, text="⚠️  Clés non générées",
            bg='#1e1e2e', fg='#f38ba8',
            font=('Consolas', 9), justify=tk.LEFT, anchor=tk.W)
        self.vote_key_info.pack(fill=tk.X, padx=4, pady=3)

        # Enregistrement votants
        vr = ttk.LabelFrame(left, text="👤  Registre des votants", padding=8)
        vr.pack(fill=tk.X, pady=5)

        vrf = tk.Frame(vr, bg='#1e1e2e'); vrf.pack(fill=tk.X)
        ttk.Label(vrf, text="ID:").pack(side=tk.LEFT)
        self.new_vid = ttk.Entry(vrf, width=8); self.new_vid.insert(0, "V005")
        self.new_vid.pack(side=tk.LEFT, padx=4)
        ttk.Label(vrf, text="Nom:").pack(side=tk.LEFT)
        self.new_vname = ttk.Entry(vrf, width=18); self.new_vname.insert(0, "Nouveau Votant")
        self.new_vname.pack(side=tk.LEFT, padx=4)
        ttk.Button(vrf, text="➕ Enregistrer",
                   command=self.register_voter).pack(side=tk.LEFT, padx=4)

        self.voter_lb = tk.Listbox(vr, height=6, bg='#181825',
                                   fg='#a6e3a1', font=('Consolas', 9),
                                   selectmode=tk.SINGLE)
        self.voter_lb.pack(fill=tk.X, pady=3)

        # Pré-enregistrer 4 votants
        for vid, name in [("V001", "Jean Dupont"), ("V002", "Marie Martin"),
                           ("V003", "Pierre Durand"), ("V004", "Sophie Bernard")]:
            self.voters[vid] = {"name": name, "voted": False}
            self.voter_lb.insert(tk.END, f"  {vid} — {name}")

        # Voter
        vv = ttk.LabelFrame(left, text="🗳️  Voter", padding=8)
        vv.pack(fill=tk.X, pady=5)

        vf1 = tk.Frame(vv, bg='#1e1e2e'); vf1.pack(fill=tk.X)
        ttk.Label(vf1, text="Mon ID :").pack(side=tk.LEFT)
        self.my_vid = ttk.Entry(vf1, width=8); self.my_vid.insert(0, "V001")
        self.my_vid.pack(side=tk.LEFT, padx=4)
        ttk.Label(vf1, text="Candidat :").pack(side=tk.LEFT, padx=8)
        self.vote_for = tk.StringVar(value="Alice")
        for c in self.candidates:
            ttk.Radiobutton(vf1, text=c, variable=self.vote_for,
                            value=c).pack(side=tk.LEFT, padx=4)

        vf2 = tk.Frame(vv, bg='#1e1e2e'); vf2.pack(fill=tk.X, pady=4)
        ttk.Button(vf2, text="🗳️ Voter (Paillier)", style='G.TButton',
                   command=self.cast_vote).pack(side=tk.LEFT, padx=4)
        ttk.Button(vf2, text="⚠️ Double vote (test)",
                   command=self.double_vote_test).pack(side=tk.LEFT, padx=4)

        # ── Colonne droite : dépouillement ──────────
        right = tk.Frame(main, bg='#1e1e2e')
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0))

        dep = ttk.LabelFrame(right, text="📊  Dépouillement homomorphique", padding=8)
        dep.pack(fill=tk.X)

        df = tk.Frame(dep, bg='#1e1e2e'); df.pack(fill=tk.X)
        ttk.Button(df, text="🔢 Cumuler (sans déchiffrer)",
                   style='Y.TButton',
                   command=self.tally_votes).pack(side=tk.LEFT, padx=4)
        ttk.Button(df, text="🔓 Révéler résultats",
                   style='G.TButton',
                   command=self.reveal_results).pack(side=tk.LEFT, padx=4)
        ttk.Button(df, text="🔄 Réinitialiser",
                   command=self.reset_vote).pack(side=tk.LEFT, padx=4)

        self.result_label = tk.Label(
            dep, text="En attente du dépouillement …",
            bg='#1e1e2e', fg='#cdd6f4',
            font=('Consolas', 10), justify=tk.LEFT, anchor=tk.W)
        self.result_label.pack(fill=tk.X, padx=4, pady=4)

        self.vote_log = self._make_log(right, height=24)

        # Init tallies
        self.enc_tally = {c: None for c in self.candidates}

        self._log(self.vote_log, "⚙️  Système de vote Paillier initialisé")
        self._log(self.vote_log, "   Propriété homomorphique : E(a)·E(b) = E(a+b) mod n²")
        self._log(self.vote_log, "👤  4 votants pré-enregistrés : V001–V004")
        self._log(self.vote_log, "📌  Générez les clés Paillier pour commencer")

    def vote_gen_keys(self):
        bits = int(self.paillier_bits.get())

        def _run():
            self._log(self.vote_log, f"⚙️  Génération Paillier-{bits} …")
            self.vote_key_info.config(text=f"⏳ Génération Paillier-{bits} …", fg='#f9e2af')
            t0 = time.time()
            self.paillier.gen_keys(bits)
            elapsed = time.time() - t0
            n, g = self.paillier.pub
            lam, mu = self.paillier.priv
            info = (f"✅ Paillier-{bits} ({elapsed:.2f} s)\n"
                    f"   n = {hex(n)[:36]}…\n"
                    f"   g = n+1\n"
                    f"   λ = {hex(lam)[:36]}…")
            self.vote_key_info.config(text=info, fg='#a6e3a1')
            self._log(self.vote_log, f"✅ Paillier-{bits} généré en {elapsed:.2f} s")
            self._log(self.vote_log, f"   Clé publique n = {hex(n)[:48]}…")
            self._log(self.vote_log, "   Homomorphisme : E(m1)·E(m2) mod n² = E(m1+m2)")
            self.enc_tally = {c: None for c in self.candidates}

        threading.Thread(target=_run, daemon=True).start()

    def register_voter(self):
        vid  = self.new_vid.get().strip()
        name = self.new_vname.get().strip()
        if vid and name:
            self.voters[vid] = {"name": name, "voted": False}
            self.voter_lb.insert(tk.END, f"  {vid} — {name}")
            self._log(self.vote_log, f"✅ Votant enregistré : {vid} — {name}")

    def cast_vote(self):
        if not self.paillier.pub:
            messagebox.showwarning("Attention", "Générez les clés Paillier d'abord !")
            return
        vid = self.my_vid.get().strip()
        cand = self.vote_for.get()

        if vid not in self.voters:
            self._log(self.vote_log, f"❌ Votant {vid} inconnu — Vote REJETÉ ⛔")
            return
        if self.voters[vid]["voted"]:
            self._log(self.vote_log, f"❌ Double vote détecté pour {vid} — REJETÉ ⛔")
            messagebox.showerror("Double Vote", f"{vid} a déjà voté !")
            return

        def _run():
            self._log(self.vote_log, "")
            self._log(self.vote_log,
                      f"🗳️  Vote de {vid} ({self.voters[vid]['name']}) → {cand}")
            for c in self.candidates:
                m = 1 if c == cand else 0
                enc = self.paillier.encrypt(m)
                if self.enc_tally[c] is None:
                    self.enc_tally[c] = enc
                else:
                    self.enc_tally[c] = self.paillier.hadd(self.enc_tally[c], enc)
                self._log(self.vote_log,
                          f"   E({c}={m}) = {hex(enc)[:32]}… → cumulé")
            self.voters[vid]["voted"] = True
            self._log(self.vote_log, "   ✅ Bulletin chiffré stocké — anonymat préservé")

        threading.Thread(target=_run, daemon=True).start()

    def double_vote_test(self):
        vid = self.my_vid.get().strip()
        if vid in self.voters and self.voters[vid]["voted"]:
            self._log(self.vote_log, f"⛔ Tentative de double vote — {vid} → BLOQUÉ")
            messagebox.showerror("Rejeté", f"Double vote bloqué pour {vid} !")
        else:
            self._log(self.vote_log, f"ℹ️  {vid} n'a pas encore voté — pas de double vote")

    def tally_votes(self):
        if not any(v for v in self.enc_tally.values() if v is not None):
            self._log(self.vote_log, "❌ Aucun vote enregistré !")
            return
        self._log(self.vote_log, "")
        self._log(self.vote_log, "🔢  DÉPOUILLEMENT HOMOMORPHIQUE")
        self._log(self.vote_log, "   (additions dans l'espace chiffré — pas de déchiffrement)")
        for c, enc in self.enc_tally.items():
            if enc is not None:
                self._log(self.vote_log, f"   Σ E({c}) = {hex(enc)[:40]}…")
            else:
                self._log(self.vote_log, f"   Σ E({c}) = E(0)  [aucun vote]")
        self._log(self.vote_log, "✅ Cumul terminé — clé privée nécessaire pour le résultat")

    def reveal_results(self):
        if not self.paillier.priv:
            self._log(self.vote_log, "❌ Clés privées non disponibles !")
            return
        results = {}
        for c, enc in self.enc_tally.items():
            results[c] = self.paillier.decrypt(enc) if enc is not None else 0

        total = sum(results.values())
        self._log(self.vote_log, "")
        self._log(self.vote_log, "═" * 50)
        self._log(self.vote_log, "🔓  RÉSULTATS FINAUX (après déchiffrement)")
        self._log(self.vote_log, "═" * 50)

        winner = max(results, key=results.get) if total else "—"
        res_str = ""
        for c, v in sorted(results.items(), key=lambda x: -x[1]):
            pct = v / total * 100 if total else 0
            bar = "█" * v + "░" * (total - v) if total <= 20 else ""
            self._log(self.vote_log,
                      f"   {c:8s}: {v:3d} voix  ({pct:5.1f}%)  {bar}")
            res_str += f"{c}: {v} voix ({pct:.1f}%)\n"

        self._log(self.vote_log, f"   Total : {total} votes")
        self._log(self.vote_log, f"   🏆 Vainqueur : {winner}")
        self._log(self.vote_log, "═" * 50)
        self.result_label.config(
            text=f"🏆 {winner}\n\n{res_str}Total : {total} votes",
            fg='#a6e3a1')

    def reset_vote(self):
        self.enc_tally = {c: None for c in self.candidates}
        for vid in self.voters:
            self.voters[vid]["voted"] = False
        self.result_label.config(text="En attente du dépouillement …", fg='#cdd6f4')
        self._log(self.vote_log, "🔄 Vote réinitialisé — tous les registres effacés")

    # ── Entry point ──────────────────────────────────
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = TP6App()
    app.run()
