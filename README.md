# Cryptography

A comprehensive cryptography utility project that provides implementations of various cryptographic algorithms and protocols. This project features a Graphical User Interface (GUI) to interact with different cipher techniques easily.

## Features

The project is structured into several key cryptographic domains:

- **Classical Ciphers**: Implementations of historical and traditional encryption methods.
- **Symmetric Encryption (Synchrone)**: Modern block and stream ciphers including AES (and AES Finalists), DES, and RC4.
- **Asymmetric Encryption (Asynchrone)**: Public-key cryptography algorithms such as RSA, Diffie-Hellman, ElGamal, and Elliptic Curve Cryptography (ECC).
- **Hashing**: Cryptographic hash functions like MD5, SHA-256, SHA-512, and HMAC.
- **Digital Signatures**: Methods for verifying message authenticity and integrity.
- **Secure Channels**: Implementations for secure communication protocols.

## Prerequisites

- Python 3.10 or newer
- `pip`

## Setup & Installation

1. **Clone the repository** (if you haven't already) and navigate to the project root.

2. **Create and activate a virtual environment** (Recommended):

   Windows:
   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate
   ```
   
   Linux/macOS:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:

   All required libraries (such as `cryptography`, `pycryptodome`, `Pillow`, `numpy`, `matplotlib`, `sympy`) are listed in the `requirements.txt` file. Install them using:
   ```powershell
   pip install -r requirements.txt
   ```

## Run the Application

The main entry point for the application is the Graphical User Interface script.

Run the GUI application:

```powershell
python gui.py
```

## Documentation & Reports

The project includes a detailed technical report documented in LaTeX. You can find the PDF version `Rapport Projet.pdf` and the source LaTeX file `rapport.tex` in the root directory.
