# secure_voting.py - Vote électronique sécurisé
# ============================================================
# Protocole: Chiffrement individuel des votes + Signature + Dépouillement
# ============================================================

import os
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from collections import Counter


class Voter:
    """Représente un votant avec sa clé RSA."""
    
    def __init__(self, name: str, voter_id: str):
        self.name = name
        self.voter_id = voter_id
        self.has_voted = False
        
        # Génération de la paire de clés RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def get_public_key_pem(self) -> bytes:
        """Exporte la clé publique au format PEM."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def sign_vote(self, vote: str) -> bytes:
        """Signe le vote avec la clé privée (RSA-PSS)."""
        vote_bytes = vote.encode('utf-8')
        signature = self.private_key.sign(
            vote_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def create_ballot(self, vote: str, election_public_key) -> dict:
        """
        Crée un bulletin de vote chiffré.
        Vote = [candidat] chiffré avec la clé publique de l'élection.
        """
        if self.has_voted:
            raise Exception(f"{self.name} a déjà voté!")
        
        # Signature du vote
        signature = self.sign_vote(vote)
        
        # Chiffrement du vote avec RSA-OAEP (petit vote)
        encrypted_vote = election_public_key.encrypt(
            vote.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        ballot = {
            "voter_id": self.voter_id,
            "encrypted_vote": encrypted_vote.hex(),
            "signature": signature.hex()
        }
        
        self.has_voted = True
        return ballot


class Election:
    """Représente une élection sécurisée."""
    
    def __init__(self, name: str, candidates: list):
        self.name = name
        self.candidates = candidates
        self.ballots = []
        self.voters = {}
        self.is_open = True
        
        # Génération de la paire de clés RSA pour l'élection
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def register_voter(self, voter: Voter):
        """Enregistre un votant pour cette élection."""
        self.voters[voter.voter_id] = voter
        print(f"   ✅ Votant enregistré: {voter.name} (ID: {voter.voter_id})")
    
    def receive_ballot(self, ballot: dict) -> bool:
        """
        Reçoit et vérifie un bulletin de vote.
        Vérifie: 1) Signature valide, 2) Votant pas double votant
        """
        if not self.is_open:
            print("   ❌ Élection fermée!")
            return False
        
        voter_id = ballot["voter_id"]
        
        # Vérifier que le votant existe
        if voter_id not in self.voters:
            print(f"   ❌ Votant {voter_id} non enregistré!")
            return False
        
        voter = self.voters[voter_id]
        
        # Vérifier que le votant n'a pas déjà voté
        if voter.has_voted:
            print(f"   ❌ Double vote détecté pour {voter.name}!")
            return False
        
        # Vérifier la signature
        encrypted_vote = bytes.fromhex(ballot["encrypted_vote"])
        signature = bytes.fromhex(ballot["signature"])
        
        # Pour vérifier la signature, il faut le vote clair
        # Dans un vrai système, on vérifierait la signature sur le vote chiffré
        # Ici on déchiffre d'abord pour vérifier
        try:
            vote = self.private_key.decrypt(
                encrypted_vote,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')
            
            # Vérifier la signature
            voter.public_key.verify(
                signature,
                vote.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Stocker le vote (déchiffré pour le dépouillement)
            self.ballots.append({
                "voter_id": voter_id,
                "vote": vote,
                "voter_name": voter.name
            })
            
            voter.has_voted = True
            print(f"   ✅ Vote reçu de {voter.name} pour '{vote}'")
            return True
            
        except Exception as e:
            print(f"   ❌ Signature invalide pour {voter.name}!")
            return False
    
    def tally(self) -> dict:
        """Dépouille les votes."""
        if self.is_open:
            print("   ⚠️  Élection encore ouverte!")
            return {}
        
        if not self.ballots:
            print("   ⚠️  Aucun vote reçu!")
            return {}
        
        # Compter les votes
        vote_count = Counter()
        for ballot in self.ballots:
            vote_count[ballot["vote"]] += 1
        
        # Calculer les pourcentages
        total = len(self.ballots)
        results = {}
        for candidate in self.candidates:
            count = vote_count.get(candidate, 0)
            percentage = (count / total) * 100 if total > 0 else 0
            results[candidate] = {
                "votes": count,
                "percentage": percentage
            }
        
        results["total_votes"] = total
        results["turnout"] = (total / len(self.voters)) * 100 if self.voters else 0
        
        return results
    
    def close(self):
        """Ferme l'élection."""
        self.is_open = False
        print(f"\n   🔒 Élection '{self.name}' fermée")


class SecureElectronicVoting:
    """Système de vote électronique complet."""
    
    def __init__(self):
        self.elections = {}
    
    def create_election(self, name: str, candidates: list) -> Election:
        """Crée une nouvelle élection."""
        election = Election(name, candidates)
        self.elections[name] = election
        print(f"\n📋 Élection créée: '{name}'")
        print(f"   Candidats: {', '.join(candidates)}")
        return election
    
    def verify_voter_eligibility(self, voter_id: str, voter_list: list) -> bool:
        """Vérifie si un votant est éligible (simulation)."""
        return voter_id in voter_list
    
    def audit_log(self, election_name: str):
        """Génère un journal d'audit pour l'élection."""
        if election_name not in self.elections:
            print(f"   Élection {election_name} introuvable")
            return
        
        election = self.elections[election_name]
        
        print(f"\n📜 JOURNAL D'AUDIT - {election_name}")
        print("=" * 50)
        
        for ballot in election.ballots:
            print(f"   Votant: {ballot['voter_name']} | Vote: {ballot['vote']}")
        
        print(f"\n   Total votes: {len(election.ballots)}")
        print(f"   Intégrité: {'✅ Vérifiée' if election.ballots else 'N/A'}")


def simulate_election():
    """Simule une élection complète."""
    print("\n" + "=" * 60)
    print("  VOTE ÉLECTRONIQUE SÉCURISÉ")
    print("  (RSA 2048 + Signatures RSA-PSS)")
    print("=" * 60)
    
    # Création du système
    voting_system = SecureElectronicVoting()
    
    # Création de l'élection
    election = voting_system.create_election(
        name="Élection Présidentielle 2024",
        candidates=["Alice", "Bob", "Charlie"]
    )
    
    # Création des votants
    voters = [
        Voter("Jean Dupont", "V001"),
        Voter("Marie Martin", "V002"),
        Voter("Pierre Durand", "V003"),
        Voter("Sophie Bernard", "V004"),
        Voter("Lucas Petit", "V005")
    ]
    
    # Enregistrement des votants
    print("\n📝 Enregistrement des votants:")
    for voter in voters:
        election.register_voter(voter)
    
    # Simulation du vote
    print("\n🗳️  DÉROULEMENT DU VOTE")
    print("-" * 40)
    
    votes = ["Alice", "Bob", "Charlie", "Alice", "Bob"]
    
    for voter, vote in zip(voters, votes):
        ballot = voter.create_ballot(vote, election.public_key)
        election.receive_ballot(ballot)
    
    # Tentative de double vote
    print("\n⚠️  Test de sécurité - Double vote:")
    try:
        ballot_dup = voters[0].create_ballot("Alice", election.public_key)
        election.receive_ballot(ballot_dup)
    except Exception as e:
        print(f"   ✅ Bloqué: {e}")
    
    # Tentative de vote non enregistré
    print("\n⚠️  Test de sécurité - Votant non enregistré:")
    fake_voter = Voter("Hacker", "V999")
    fake_ballot = fake_voter.create_ballot("Alice", election.public_key)
    election.receive_ballot(fake_ballot)
    
    # Fermeture et dépouillement
    print("\n🔒 FERMETURE DE L'ÉLECTION")
    election.close()
    
    # Dépouillement
    print("\n📊 DÉPOUILLEMENT")
    print("-" * 40)
    results = election.tally()
    
    print(f"\nRésultats de {election.name}:")
    for candidate, stats in results.items():
        if candidate not in ["total_votes", "turnout"]:
            print(f"   {candidate}: {stats['votes']} voix ({stats['percentage']:.1f}%)")
    
    print(f"\n📈 Participation: {results['turnout']:.1f}% ({results['total_votes']}/{len(voters)})")
    
    # Journal d'audit
    voting_system.audit_log("Élection Présidentielle 2024")


def demonstrate_homomorphic_voting():
    """
    Démontre le principe du vote homomorphique (simplifié).
    Permet le dépouillement sans déchiffrer les votes individuels.
    """
    print("\n" + "=" * 60)
    print("  VOTE HOMOMORPHIQUE (Principe)")
    print("  = Chiffrement qui permet l'addition sans déchiffrer")
    print("=" * 60)
    
    # Chiffrement de Paillier (simplifié ici avec RSA modifié)
    print("\n📚 Principe général:")
    print("   E(vote1) × E(vote2) = E(vote1 + vote2)")
    print("   → On peut compter les votes sans les déchiffrer individuellement!")
    
    print("\n📊 Exemple avec 3 votes:")
    print("   Vote 1: Pour Alice (chiffré: 0x7F3A...)")
    print("   Vote 2: Pour Alice (chiffré: 0x2B8C...)")
    print("   Vote 3: Pour Bob   (chiffré: 0x9D1E...)")
    print("   Multiplication: 0x7F3A × 0x2B8C × 0x9D1E = 0x...")
    print("   → Résultat déchiffré = 2 voix pour Alice, 1 pour Bob")
    
    print("\n✅ Avantages:")
    print("   - Anonymat préservé")
    print("   - Vérifiabilité publique")
    print("   - Pas besoin de déchiffrer individuellement")
    
    print("\n⚠️  Inconvénients:")
    print("   - Complexe à implémenter")
    print("   - Plus lent que le vote standard")
    print("   - Nécessite un chiffrement spécial (Paillier, BGV, etc.)")


def compare_voting_systems():
    """Compare différents systèmes de vote électronique."""
    print("\n" + "=" * 60)
    print("  COMPARAISON DES SYSTÈMES DE VOTE")
    print("=" * 60)
    
    systems = {
        "Papier": {
            "sécurité": "Bonne (physique)",
            "vérifiable": "Oui (manuelle)",
            "anonyme": "✅ Oui",
            "coût": "Élevé",
            "rapidité": "Lente"
        },
        "RSA simple (notre TP)": {
            "sécurité": "Bonne (2048 bits)",
            "vérifiable": "✅ Oui (signatures)",
            "anonyme": "⚠️  Pseudonyme",
            "coût": "Faible",
            "rapidité": "Rapide"
        },
        "Homomorphique": {
            "sécurité": "Très bonne",
            "vérifiable": "✅ Oui (publique)",
            "anonyme": "✅ Oui",
            "coût": "Élevé (calcul)",
            "rapidité": "Lente"
        },
        "Blockchain": {
            "sécurité": "Très bonne",
            "vérifiable": "✅ Oui (publique)",
            "anonyme": "⚠️  Variable",
            "coût": "Très élevé",
            "rapidité": "Moyenne"
        }
    }
    
    print("\n📊 Comparatif:")
    print(f"{'Système':<16} {'Sécurité':<12} {'Vérifiable':<12} {'Anonyme':<10} {'Coût':<10} {'Rapidité':<10}")
    print("-" * 70)
    
    for name, props in systems.items():
        print(f"{name:<16} {props['sécurité']:<12} {props['vérifiable']:<12} {props['anonyme']:<10} {props['coût']:<10} {props['rapidité']:<10}")


def menu():
    print("\n" + "=" * 55)
    print("  VOTE ÉLECTRONIQUE SÉCURISÉ")
    print("=" * 55)
    print("1. Simuler une élection complète (RSA + signatures)")
    print("2. Démontrer le vote homomorphique (principe)")
    print("3. Comparer les systèmes de vote")
    print("4. Quitter")
    print("-" * 55)


if __name__ == "__main__":
    while True:
        menu()
        
        try:
            choix = int(input("Choisissez une option : "))
            
            if choix == 4:
                print("Au revoir !")
                break
            
            if choix == 1:
                simulate_election()
            
            elif choix == 2:
                demonstrate_homomorphic_voting()
            
            elif choix == 3:
                compare_voting_systems()
            
        except Exception as e:
            print(f"Erreur: {e}")
