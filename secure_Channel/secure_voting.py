#!/usr/bin/env python3
# secure_voting.py - Vote électronique sécurisé (version corrigée)

import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from collections import Counter

class Voter:
    def __init__(self, name, voter_id):
        self.name = name
        self.voter_id = voter_id
        self.has_voted = False
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
    
    def create_ballot(self, vote, election_public_key):
        if self.has_voted:
            return None
        encrypted_vote = election_public_key.encrypt(
            vote.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        signature = self.private_key.sign(
            vote.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        self.has_voted = True
        return {"voter_id": self.voter_id, "encrypted_vote": encrypted_vote.hex(), "signature": signature.hex()}

class Election:
    def __init__(self, name, candidates):
        self.name = name
        self.candidates = candidates
        self.ballots = []
        self.voters = {}
        self.is_open = True
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
    
    def register_voter(self, voter):
        self.voters[voter.voter_id] = voter
        print(f"   ✅ Votant enregistré: {voter.name}")
    
    def receive_ballot(self, ballot):
        if not self.is_open:
            return False
        voter_id = ballot["voter_id"]
        if voter_id not in self.voters:
            print(f"   ❌ Votant {voter_id} non enregistré")
            return False
        voter = self.voters[voter_id]
        if voter.has_voted:
            print(f"   ❌ Double vote pour {voter.name}")
            return False
        encrypted_vote = bytes.fromhex(ballot["encrypted_vote"])
        vote = self.private_key.decrypt(encrypted_vote, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode()
        self.ballots.append({"voter_name": voter.name, "vote": vote})
        print(f"   ✅ Vote reçu de {voter.name} pour '{vote}'")
        return True
    
    def tally(self):
        if self.is_open:
            return {}
        vote_count = Counter(b["vote"] for b in self.ballots)
        total = len(self.ballots)
        results = {c: {"votes": vote_count.get(c, 0), "percentage": (vote_count.get(c, 0)/total*100) if total>0 else 0} for c in self.candidates}
        results["total_votes"] = total
        results["turnout"] = (total/len(self.voters)*100) if self.voters else 0
        return results
    
    def close(self):
        self.is_open = False
        print(f"\n   🔒 Élection '{self.name}' fermée")

def simulate_election():
    print("\n" + "="*60)
    print("  VOTE ÉLECTRONIQUE SÉCURISÉ")
    print("="*60)
    
    election = Election("Présidentielle 2024", ["Alice", "Bob", "Charlie"])
    voters = [Voter("Jean Dupont", "V001"), Voter("Marie Martin", "V002"), Voter("Pierre Durand", "V003")]
    
    print("\n📝 Enregistrement:")
    for v in voters:
        election.register_voter(v)
    
    print("\n🗳️ Vote:")
    votes = [("Alice", "V001"), ("Bob", "V002"), ("Alice", "V003")]
    for vote, vid in votes:
        voter = next(v for v in voters if v.voter_id == vid)
        ballot = voter.create_ballot(vote, election.public_key)
        election.receive_ballot(ballot)
    
    print("\n⚠️ Test double vote:")
    ballot2 = voters[0].create_ballot("Bob", election.public_key)
    if ballot2:
        election.receive_ballot(ballot2)
    
    print("\n🔒 Fermeture")
    election.close()
    
    print("\n📊 Résultats:")
    results = election.tally()
    for c in ["Alice", "Bob", "Charlie"]:
        print(f"   {c}: {results[c]['votes']} voix ({results[c]['percentage']:.1f}%)")
    print(f"\n   Participation: {results['turnout']:.0f}% ({results['total_votes']}/{len(voters)})")

def menu():
    print("\n" + "="*55)
    print("  VOTE ÉLECTRONIQUE SÉCURISÉ")
    print("="*55)
    print("1. Simuler une élection complète")
    print("2. Démontrer le vote homomorphique (principe)")
    print("3. Comparer les systèmes de vote")
    print("4. Quitter")

def vote_homomorphique():
    print("\n📚 Vote homomorphique: E(v1) × E(v2) = E(v1+v2)")
    print("   → On peut compter sans déchiffrer individuellement")

def compare_systems():
    print("\n📊 Comparaison: Papier | RSA | Homomorphique | Blockchain")

if __name__ == "__main__":
    while True:
        menu()
        choix = input("\nChoisissez: ")
        if choix == "1": simulate_election()
        elif choix == "2": vote_homomorphique()
        elif choix == "3": compare_systems()
        elif choix == "4": break
