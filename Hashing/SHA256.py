import hashlib

def sha256_hash():
    word = input("Enter the word to hash with SHA256: ")
    # Create a SHA256 hash object
    hash_obj = hashlib.sha256()
    # Update the hash object with the bytes of the word
    hash_obj.update(word.encode('utf-8'))
    # Get the hexadecimal representation of the hash
    hashed_word = hash_obj.hexdigest()
    print(f"SHA256 Hash: {hashed_word}")

if __name__ == "__main__":
    sha256_hash()
