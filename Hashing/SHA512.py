import hashlib

def sha512_hash():
    word = input("Enter the word to hash with SHA512: ")
    # Create a SHA512 hash object
    hash_obj = hashlib.sha512()
    # Update the hash object with the bytes of the word
    hash_obj.update(word.encode('utf-8'))
    # Get the hexadecimal representation of the hash
    hashed_word = hash_obj.hexdigest()
    print(f"SHA512 Hash: {hashed_word}")

if __name__ == "__main__":
    sha512_hash()
