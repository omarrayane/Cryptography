import hashlib

def md5_hash():
    word = input("Enter the word to hash with MD5: ")
    # Create an MD5 hash object
    hash_obj = hashlib.md5()
    # Update the hash object with the bytes of the word
    hash_obj.update(word.encode('utf-8'))
    # Get the hexadecimal representation of the hash
    hashed_word = hash_obj.hexdigest()
    print(f"MD5 Hash: {hashed_word}")

if __name__ == "__main__":
    md5_hash()
