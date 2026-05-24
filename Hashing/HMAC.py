import hmac
import hashlib

def hmac_hash():
    word = input("Enter the word to hash with HMAC: ")
    key = input("Enter the secret key for HMAC: ")
    
    hmac_obj = hmac.new(
        key.encode('utf-8'),
        word.encode('utf-8'),
        hashlib.sha256
    )

    hashed_word = hmac_obj.hexdigest()
    print(f"HMAC (SHA256) Hash: {hashed_word}")

if __name__ == "__main__":
    hmac_hash()
