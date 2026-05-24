def rail_fence_encrypt(text: str, rails: int) -> str:
    """
    Chiffre un texte avec le chiffre Rail Fence.
    """
    fence = [[] for _ in range(rails)]
    direction = 1  # 1 = down, -1 = up
    rail = 0
    
    for char in text:
        fence[rail].append(char)
        rail += direction
        
        if rail == rails - 1 or rail == 0:
            direction *= -1
    
    result = ''.join([''.join(r) for r in fence])
    return result

def rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    """
    Déchiffre un texte avec le chiffre Rail Fence.
    """
    length = len(ciphertext)
    
    # Reconstruire le pattern
    pattern = [[] for _ in range(rails)]
    direction = 1
    rail = 0
    
    for i in range(length):
        pattern[rail].append(i)
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction *= -1
    
    # Placer les caractères
    flat_pattern = [pos for rail in pattern for pos in rail]
    result = [''] * length
    
    for i, pos in enumerate(flat_pattern):
        result[pos] = ciphertext[i]
    
    return ''.join(result)

def test_rail_fence():
    print("\n===== TEST RAIL FENCE =====")
    message = "HELLO WORLD"
    rails = 3
    
    encrypted = rail_fence_encrypt(message, rails)
    decrypted = rail_fence_decrypt(encrypted, rails)
    
    print(f"Original  : {message}")
    print(f"Chiffré   : {encrypted}")
    print(f"Déchiffré : {decrypted}")

if __name__ == "__main__":
    test_rail_fence()
