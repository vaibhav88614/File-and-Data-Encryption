# Twofish S-boxes
SBOX = [
    [0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76],
    [0x9A, 0x4E, 0xCB, 0xD7, 0xC5, 0xC1, 0xD3, 0xFA],
    [0x4C, 0xBF, 0x70, 0xA6, 0x83, 0xFE, 0xD4, 0xC4],
    [0x1E, 0xC7, 0x41, 0x91, 0xE2, 0x88, 0xF1, 0xB5],
    [0xF9, 0xE7, 0x1B, 0x09, 0xC3, 0x84, 0xB0, 0x1C],
    [0x14, 0xB6, 0x31, 0x24, 0x6B, 0xF8, 0x6D, 0x01],
    [0x7B, 0xB2, 0x16, 0x82, 0x3A, 0xF6, 0x8F, 0x74],
    [0x83, 0xF0, 0x6A, 0x05, 0x8A, 0x3F, 0x11, 0x8B]
]

def rotate_left(x, n, b):
    return ((x << n) | (x >> (b - n))) & ((1 << b) - 1)

def g_function(h, K):
    """Twofish's G function"""
    h1 = (h >> 24) & 0xFF
    h2 = (h >> 16) & 0xFF
    h3 = (h >> 8) & 0xFF
    h4 = h & 0xFF
    
    K1 = (K >> 24) & 0xFF
    K2 = (K >> 16) & 0xFF
    K3 = (K >> 8) & 0xFF
    K4 = K & 0xFF
    
    g1 = (SBOX[0][h1] + SBOX[1][h2]) & 0xFF
    g2 = (SBOX[2][h3] + SBOX[3][h4]) & 0xFF
    g = (g1 ^ g2) ^ K1
    
    return (g, h2, h3, h4)

def encrypt_block(block, K):
    """Encrypts one block using Twofish"""
    L = block >> 64
    R = block & ((1 << 64) - 1)
    
    for i in range(8):
        K1 = (K >> (8 * i)) & 0xFFFFFFFF
        K2 = (K >> (8 * i + 32)) & 0xFFFFFFFF
        g1, g2, g3, g4 = g_function(R, K1)
        f1 = (g1 ^ g2) ^ g3
        f2 = g4
        L, R = R, L ^ (rotate_left(f1 + 2 * f2, 1, 64))
    
    return (R << 64) | L

def twofish_encrypt(data, key):
    """Encrypts data using Twofish with a given key"""
    key = key.ljust(32, b'\0')[:32]  # Pad or trim key to 32 bytes
    
    K = int.from_bytes(key, 'big')
    encrypted_data = []
    
    for i in range(0, len(data), 16):
        block = int.from_bytes(data[i:i+16].ljust(16, b'\0'), 'big')
        encrypted_block = encrypt_block(block, K)
        encrypted_data.append(encrypted_block.to_bytes(16, 'big'))
    
    return b''.join(encrypted_data)

def twofish_decrypt(data, key):
    """Decrypts data using Twofish with a given key"""
    key = key.ljust(32, b'\0')[:32]  # Pad or trim key to 32 bytes
    
    K = int.from_bytes(key, 'big')
    decrypted_data = []
    
    for i in range(0, len(data), 16):
        block = int.from_bytes(data[i:i+16], 'big')
        decrypted_block = encrypt_block(block, K)  # Encryption and decryption are the same in this simplified version
        decrypted_data.append(decrypted_block.to_bytes(16, 'big'))
    
    return b''.join(decrypted_data)

def main():
    data = input("Enter the text to encrypt: ").encode()
    key = input("Enter the key (must be 16 bytes): ").encode()
    
    ciphertext = twofish_encrypt(data, key)
    decrypted_text = twofish_decrypt(ciphertext, key)
    
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted text: {decrypted_text.decode()}")

if __name__ == "__main__":
    main()
