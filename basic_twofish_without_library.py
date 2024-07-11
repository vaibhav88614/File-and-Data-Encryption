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

MDS_MATRIX = [
    [0x01, 0xEF, 0x5B, 0x5B],
    [0x5B, 0xEF, 0xEF, 0x01],
    [0xEF, 0x5B, 0x01, 0xEF],
    [0xEF, 0x01, 0xEF, 0x5B]
]

def rotate_left(x, n, b):
    """Rotate left function"""
    return ((x << n) | (x >> (b - n))) & ((1 << b) - 1)

def h_function(X, K):
    """H function for key scheduling"""
    # Split X into bytes
    x = [(X >> (8 * i)) & 0xFF for i in range(4)]
    h = [0] * 4
    
    for i in range(4):
        h[i] = SBOX[i][(x[0] >> (8 * i)) & 0xFF]
        h[i] ^= SBOX[i + 4][(x[1] >> (8 * i)) & 0xFF]
        h[i] ^= SBOX[i + 4][(x[2] >> (8 * i)) & 0xFF]
        h[i] ^= SBOX[i][(x[3] >> (8 * i)) & 0xFF]
        h[i] ^= (K >> (8 * i)) & 0xFF
    
    return sum((h[i] << (8 * i)) for i in range(4))

def generate_round_keys(key):
    """Generate round keys for Twofish"""
    key_len = len(key)
    if key_len not in [16, 24, 32]:
        raise ValueError("Key size must be 128, 192, or 256 bits (16, 24, or 32 bytes)")
    
    N = key_len // 8
    M = 2 * N
    
    # Initialize arrays
    K = [0] * N
    L = [0] * N
    for i in range(N):
        K[i] = int.from_bytes(key[i * 4:(i + 1) * 4], byteorder='little')
        L[i] = int.from_bytes(key[(N + i) * 4:(N + i + 1) * 4], byteorder='little')
    
    # Generate round keys
    round_keys = [0] * (2 * M + 8)
    for i in range(M):
        round_keys[i] = h_function(2 * i * 0x01010101, K)
        round_keys[M + i] = rotate_left(h_function((2 * i + 1) * 0x01010101, L), 8, 32)
    
    return round_keys

def f_function(X, round_keys):
    """F function used in encryption"""
    # Split X into bytes
    x = [(X >> (8 * i)) & 0xFF for i in range(4)]
    y = [0] * 4
    
    for i in range(4):
        y[i] = SBOX[i][x[0]] + SBOX[i + 4][x[1]]
        y[i] ^= SBOX[i + 4][x[2]] + SBOX[i][x[3]]
        y[i] ^= round_keys[2 * i]
    
    F0 = (y[0] + y[1]) & 0xFFFFFFFF
    F1 = (y[2] + y[3]) & 0xFFFFFFFF
    
    return (F0, F1)

def mix_columns(block):
    """MixColumns operation in Twofish"""
    col1 = (block >> 96) & 0xFFFFFFFF
    col2 = (block >> 64) & 0xFFFFFFFF
    col3 = (block >> 32) & 0xFFFFFFFF
    col4 = block & 0xFFFFFFFF
    
    mixed_col1 = (MDS_MATRIX[0][0] * col1 + MDS_MATRIX[0][1] * col2 +
                  MDS_MATRIX[0][2] * col3 + MDS_MATRIX[0][3] * col4) & 0xFFFFFFFF
    mixed_col2 = (MDS_MATRIX[1][0] * col1 + MDS_MATRIX[1][1] * col2 +
                  MDS_MATRIX[1][2] * col3 + MDS_MATRIX[1][3] * col4) & 0xFFFFFFFF
    mixed_col3 = (MDS_MATRIX[2][0] * col1 + MDS_MATRIX[2][1] * col2 +
                  MDS_MATRIX[2][2] * col3 + MDS_MATRIX[2][3] * col4) & 0xFFFFFFFF
    mixed_col4 = (MDS_MATRIX[3][0] * col1 + MDS_MATRIX[3][1] * col2 +
                  MDS_MATRIX[3][2] * col3 + MDS_MATRIX[3][3] * col4) & 0xFFFFFFFF
    
    return (mixed_col1 << 96) | (mixed_col2 << 64) | (mixed_col3 << 32) | mixed_col4

def encrypt_block(block, round_keys):
    """Encrypts one block using Twofish"""
    L0 = block >> 128
    R0 = block & ((1 << 128) - 1)
    L1 = R0
    R1 = L0 ^ f_function(R0, round_keys)[0]
    L2 = R1
    R2 = L1 ^ f_function(R1, round_keys)[1]
    L3 = R2
    R3 = L2 ^ f_function(R2, round_keys)[0]
    
    return (L3 << 128) | R3

def twofish_encrypt(data, key):
    """Encrypts data using Twofish with a given key"""
    key = key.ljust(32, b'\0')[:32]  # Pad or trim key to 32 bytes
    round_keys = generate_round_keys(key)
    
    encrypted_data = []
    for i in range(0, len(data), 16):
        block = int.from_bytes(data[i:i + 16].ljust(16, b'\0'), byteorder='big')
        encrypted_block = encrypt_block(block, round_keys)
        encrypted_data.append(encrypted_block.to_bytes(32, byteorder='big'))
    
    return b''.join(encrypted_data)

def twofish_decrypt(data, key):
    """Decrypts data using Twofish with a given key"""
    key = key.ljust(32, b'\0')[:32]  # Pad or trim key to 32 bytes
    round_keys = generate_round_keys(key)
    
    decrypted_data = []
    for i in range(0, len(data), 32):
        block = int.from_bytes(data[i:i + 32], byteorder='big')
        decrypted_block = encrypt_block(block, round_keys)  # Encryption and decryption are the same
        decrypted_data.append(decrypted_block.to_bytes(16, byteorder='big'))
    
    return b''.join(decrypted_data)

def main():
    data = input("Enter the text to encrypt: ").encode()
    key = input("Enter the key (must be 16, 24, or 32 bytes): ").encode()
    
    ciphertext = twofish_encrypt(data, key)
    decrypted_text = twofish_decrypt(ciphertext, key)
    
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted text: {decrypted_text.decode()}")

if __name__ == "__main__":
    main()
