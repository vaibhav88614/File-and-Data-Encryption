from Crypto.Cipher import AES, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from struct import pack
import struct

# Simplified S-boxes for Twofish
S_BOX = [
    [0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76],
    [0x9a, 0x4e, 0xcb, 0xd7, 0xc5, 0xc1, 0xd3, 0xfa],
    [0x4c, 0xbf, 0x70, 0xa6, 0x83, 0xfe, 0xd4, 0xc4],
    [0x1e, 0xc7, 0x41, 0x91, 0xe2, 0x88, 0xf1, 0xb5],
    [0xf9, 0xe7, 0x1b, 0x09, 0xc3, 0x84, 0xb0, 0x1c],
    [0x14, 0xb6, 0x31, 0x24, 0x6b, 0xf8, 0x6d, 0x01],
    [0x7b, 0xb2, 0x16, 0x82, 0x3a, 0xf6, 0x8f, 0x74],
    [0x83, 0xf0, 0x6a, 0x05, 0x8a, 0x3f, 0x11, 0x8b]
]

def rotate_left(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
           ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

def h_function(X, L, K):
    """Simplified h-function"""
    t0 = X
    t1 = rotate_left(t0, 8, 32)
    t2 = rotate_left(t1, 8, 32)
    t3 = rotate_left(t2, 8, 32)
    return (S_BOX[0][t0 & 0xFF] ^ S_BOX[1][t1 & 0xFF] ^
            S_BOX[2][t2 & 0xFF] ^ S_BOX[3][t3 & 0xFF]) & 0xFFFFFFFF

def F_function(R0, R1, round_keys, round_num):
    T0 = h_function(R0, round_keys[round_num * 4], round_keys[round_num * 4 + 1])
    T1 = h_function(rotate_left(R1, 8, 32), round_keys[round_num * 4 + 2], round_keys[round_num * 4 + 3])
    F0 = (T0 + 2 * T1 + round_keys[round_num * 2 + 8]) & 0xFFFFFFFF
    F1 = (2 * T0 + T1 + round_keys[round_num * 2 + 9]) & 0xFFFFFFFF
    return F0, F1

def encrypt_block(block, round_keys):
    """Simplified encryption function for one block"""
    L0, L1, R0, R1 = struct.unpack("<4I", block)
    for round_num in range(16):
        F0, F1 = F_function(R0, R1, round_keys, round_num)
        L0, L1, R0, R1 = R0, R1, L0 ^ F0, L1 ^ F1
    return struct.pack("<4I", R0, R1, L0, L1)

def key_schedule(key):
    """Simplified key schedule generation"""
    round_keys = []
    for i in range(20):
        round_keys.append(int.from_bytes(key[i*4:(i+1)*4], 'little'))
    return round_keys

def twofish_encrypt(data, key):
    key = key.ljust(32, b'\0')[:32]  # Pad or trim key to 32 bytes
    round_keys = key_schedule(key)
    encrypted_data = b''
    for i in range(0, len(data), 16):
        block = data[i:i+16].ljust(16, b'\0')
        encrypted_data += encrypt_block(block, round_keys)
    return encrypted_data

def twofish_decrypt(data, key):
    key = key.ljust(32, b'\0')[:32]  # Pad or trim key to 32 bytes
    round_keys = key_schedule(key)
    decrypted_data = b''
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted_data += encrypt_block(block, round_keys)  # Simplified decryption
    return decrypted_data.rstrip(b'\0')

def pad(data, block_size):
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return key, nonce, ciphertext, tag

def aes_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def rsa_encrypt(data):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    ciphertext = cipher_rsa.encrypt(data)
    return private_key, ciphertext

def rsa_decrypt(private_key, ciphertext):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext

def blowfish_encrypt(data):
    key = get_random_bytes(16)
    cipher = Blowfish.new(key, Blowfish.MODE_EAX)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(pad(data, Blowfish.block_size))
    return key, nonce, ciphertext

def blowfish_decrypt(key, nonce, ciphertext):
    cipher = Blowfish.new(key, Blowfish.MODE_EAX, nonce=nonce)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext

def main():
    print("Select encryption algorithm:")
    print("1. AES")
    print("2. RSA")
    print("3. Blowfish")
    print("4. Twofish")
    choice = input("Enter choice (1/2/3/4): ")

    data = input("Enter the text to encrypt: ").encode()

    if choice == '1':
        key, nonce, ciphertext, tag = aes_encrypt(data)
        plaintext = aes_decrypt(key, nonce, ciphertext, tag)
    elif choice == '2':
        private_key, ciphertext = rsa_encrypt(data)
        plaintext = rsa_decrypt(private_key, ciphertext)
    elif choice == '3':
        key, nonce, ciphertext = blowfish_encrypt(data)
        plaintext = blowfish_decrypt(key, nonce, ciphertext)
    elif choice == '4':
        key = get_random_bytes(32)
        ciphertext = twofish_encrypt(data, key)
        plaintext = twofish_decrypt(ciphertext, key)
    else:
        print("Invalid choice!")
        return

    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted text: {plaintext.decode()}")

if __name__ == "__main__":
    main()
