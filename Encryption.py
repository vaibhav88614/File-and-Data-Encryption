from Crypto.Cipher import AES, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from struct import pack
import twofish

def aes_encrypt_decrypt(data):
    key = get_random_bytes(16)  # AES-128 key size
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return ciphertext, plaintext

def rsa_encrypt_decrypt(data):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    ciphertext = cipher_rsa.encrypt(data)
    
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    plaintext = cipher_rsa.decrypt(ciphertext)
    
    return ciphertext, plaintext

def blowfish_encrypt_decrypt(data):
    key = get_random_bytes(16)  # Blowfish key size can be between 4 and 56 bytes
    cipher = Blowfish.new(key, Blowfish.MODE_EAX)
    
    bs = Blowfish.block_size
    plen = bs - divmod(len(data), bs)[1]
    padding = [plen] * plen
    padding = pack('b' * plen, *padding)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(data + padding)
    
    cipher = Blowfish.new(key, Blowfish.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt(ciphertext)
    plaintext = decrypted_data[:-decrypted_data[-1]]
    
    return ciphertext, plaintext

def twofish_encrypt_decrypt(data):
    key = b'1234567890abcdef'  # Twofish key size can be 16, 24, or 32 bytes
    cipher = twofish.Twofish(key)
    
    data += b'\x00' * (16 - len(data) % 16)  # Padding to ensure block size
    ciphertext = b''.join([cipher.encrypt(data[i:i + 16]) for i in range(0, len(data), 16)])
    
    decrypted_data = b''.join([cipher.decrypt(ciphertext[i:i + 16]) for i in range(0, len(ciphertext), 16)])
    plaintext = decrypted_data.rstrip(b'\x00')
    
    return ciphertext, plaintext

def main():
    print("Select encryption algorithm:")
    print("1. AES")
    print("2. RSA")
    print("3. Blowfish")
    print("4. Twofish")
    choice = input("Enter choice (1/2/3/4): ")
    
    data = input("Enter the text to encrypt: ").encode()
    
    if choice == '1':
        ciphertext, plaintext = aes_encrypt_decrypt(data)
    elif choice == '2':
        ciphertext, plaintext = rsa_encrypt_decrypt(data)
    elif choice == '3':
        ciphertext, plaintext = blowfish_encrypt_decrypt(data)
    elif choice == '4':
        ciphertext, plaintext = twofish_encrypt_decrypt(data)
    else:
        print("Invalid choice!")
        return
    
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted text: {plaintext.decode()}")

if __name__ == "__main__":
    main()
