import ctypes
import os

# importing our builded shared library
libaes = ctypes.CDLL(os.path.abspath("./libaes.so"))

# describing c-structure using aes.h
AES_BLOCK_SIZE = 16
AES_KEYLEN_256 = 32

class AesCtx(ctypes.Structure):
    _fields_ = [
        ("round_key", ctypes.c_uint32 * 60), 
        ("round_count", ctypes.c_uint8)
    ]

# basic settings
ctx = AesCtx()
key = (ctypes.c_uint8 * AES_KEYLEN_256)()
libaes.rng_fill(key, AES_KEYLEN_256)
libaes.aes_init(ctypes.byref(ctx), key, AES_KEYLEN_256)

# wrappingsa for c-functions
def cbc_encrypt(plaintext, iv):
    out = (ctypes.c_uint8 * len(plaintext))()
    c_pt = (ctypes.c_uint8 * len(plaintext))(*plaintext)
    c_iv = (ctypes.c_uint8 * AES_BLOCK_SIZE)(*iv)
    libaes.aes_cbc_encrypt(ctypes.byref(ctx), out, c_pt, len(plaintext), c_iv)
    return bytes(out)

def cbc_decrypt(ciphertext, iv):
    out = (ctypes.c_uint8 * len(ciphertext))()
    c_ct = (ctypes.c_uint8 * len(ciphertext))(*ciphertext)
    c_iv = (ctypes.c_uint8 * AES_BLOCK_SIZE)(*iv)
    libaes.aes_cbc_decrypt(ctypes.byref(ctx), out, c_ct, len(ciphertext), c_iv)
    return bytes(out)

# function to work with PKCS#7
def pad(data):
    pad_len = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def unpad_check(data):
    if not data: return False
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES_BLOCK_SIZE: return False
    for i in range(1, pad_len + 1):
        if data[-i] != pad_len: return False
    return True

# server simulation(oracle)
SECRET_TEXT = b"Super secret text that you will never read this without the key!"
SERVER_IV = os.urandom(16)

# server encodes secret
padded_text = pad(SECRET_TEXT)
target_ciphertext = cbc_encrypt(padded_text, SERVER_IV)

# oracle-function: server recieves data, decodes and return status of padding
def padding_oracle(iv, ciphertext):
    decrypted = cbc_decrypt(ciphertext, iv)
    return unpad_check(decrypted)

print("=== Padding Oracle Attack on AES-CBC ===")
print(f"[server] Secret is encrypted. Length: {len(target_ciphertext)} bytes.")
print("[attack]  Staarting byte-by-byte iteration. Few seconds \n")

# logic of attack
def attack_block(prev_block, cipher_block):
    decrypted_bytes = bytearray(AES_BLOCK_SIZE)
    
    # starting from the end
    for byte_idx in reversed(range(AES_BLOCK_SIZE)):
        padding_val = AES_BLOCK_SIZE - byte_idx
        
        # creating fake pre-block, which we will send to server
        fake_prev_block = bytearray(AES_BLOCK_SIZE)
        
        # filling вже розгадані байти правильними значеннями для поточного кроку
        for i in range(byte_idx + 1, AES_BLOCK_SIZE):
            fake_prev_block[i] = decrypted_bytes[i] ^ padding_val
            
        # looking for current byte
        for guess in range(256):
            fake_prev_block[byte_idx] = guess ^ padding_val
            
            # sending fake block + block, that we want to decode
            if padding_oracle(bytes(fake_prev_block), cipher_block):
                # additional check for 15th byte to avoid false results
                if byte_idx == 15 and guess == prev_block[15]:
                    fake_prev_block[14] ^= 0x01
                    if not padding_oracle(bytes(fake_prev_block), cipher_block):
                        continue
                
                decrypted_bytes[byte_idx] = guess
                break
                
    # CBC formula: open text = decoded block ^ truthfull pre-block
    plaintext_block = bytearray(AES_BLOCK_SIZE)
    for i in range(AES_BLOCK_SIZE):
        plaintext_block[i] = decrypted_bytes[i] ^ prev_block[i]
        
    return plaintext_block

# breakling cipher text on blocks with 16 bytes
blocks = [SERVER_IV] + [target_ciphertext[i:i+AES_BLOCK_SIZE] for i in range(0, len(target_ciphertext), AES_BLOCK_SIZE)]

recovered_plaintext = b""

# attacking every block one by one
for i in range(1, len(blocks)):
    print(f"[*] Attacks block {i}/{len(blocks)-1}...")
    recovered_block = attack_block(blocks[i-1], blocks[i])
    recovered_plaintext += recovered_block

# losing padding in the end of the text
pad_len = recovered_plaintext[-1]
final_text = recovered_plaintext[:-pad_len]

print(f"\n[!] Success! Attack gave this result: {final_text}")