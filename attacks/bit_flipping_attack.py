import ctypes # allows to work with c code
import os
import sys

# importing our builded shared library
lib_ext = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
lib_path = os.path.abspath(f"./libaes{lib_ext}")
if not os.path.exists(lib_path):
    lib_path = os.path.abspath(f"./build/libaes{lib_ext}")
libaes = ctypes.CDLL(lib_path)

# describing c-structure using aes.h
AES_BLOCK_SIZE = 16
AES_KEYLEN_256 = 32

class AesCtx(ctypes.Structure):
    _fields_ = [
        ("round_key", ctypes.c_uint32 * 60),
        ("round_count", ctypes.c_uint8)
    ]

# basic settings
key = (ctypes.c_uint8 * AES_KEYLEN_256)()
iv = (ctypes.c_uint8 * AES_BLOCK_SIZE)()
ctx = AesCtx()

# using our generator rng_fill for random numbers
libaes.rng_fill(key, AES_KEYLEN_256)
libaes.rng_fill(iv, AES_BLOCK_SIZE)

# initialize context of aes(aes_init)
libaes.aes_init(ctypes.byref(ctx), key, AES_KEYLEN_256)

print("=== Bit-Flipping attack on AES-CFB ===")

# == server simalation: encode ==
# imagining we have authorization token:
original_plaintext = b"user_id=1001;role=user"
data_len = len(original_plaintext)

# creating 
c_plaintext = (ctypes.c_uint8 * data_len)(*original_plaintext)
c_ciphertext = (ctypes.c_uint8 * data_len)()

# saving the copy, before modifying
c_iv_encrypt = (ctypes.c_uint8 * AES_BLOCK_SIZE)(*iv)

# calling our c-function aes_cfb128_encrypt
libaes.aes_cfb128_encrypt(ctypes.byref(ctx), c_ciphertext, c_plaintext, data_len, c_iv_encrypt)

ciphertext_bytes = bytes(c_ciphertext)
print(f"\n[server] Token given: {original_plaintext}")
print(f"[server] Encrypted: {ciphertext_bytes.hex()}")

# changing ciphertext
print("\n[attack] Received ciphertext. Strating the attack")

# we know that original text ends on 'user'
target_known_text = b"user"
# we change it to root
target_new_text = b"root"

# counting index of 'user'
offset = original_plaintext.rfind(target_known_text)

# convert ciphertext in bytearray
malicious_ciphertext = bytearray(ciphertext_bytes)

# attack formula: C' = C ^ P ^ P'
for i in range(len(target_known_text)):
    malicious_ciphertext[offset + i] ^= target_known_text[i] ^ target_new_text[i]

print(f"[attack] Modified ciphertext: {malicious_ciphertext.hex()}")

# == server simulation: decode ==
c_malicious_ciphertext = (ctypes.c_uint8 * data_len)(*malicious_ciphertext)
c_decrypted = (ctypes.c_uint8 * data_len)()
c_iv_decrypt = (ctypes.c_uint8 * AES_BLOCK_SIZE)(*iv)

# calling c-function aes_cfb128_decrypt
libaes.aes_cfb128_decrypt(ctypes.byref(ctx), c_decrypted, c_malicious_ciphertext, data_len, c_iv_decrypt)

print(f"\n[server] Decrypted token: {bytes(c_decrypted)}")
if b"role=root" in bytes(c_decrypted):
    print("\n[!] Success! Now our user has root rights")