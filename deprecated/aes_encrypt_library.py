from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

def standard_aes_encrypt(plaintext, key_string):
    key_bytes = key_string.encode('utf-8')
    key_bytes = key_bytes + b'\0' * (16 - len(key_bytes)) if len(key_bytes) < 16 else key_bytes[:16]
    
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    return base64.b64encode(ciphertext).decode('utf-8')

# Test with your data
plaintext = "Andi tidur malam"
key = "satu dua delapan"
encrypted = standard_aes_encrypt(plaintext, key)
print(f"Encrypted (Base64) using standard AES: {encrypted}")