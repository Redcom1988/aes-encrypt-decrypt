from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import binascii

# AES S-box for SubBytes operation
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Round constants for key expansion
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# Helper function to print state matrix and key matrices in hex format
def print_matrix(name, matrix):
    print(f"\n{name}:")
    for row in matrix:
        print(" ".join(f"{byte:02x}" for byte in row))

def bytes_to_state(data):
    """
    Convert 16 bytes to a 4x4 state matrix (column-major order)
    This is the standard way AES treats bytes as a state matrix
    """
    state = [[0 for _ in range(4)] for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = data[col * 4 + row]
    return state

def state_to_bytes(state):
    """
    Convert a 4x4 state matrix back to bytes (column-major order)
    """
    result = bytearray(16)
    for col in range(4):
        for row in range(4):
            result[col * 4 + row] = state[row][col]
    return bytes(result)

def sub_bytes(state):
    """Apply S-box to each byte in the state matrix"""
    for row in range(4):
        for col in range(4):
            state[row][col] = SBOX[state[row][col]]
    return state

def shift_rows(state):
    """Shift rows of the state matrix"""
    # No shift for row 0
    # Shift row 1 by 1
    state[1] = state[1][1:] + state[1][:1]
    # Shift row 2 by 2
    state[2] = state[2][2:] + state[2][:2]
    # Shift row 3 by 3
    state[3] = state[3][3:] + state[3][:3]
    return state

def gmul(a, b):
    """Galois Field multiplication for MixColumns"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b  # AES irreducible polynomial
        b >>= 1
    return p & 0xff

def mix_columns(state):
    """Mix columns of the state matrix"""
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    for col in range(4):
        new_state[0][col] = gmul(0x02, state[0][col]) ^ gmul(0x03, state[1][col]) ^ state[2][col] ^ state[3][col]
        new_state[1][col] = state[0][col] ^ gmul(0x02, state[1][col]) ^ gmul(0x03, state[2][col]) ^ state[3][col]
        new_state[2][col] = state[0][col] ^ state[1][col] ^ gmul(0x02, state[2][col]) ^ gmul(0x03, state[3][col])
        new_state[3][col] = gmul(0x03, state[0][col]) ^ state[1][col] ^ state[2][col] ^ gmul(0x02, state[3][col])
    return new_state

def add_round_key(state, round_key):
    """Add round key to state"""
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]
    return state

def rot_word(word):
    """Rotate a word (array of 4 bytes)"""
    return word[1:] + word[:1]

def sub_word(word):
    """Apply S-box to each byte in a word"""
    return [SBOX[b] for b in word]

def key_expansion(key):
    """
    Expand the 16-byte key into round keys
    Each round key is a 4x4 matrix
    """
    # The first round key is the key itself
    words = [key[i:i+4] for i in range(0, len(key), 4)]
    
    print("\n===== KEY EXPANSION =====")
    print(f"Original key: {key.hex()}")
    print(f"Initial words: {[w.hex() for w in words]}")
    
    # Expand to get 44 words (11 round keys, 4 words each)
    for i in range(4, 44):
        temp = list(words[i-1])
        
        if i % 4 == 0:
            print(f"\nStarting word {i} (Round {i//4}):")
            print(f"  Word[{i-1}] = {bytes(temp).hex()}")
            
            temp_rot = rot_word(temp)
            print(f"  After RotWord: {bytes(temp_rot).hex()}")
            
            temp_sub = sub_word(temp_rot)
            print(f"  After SubWord: {bytes(temp_sub).hex()}")
            
            temp = temp_sub
            temp[0] ^= RCON[i // 4 - 1]
            print(f"  After XOR with RCON[{i//4-1}]={RCON[i//4-1]:02x}: {bytes(temp).hex()}")
        
        new_word = [words[i-4][j] ^ temp[j] for j in range(4)]
        print(f"  Word[{i}] = Word[{i-4}] ⊕ temp = {bytes(words[i-4]).hex()} ⊕ {bytes(temp).hex()} = {bytes(new_word).hex()}")
        
        words.append(new_word)
    
    # Convert words to round keys
    round_keys = []
    for i in range(0, 44, 4):
        # Arrange words into a 4x4 matrix (column-major order)
        round_key = [[0 for _ in range(4)] for _ in range(4)]
        for col in range(4):
            for row in range(4):
                round_key[row][col] = words[i + col][row]
        
        round_num = i // 4
        print(f"\nRound Key {round_num}:")
        for row in round_key:
            print(" ".join(f"{byte:02x}" for byte in row))
        
        round_keys.append(round_key)
    
    return round_keys

def aes_encrypt_block(block, round_keys):
    """Encrypt a single 16-byte block"""
    print("\n===== AES ENCRYPTION PROCESS =====")
    print(f"Input block: {block.hex()}")
    
    state = bytes_to_state(block)
    print_matrix("Initial state matrix", state)
    
    # Initial round
    print("\n--- Round 0 (Initial round) ---")
    print_matrix("Round Key 0", round_keys[0])
    state = add_round_key(state, round_keys[0])
    print_matrix("After AddRoundKey", state)
    
    # Main rounds
    for round_num in range(1, 10):
        print(f"\n--- Round {round_num} ---")
        
        state = sub_bytes(state)
        print_matrix(f"After SubBytes", state)
        
        state = shift_rows(state)
        print_matrix(f"After ShiftRows", state)
        
        state = mix_columns(state)
        print_matrix(f"After MixColumns", state)
        
        print_matrix(f"Round Key {round_num}", round_keys[round_num])
        state = add_round_key(state, round_keys[round_num])
        print_matrix(f"After AddRoundKey", state)
    
    # Final round (no MixColumns)
    print("\n--- Round 10 (Final round) ---")
    
    state = sub_bytes(state)
    print_matrix("After SubBytes", state)
    
    state = shift_rows(state)
    print_matrix("After ShiftRows", state)
    
    print_matrix("Round Key 10", round_keys[10])
    state = add_round_key(state, round_keys[10])
    print_matrix("After AddRoundKey (Final)", state)
    
    encrypted_block = state_to_bytes(state)
    print(f"Encrypted block: {encrypted_block.hex()}")
    
    return encrypted_block

def aes_encrypt(plaintext, key_string):
    """Encrypt plaintext using AES-128 in ECB mode"""
    # Prepare the key (16 bytes for AES-128)
    key_bytes = key_string.encode('utf-8')
    key_bytes = key_bytes + b'\0' * (16 - len(key_bytes)) if len(key_bytes) < 16 else key_bytes[:16]
    
    print(f"\nPlaintext: '{plaintext}'")
    print(f"Key: '{key_string}'")
    print(f"Key bytes (hex): {key_bytes.hex()}")
    
    # Generate round keys
    round_keys = key_expansion(key_bytes)
    
    # Pad and split plaintext into blocks
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = pad(plaintext_bytes, AES.block_size)
    print(f"\nPlaintext bytes: {plaintext_bytes.hex()}")
    print(f"Padded data: {padded_data.hex()}")
    
    blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
    print(f"Number of blocks: {len(blocks)}")
    
    # Encrypt each block
    encrypted_blocks = []
    for i, block in enumerate(blocks):
        print(f"\n===== Processing Block {i+1}/{len(blocks)} =====")
        encrypted_block = aes_encrypt_block(block, round_keys)
        encrypted_blocks.append(encrypted_block)
    
    # Combine all encrypted blocks
    ciphertext = b''.join(encrypted_blocks)
    print(f"\nFinal ciphertext (hex): {ciphertext.hex()}")
    
    # Return base64 encoded result
    b64_result = base64.b64encode(ciphertext).decode('utf-8')
    print(f"Base64 encoded: {b64_result}")
    
    return b64_result

def aes_decrypt(ciphertext_b64, key_string):
    """Decrypt ciphertext using standard library"""
    key_bytes = key_string.encode('utf-8')
    key_bytes = key_bytes + b'\0' * (16 - len(key_bytes)) if len(key_bytes) < 16 else key_bytes[:16]
    
    print(f"\n===== DECRYPTION =====")
    print(f"Ciphertext (Base64): {ciphertext_b64}")
    
    ciphertext = base64.b64decode(ciphertext_b64)
    print(f"Decoded ciphertext (hex): {ciphertext.hex()}")
    
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(ciphertext)
    print(f"Decrypted padded (hex): {decrypted_padded.hex()}")
    
    try:
        decrypted = unpad(decrypted_padded, AES.block_size)
        print(f"Unpadded result (hex): {decrypted.hex()}")
        result = decrypted.decode('utf-8')
        print(f"Decrypted text: '{result}'")
        return result
    except Exception as e:
        print(f"Decryption error: {e}")
        return f"Decryption error: {e}"

# Test with a sample plaintext and key
plaintext = "Andi tidur malam"
key = "satu dua delapan"

print("\n" + "="*50)
print("AES-128 ENCRYPTION DEMONSTRATION WITH LOGGING")
print("="*50)

# Our implementation (following the official AES spec)
my_result = aes_encrypt(plaintext, key)
print(f"\nMy implementation result: {my_result}")

# Try the standard library for comparison
cipher = AES.new(key.encode('utf-8').ljust(16, b'\0'), AES.MODE_ECB)
padded = pad(plaintext.encode('utf-8'), AES.block_size)
std_result = base64.b64encode(cipher.encrypt(padded)).decode('utf-8')
print(f"Standard library result: {std_result}")
print(f"Results match: {my_result == std_result}")

# Decrypt the result
print(f"\nDecrypting the result:")
decrypted = aes_decrypt(my_result, key)
print(f"Original text matches decrypted: {plaintext == decrypted}")