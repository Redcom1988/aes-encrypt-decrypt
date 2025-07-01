from Crypto.Util.Padding import pad
import base64

# =====================================
# KONSTANTA AES
# =====================================
# S-box untuk operasi SubBytes - tabel substitusi byte dalam AES
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

# Round constants untuk ekspansi kunci - konstanta yang digunakan dalam pembuatan round key
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# =====================================
# FUNGSI KONVERSI STATE MATRIX
# =====================================
# Bagian ini mengatur konversi antara byte array dan state matrix 4x4

def bytes_to_state(data):
    """Mengkonversi 16 bytes menjadi state matrix 4x4 (urutan kolom-mayor)"""
    state = [[0 for _ in range(4)] for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = data[col * 4 + row]
    return state

def state_to_bytes(state):
    """Mengkonversi state matrix 4x4 kembali menjadi bytes (urutan kolom-mayor)"""
    result = bytearray(16)
    for col in range(4):
        for row in range(4):
            result[col * 4 + row] = state[row][col]
    return bytes(result)

# =====================================
# OPERASI TRANSFORMASI AES
# =====================================
# Bagian ini berisi 4 operasi utama AES: SubBytes, ShiftRows, MixColumns, AddRoundKey

def sub_bytes(state):
    """Menerapkan S-box ke setiap byte dalam state matrix"""
    for row in range(4):
        for col in range(4):
            state[row][col] = SBOX[state[row][col]]
    return state

def shift_rows(state):
    """Menggeser baris-baris state matrix sesuai pola AES"""
    state[1] = state[1][1:] + state[1][:1]  # Geser baris 1 sebanyak 1
    state[2] = state[2][2:] + state[2][:2]  # Geser baris 2 sebanyak 2
    state[3] = state[3][3:] + state[3][:3]  # Geser baris 3 sebanyak 3
    return state

def gmul(a, b):
    """Perkalian Galois Field untuk operasi MixColumns"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p & 0xff

def mix_columns(state):
    """Mencampur kolom-kolom state matrix menggunakan perkalian matrix di Galois Field"""
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    for col in range(4):
        new_state[0][col] = gmul(0x02, state[0][col]) ^ gmul(0x03, state[1][col]) ^ state[2][col] ^ state[3][col]
        new_state[1][col] = state[0][col] ^ gmul(0x02, state[1][col]) ^ gmul(0x03, state[2][col]) ^ state[3][col]
        new_state[2][col] = state[0][col] ^ state[1][col] ^ gmul(0x02, state[2][col]) ^ gmul(0x03, state[3][col])
        new_state[3][col] = gmul(0x03, state[0][col]) ^ state[1][col] ^ state[2][col] ^ gmul(0x02, state[3][col])
    return new_state

def add_round_key(state, round_key):
    """Menambahkan round key ke state menggunakan operasi XOR"""
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]
    return state

# =====================================
# EKSPANSI KUNCI (KEY EXPANSION)
# =====================================
# Bagian ini menghasilkan round keys dari kunci utama

def rot_word(word):
    """Merotasi word (array 4 bytes) ke kiri sebanyak 1 posisi"""
    return word[1:] + word[:1]

def sub_word(word):
    """Menerapkan S-box ke setiap byte dalam word"""
    return [SBOX[b] for b in word]

def key_expansion(key):
    """Memperluas kunci 16-byte menjadi 11 round keys (masing-masing matrix 4x4)"""
    words = [key[i:i+4] for i in range(0, len(key), 4)]
    
    for i in range(4, 44):
        temp = list(words[i-1])
        
        if i % 4 == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= RCON[i // 4 - 1]
        
        words.append([words[i-4][j] ^ temp[j] for j in range(4)])
    
    round_keys = []
    for i in range(0, 44, 4):
        round_key = [[0 for _ in range(4)] for _ in range(4)]
        for col in range(4):
            for row in range(4):
                round_key[row][col] = words[i + col][row]
        round_keys.append(round_key)
    
    return round_keys

# =====================================
# FUNGSI UTILITAS TAMPILAN
# =====================================
# Bagian ini untuk menampilkan data dalam format yang mudah dibaca

def print_state(state, label):
    """Menampilkan state matrix 4x4 dalam format hex"""
    print(f"{label}:")
    for row in range(4):
        print("  " + " ".join(f"{state[row][col]:02x}" for col in range(4)))
    print()

def display_hex_with_utf8(data, title="Data Terenkripsi"):
    """Menampilkan nilai hex dengan karakter UTF-8 di bawahnya"""
    print(f"\n{title}:")
    
    hex_row = "| Hex |"
    utf8_row = "| UTF |"
    
    for byte in data:
        hex_row += f" {byte:02X} |"
        
        try:
            char = chr(byte)
            if byte < 32:
                if byte == 8:
                    char = "BS"
                elif byte == 13:
                    char = "CR"
                elif byte == 0:
                    char = "0"
                else:
                    char = "."
            elif byte == 127:
                char = "."
            elif byte > 127:
                if 160 <= byte <= 255:
                    char = chr(byte)
                else:
                    char = "."
        except:
            char = "."
        
        utf8_row += f" {char:>2} |"
    
    border = "+" + "-" * (len(hex_row) - 2) + "+"
    print(border)
    print(hex_row)
    print(border)
    print(utf8_row)
    print(border)

# =====================================
# FUNGSI ENKRIPSI UTAMA
# =====================================
# Bagian ini menggabungkan semua operasi untuk enkripsi lengkap

def aes_encrypt_block(block, round_keys, verbose=False):
    """Mengenkripsi satu blok 16-byte menggunakan AES"""
    state = bytes_to_state(block)
    
    if verbose:
        print(f"Blok input (16 bytes): {block.hex()}")
        print_state(state, "State awal (matrix 4x4)")
    
    state = add_round_key(state, round_keys[0])
    if verbose:
        print_state(state, "Setelah AddRoundKey (round 0)")
    
    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
        if verbose:
            print_state(state, f"Setelah round {round_num}")
    
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    if verbose:
        print_state(state, "State akhir (matrix 4x4)")
    
    result = state_to_bytes(state)
    if verbose:
        print(f"Blok output (16 bytes): {result.hex()}")
        print("=" * 50)
    
    return result

def aes_encrypt(plaintext, key_string, verbose=False):
    """Mengenkripsi plaintext menggunakan AES-128 dalam mode ECB"""
    key_bytes = key_string.encode('utf-8')
    key_bytes = key_bytes + b'\0' * (16 - len(key_bytes)) if len(key_bytes) < 16 else key_bytes[:16]
    
    round_keys = key_expansion(key_bytes)
    
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = pad(plaintext_bytes, 16)
    blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
    
    if verbose:
        print(f"Jumlah blok 16-byte: {len(blocks)}")
        print()
    
    encrypted_blocks = []
    for i, block in enumerate(blocks):
        if verbose:
            print(f"=== BLOK {i+1} ===")
        encrypted_block = aes_encrypt_block(block, round_keys, verbose)
        encrypted_blocks.append(encrypted_block)
    
    ciphertext = b''.join(encrypted_blocks)
    
    display_hex_with_utf8(ciphertext, "Data Terenkripsi (Hex dengan UTF-8)")
    
    print(f"\nFormat tradisional:")
    print(f"Hex berkesinambungan: {ciphertext.hex()}")
    print(f"Hex dengan spasi: {' '.join(f'{b:02x}' for b in ciphertext)}")
    
    if verbose:
        print(f"\nTotal bytes terenkripsi: {len(ciphertext)}")
        print(f"Sebagai blok 4x4, ini merepresentasikan {len(ciphertext)//16} blok dari 16 bytes masing-masing")
    
    return base64.b64encode(ciphertext).decode('utf-8')

# =====================================
# PROGRAM UTAMA
# =====================================

plaintext = "INFORMATIKAKEREN"
key = "KUNCIRAHASIA1234"

print(f"Plaintext: {plaintext}")
print(f"Key: {key}")

print("\nData Input:")
display_hex_with_utf8(plaintext.encode('utf-8'), "Plaintext (UTF-8)")
display_hex_with_utf8(key.encode('utf-8'), "Key (UTF-8)")

print("\n" + "="*80)
print("HASIL ENKRIPSI")
print("="*80)
hasil_enkripsi = aes_encrypt(plaintext, key, verbose=False)
print(f"\nHasil Base64: {hasil_enkripsi}")