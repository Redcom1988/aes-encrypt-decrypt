from Crypto.Util.Padding import unpad

# =====================================
# INVERSE S-BOX DAN KONSTANTA DEKRIPSI
# =====================================
# Inverse S-box untuk operasi InvSubBytes
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# =====================================
# OPERASI TRANSFORMASI INVERSE AES
# =====================================

def inv_sub_bytes(state):
    """Menerapkan inverse S-box ke setiap byte dalam state matrix"""
    for row in range(4):
        for col in range(4):
            state[row][col] = INV_SBOX[state[row][col]]
    return state

def inv_shift_rows(state):
    """Menggeser baris-baris state matrix dengan arah berlawanan dari ShiftRows"""
    state[1] = state[1][-1:] + state[1][:-1]  # Geser baris 1 ke kanan sebanyak 1
    state[2] = state[2][-2:] + state[2][:-2]  # Geser baris 2 ke kanan sebanyak 2
    state[3] = state[3][-3:] + state[3][:-3]  # Geser baris 3 ke kanan sebanyak 3
    return state

def inv_mix_columns(state):
    """Inverse dari operasi MixColumns menggunakan matrix inverse di Galois Field"""
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    for col in range(4):
        new_state[0][col] = gmul(0x0e, state[0][col]) ^ gmul(0x0b, state[1][col]) ^ gmul(0x0d, state[2][col]) ^ gmul(0x09, state[3][col])
        new_state[1][col] = gmul(0x09, state[0][col]) ^ gmul(0x0e, state[1][col]) ^ gmul(0x0b, state[2][col]) ^ gmul(0x0d, state[3][col])
        new_state[2][col] = gmul(0x0d, state[0][col]) ^ gmul(0x09, state[1][col]) ^ gmul(0x0e, state[2][col]) ^ gmul(0x0b, state[3][col])
        new_state[3][col] = gmul(0x0b, state[0][col]) ^ gmul(0x0d, state[1][col]) ^ gmul(0x09, state[2][col]) ^ gmul(0x0e, state[3][col])
    return new_state

# =====================================
# FUNGSI DEKRIPSI UTAMA
# =====================================

def aes_decrypt_block(block, round_keys, verbose=False):
    """Mendekripsi satu blok 16-byte menggunakan AES"""
    state = bytes_to_state(block)
    
    if verbose:
        print(f"Blok encrypted input (16 bytes): {block.hex()}")
        print_state(state, "State awal dekripsi (matrix 4x4)")
    
    # Round terakhir (round 10) - tanpa InvMixColumns
    state = add_round_key(state, round_keys[10])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    
    if verbose:
        print_state(state, "Setelah round 10 (final round)")
    
    # Round 9 sampai 1
    for round_num in range(9, 0, -1):
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        if verbose:
            print_state(state, f"Setelah round {round_num}")
    
    # Round awal (round 0)
    state = add_round_key(state, round_keys[0])
    
    if verbose:
        print_state(state, "State akhir dekripsi (matrix 4x4)")
    
    result = state_to_bytes(state)
    if verbose:
        print(f"Blok decrypted output (16 bytes): {result.hex()}")
        print("=" * 50)
    
    return result

def aes_decrypt(ciphertext_b64, key_string, verbose=False):
    """Mendekripsi ciphertext menggunakan AES-128 dalam mode ECB"""
    # Decode dari Base64
    ciphertext = base64.b64decode(ciphertext_b64)
    
    # Persiapkan kunci
    key_bytes = key_string.encode('utf-8')
    key_bytes = key_bytes + b'\0' * (16 - len(key_bytes)) if len(key_bytes) < 16 else key_bytes[:16]
    
    # Generate round keys
    round_keys = key_expansion(key_bytes)
    
    # Pisahkan ciphertext menjadi blok-blok 16 byte
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    
    if verbose:
        print(f"Jumlah blok 16-byte untuk dekripsi: {len(blocks)}")
        print()
    
    # Dekripsi setiap blok
    decrypted_blocks = []
    for i, block in enumerate(blocks):
        if verbose:
            print(f"=== DEKRIPSI BLOK {i+1} ===")
        decrypted_block = aes_decrypt_block(block, round_keys, verbose)
        decrypted_blocks.append(decrypted_block)
    
    # Gabungkan hasil dekripsi
    decrypted_data = b''.join(decrypted_blocks)
    
    # Hapus padding
    try:
        plaintext_bytes = unpad(decrypted_data, 16)
        plaintext = plaintext_bytes.decode('utf-8')
        
        if verbose:
            display_hex_with_utf8(decrypted_data, "Data Terdekripsi (dengan padding)")
            display_hex_with_utf8(plaintext_bytes, "Data Terdekripsi (tanpa padding)")
        
        return plaintext
    except Exception as e:
        if verbose:
            print(f"Error saat menghapus padding atau decode UTF-8: {e}")
        return None

# =====================================
# TESTING DEKRIPSI
# =====================================

# Tambahkan di bagian program utama, setelah enkripsi
print("\n" + "="*80)
print("HASIL DEKRIPSI")
print("="*80)

# Test dekripsi
hasil_dekripsi = aes_decrypt(hasil_enkripsi, key, verbose=False)

if hasil_dekripsi:
    print(f"Plaintext hasil dekripsi: {hasil_dekripsi}")
    print(f"Dekripsi berhasil: {'✓' if hasil_dekripsi == plaintext else '✗'}")
    
    if hasil_dekripsi == plaintext:
        print("🎉 Enkripsi dan dekripsi berfungsi dengan benar!")
    else:
        print("❌ Ada masalah dalam proses enkripsi/dekripsi")
else:
    print("❌ Dekripsi gagal")

# Test dengan verbose untuk melihat detail proses
print(f"\n" + "="*80)
print("DEKRIPSI DENGAN DETAIL PROSES")
print("="*80)
hasil_dekripsi_verbose = aes_decrypt(hasil_enkripsi, key, verbose=True)