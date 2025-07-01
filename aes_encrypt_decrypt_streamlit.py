import streamlit as st
import base64
from Crypto.Util.Padding import pad, unpad

# =====================================
# KONSTANTA AES
# =====================================
# S-box untuk operasi SubBytes
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

# Round constants untuk ekspansi kunci
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# =====================================
# FUNGSI KONVERSI STATE MATRIX
# =====================================

def bytes_to_state(data):
    """Mengkonversi 16 bytes menjadi state matrix 4x4"""
    state = [[0 for _ in range(4)] for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = data[col * 4 + row]
    return state

def state_to_bytes(state):
    """Mengkonversi state matrix 4x4 kembali menjadi bytes"""
    result = bytearray(16)
    for col in range(4):
        for row in range(4):
            result[col * 4 + row] = state[row][col]
    return bytes(result)

# =====================================
# OPERASI TRANSFORMASI AES
# =====================================

def sub_bytes(state):
    """Menerapkan S-box ke setiap byte dalam state matrix"""
    for row in range(4):
        for col in range(4):
            state[row][col] = SBOX[state[row][col]]
    return state

def inv_sub_bytes(state):
    """Menerapkan inverse S-box ke setiap byte dalam state matrix"""
    for row in range(4):
        for col in range(4):
            state[row][col] = INV_SBOX[state[row][col]]
    return state

def shift_rows(state):
    """Menggeser baris-baris state matrix sesuai pola AES"""
    state[1] = state[1][1:] + state[1][:1]  # Geser baris 1 sebanyak 1
    state[2] = state[2][2:] + state[2][:2]  # Geser baris 2 sebanyak 2
    state[3] = state[3][3:] + state[3][:3]  # Geser baris 3 sebanyak 3
    return state

def inv_shift_rows(state):
    """Menggeser baris-baris state matrix dengan arah berlawanan dari ShiftRows"""
    state[1] = state[1][-1:] + state[1][:-1]  # Geser baris 1 ke kanan sebanyak 1
    state[2] = state[2][-2:] + state[2][:-2]  # Geser baris 2 ke kanan sebanyak 2
    state[3] = state[3][-3:] + state[3][:-3]  # Geser baris 3 ke kanan sebanyak 3
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

def inv_mix_columns(state):
    """Inverse dari operasi MixColumns menggunakan matrix inverse di Galois Field"""
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    for col in range(4):
        new_state[0][col] = gmul(0x0e, state[0][col]) ^ gmul(0x0b, state[1][col]) ^ gmul(0x0d, state[2][col]) ^ gmul(0x09, state[3][col])
        new_state[1][col] = gmul(0x09, state[0][col]) ^ gmul(0x0e, state[1][col]) ^ gmul(0x0b, state[2][col]) ^ gmul(0x0d, state[3][col])
        new_state[2][col] = gmul(0x0d, state[0][col]) ^ gmul(0x09, state[1][col]) ^ gmul(0x0e, state[2][col]) ^ gmul(0x0b, state[3][col])
        new_state[3][col] = gmul(0x0b, state[0][col]) ^ gmul(0x0d, state[1][col]) ^ gmul(0x09, state[2][col]) ^ gmul(0x0e, state[3][col])
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

def rot_word(word):
    """Merotasi word (array 4 bytes) ke kiri sebanyak 1 posisi"""
    return word[1:] + word[:1]

def sub_word(word):
    """Menerapkan S-box ke setiap byte dalam word"""
    return [SBOX[b] for b in word]

def key_expansion(key):
    """Memperluas kunci 16-byte menjadi 11 round keys"""
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
# FUNGSI ENKRIPSI DAN DEKRIPSI
# =====================================

def aes_encrypt_block(block, round_keys):
    """Mengenkripsi satu blok 16-byte menggunakan AES"""
    state = bytes_to_state(block)
    
    state = add_round_key(state, round_keys[0])
    
    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
    
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    return state_to_bytes(state)

def aes_decrypt_block(block, round_keys):
    """Mendekripsi satu blok 16-byte menggunakan AES"""
    state = bytes_to_state(block)
    
    state = add_round_key(state, round_keys[10])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    
    for round_num in range(9, 0, -1):
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    
    state = add_round_key(state, round_keys[0])
    
    return state_to_bytes(state)

def aes_encrypt(plaintext, key_string):
    """Mengenkripsi plaintext menggunakan AES-128 dalam mode ECB"""
    key_bytes = key_string.encode('utf-8')
    key_bytes = key_bytes + b'\0' * (16 - len(key_bytes)) if len(key_bytes) < 16 else key_bytes[:16]
    
    round_keys = key_expansion(key_bytes)
    
    plaintext_bytes = plaintext.encode('utf-8')
    padded_data = pad(plaintext_bytes, 16)
    blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
    
    encrypted_blocks = []
    for block in blocks:
        encrypted_block = aes_encrypt_block(block, round_keys)
        encrypted_blocks.append(encrypted_block)
    
    ciphertext = b''.join(encrypted_blocks)
    return base64.b64encode(ciphertext).decode('utf-8')

def aes_decrypt(ciphertext_b64, key_string):
    """Mendekripsi ciphertext menggunakan AES-128 dalam mode ECB"""
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        
        key_bytes = key_string.encode('utf-8')
        key_bytes = key_bytes + b'\0' * (16 - len(key_bytes)) if len(key_bytes) < 16 else key_bytes[:16]
        
        round_keys = key_expansion(key_bytes)
        
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        
        decrypted_blocks = []
        for block in blocks:
            decrypted_block = aes_decrypt_block(block, round_keys)
            decrypted_blocks.append(decrypted_block)
        
        decrypted_data = b''.join(decrypted_blocks)
        
        plaintext_bytes = unpad(decrypted_data, 16)
        plaintext = plaintext_bytes.decode('utf-8')
        
        return plaintext
    except Exception as e:
        return None

# =====================================
# STREAMLIT APPLICATION
# =====================================

def main():
    st.set_page_config(
        page_title="AES Encryption/Decryption Tool",
        page_icon="🔐",
        layout="wide"
    )
    
    st.title("🔐 AES Encryption/Decryption Tool")
    st.markdown("---")
    
    # Sidebar for operation selection
    st.sidebar.title("Operation")
    operation = st.sidebar.radio("Choose operation:", ["Encrypt", "Decrypt"])
    
    # Main content area
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Input")
        
        if operation == "Encrypt":
            text_input = st.text_area("Enter plaintext to encrypt:", height=150, placeholder="Type your message here...")
        else:
            text_input = st.text_area("Enter Base64 ciphertext to decrypt:", height=150, placeholder="Paste your Base64 encoded ciphertext here...")
        
        key_input = st.text_input("Enter encryption key:", type="password", placeholder="Enter your secret key...")
        
        # Process button
        if st.button(f"🔒 {operation}" if operation == "Encrypt" else "🔓 Decrypt", type="primary"):
            if not text_input.strip():
                st.error("Please enter text to process!")
            elif not key_input.strip():
                st.error("Please enter an encryption key!")
            else:
                with st.spinner(f"{operation}ing..."):
                    if operation == "Encrypt":
                        result = aes_encrypt(text_input, key_input)
                        if result:
                            st.session_state.result = result
                            st.session_state.operation = "Encrypt"
                            st.session_state.input_text = text_input
                            st.session_state.key = key_input
                    else:
                        result = aes_decrypt(text_input, key_input)
                        if result:
                            st.session_state.result = result
                            st.session_state.operation = "Decrypt"
                            st.session_state.input_text = text_input
                            st.session_state.key = key_input
                        else:
                            st.error("Decryption failed! Please check your ciphertext and key.")
    
    with col2:
        st.subheader("Output")
        
        if hasattr(st.session_state, 'result'):
            if st.session_state.operation == "Encrypt":
                st.success("✅ Encryption successful!")
                st.text_area("Base64 Encrypted Result:", value=st.session_state.result, height=150)
                
                # Additional information
                with st.expander("📊 Encryption Details"):
                    st.write(f"**Original Text Length:** {len(st.session_state.input_text)} characters")
                    st.write(f"**Key Length:** {len(st.session_state.key)} characters")
                    st.write(f"**Base64 Output Length:** {len(st.session_state.result)} characters")
                    
                    # Show hex representation
                    try:
                        hex_data = base64.b64decode(st.session_state.result).hex()
                        st.write(f"**Hex Representation:** `{hex_data}`")
                    except:
                        pass
                
            else:
                st.success("✅ Decryption successful!")
                st.text_area("Decrypted Plaintext:", value=st.session_state.result, height=150)
                
                # Additional information
                with st.expander("📊 Decryption Details"):
                    st.write(f"**Decrypted Text Length:** {len(st.session_state.result)} characters")
                    st.write(f"**Key Used:** {st.session_state.key}")
        else:
            st.info("👆 Enter text and key, then click the button to see results here.")
    
    # Example section
    st.markdown("---")
    st.subheader("📖 Example Usage")
    
    example_col1, example_col2 = st.columns(2)
    
    with example_col1:
        st.markdown("**Sample Encryption:**")
        st.code("""
Plaintext: "INFORMATIKAKEREN"
Key: "KUNCIRAHASIA1234"
Result: Base64 encoded ciphertext
        """)
    

if __name__ == "__main__":
    main()