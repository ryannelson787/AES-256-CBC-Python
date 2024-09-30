from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

import numpy as np

'''
Class: AES_256_CBC
Purpose: encrypt and decrypt via AES_256_CBC algorithm
'''
class AES_256_CBC:

    '''
    AES_256_CBC Constructor
    Parameters: none
    Returns: class instance with methods to encrypt and decrypt
    '''
    def __init__(self):

        # default values and initializations for AES 256
        self.rounds = 14

        self.sbox = np.array([  0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76,
                                0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0,
                                0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15,
                                0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75,
                                0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84,
                                0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf,
                                0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8,
                                0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2,
                                0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73,
                                0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb,
                                0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79,
                                0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08,
                                0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a,
                                0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e,
                                0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf,
                                0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16])
        
        self.rsbox = np.array([ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
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
                                0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d])
        
        self.rcon = np.array([  b'\x00\x00\x00\x00',
                                b'\x01\x00\x00\x00',
                                b'\x02\x00\x00\x00',
                                b'\x04\x00\x00\x00',
                                b'\x08\x00\x00\x00',
                                b'\x10\x00\x00\x00',
                                b'\x20\x00\x00\x00',
                                b'\x40\x00\x00\x00'])
    
    '''
    Method: cryptodome_encrypt
    Parameters:
        data (byte string): message to be encrypted
        key (byte string): syncronous key for algorithm
        iv (byte string): used for unpredictability in matching patterns
    Returns:
        ciphertext (byte string): message encrypted by Python's cryptodome
    '''
    def cryptodome_encrypt(self, data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        ciphertext = base64.b64encode(ct_bytes).decode('utf-8')

        return ciphertext
    
    '''
    Method: cryptodome_decrypt
    Parameters:
        ciphertext (byte string): message to be decrypted
        key (byte string): syncronous key for algorithm
        iv (byte string): used for unpredictability in matching patterns
    Returns:
        plaintext (byte string): message decrypted by Python's cryptodome
    '''
    def cryptodome_decrypt(self, ciphertext, key, iv):
        ct_bytes = base64.b64decode(ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ct_bytes), AES.block_size)

        return plaintext
    
    '''
    Method: encrypt
    Parameters:
        data (byte string): message to be encrypted
        key (byte string): syncronous key for algorithm
        iv (byte string): used for unpredictability in matching patterns
    Returns:
        ciphertext (byte string): message encrypted via AES_256_CBC algorithm
    '''
    def encrypt(self, data, key, iv):
        key_exp = self._key_expansion(key)

        iv_block = np.zeros((4, 4), dtype=np.uint8)
        for r in range(4):
            for c in range(4):
                iv_ind = r*4 + c
                iv_block[r, c] = iv[iv_ind]

        orig_blocks = []
        for i in range((len(data)+15)//16):
            block = np.zeros((4, 4), dtype=np.uint8)
            orig_blocks.append(block)

            for r in range(4):
                for c in range(4):
                    ind = i*16 + r*4 + c
                    if ind < len(data):
                        block[r, c] = data[ind]

        encrypt_blocks = []
        prev_block = iv_block
        
        for block in orig_blocks:
            new_block = prev_block ^ block
            new_block = self._encrypt_block(new_block, key_exp)
            encrypt_blocks.append(new_block)
            prev_block = new_block

        flattened_blocks = np.concatenate([block.flatten() for block in encrypt_blocks])
        ciphertext = flattened_blocks.tobytes()

        return ciphertext
    
    '''
    Method: decrypt
    Parameters:
        ciphertext (byte string): message to be decrypted
        key (byte string): syncronous key for algorithm
        iv (byte string): used for unpredictability in matching patterns
    Returns:
        plaintext (byte string): message decrypted by AES_256_CBC algorithm
    '''
    def decrypt(self, data, key, iv):
        key_exp = self._key_expansion(key)

        iv_block = np.zeros((4, 4), dtype=np.uint8)
        for r in range(4):
            for c in range(4):
                iv_ind = r*4 + c
                iv_block[r, c] = iv[iv_ind]

        orig_blocks = []
        for i in range((len(data)+15)//16):
            block = np.zeros((4, 4), dtype=np.uint8)
            orig_blocks.append(block)

            for r in range(4):
                for c in range(4):
                    ind = i*16 + r*4 + c
                    if ind < len(data):
                        block[r, c] = data[ind]

        decrypt_blocks = []
        prev_block = iv_block
        for block in orig_blocks:
            new_block = self._decrypt_block(block, key_exp)
            new_block = new_block ^ prev_block
            decrypt_blocks.append(new_block)
            prev_block = block

        flattened_blocks = np.concatenate([block.flatten() for block in decrypt_blocks])
        plaintext = flattened_blocks.tobytes()

        return plaintext

    '''
    Method: _encrypt_block (private)
    Parameters:
        block (numpy 4x4 array of uint_8 elements): block to be encrypted
        key (byte string): expanded key used for block encryption
    Returns:
        state (numpy 4x4 array of uint_8 elements): encrypted block
    '''
    def _encrypt_block(self, block, key):
        state = np.copy(block)

        state = self._add_round_key(state, key[0:4])

        for round in range(1, self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, key[round*4 : round*4+4])

        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, key[self.rounds*4 : self.rounds*4+4])

        return state
    
    '''
    Method: _decrypt_block (private)
    Parameters:
        block (numpy 4x4 array of uint_8 elements): block to be decrypted
        key (byte string): expanded key used for block decryption
    Returns:
        state (numpy 4x4 array of uint_8 elements): decrypted block
    '''
    def _decrypt_block(self, block, key):
        state = np.copy(block)

        state = self._rev_add_round_key(state, key[self.rounds*4 : self.rounds*4+4])
        state = self._rev_shift_rows(state)
        state = self._rev_sub_bytes(state)

        for round in range(self.rounds - 1, 0, -1):
            state = self._rev_add_round_key(state, key[round*4 : round*4+4])
            state = self._rev_mix_columns(state)
            state = self._rev_shift_rows(state)
            state = self._rev_sub_bytes(state)

        state = self._rev_add_round_key(state, key[0:4])

        return state
    
    '''
    Method: _sub_bytes (private)
    Parameters:
        old_state (numpy 4x4 array of uint_8 elements): block to be subbed via sbox
    Returns:
        state (numpy 4x4 array of uint_8 elements): subbed block
    '''
    def _sub_bytes(self, old_state):
        state = np.copy(old_state)

        for r in range(4):
            for c in range(4):
                state[r, c] = self.sbox[state[r, c]]

        return state

    '''
    Method: _rev_sub_bytes (private)
    Parameters:
        old_state (numpy 4x4 array of uint_8 elements): block to be subbed via rsbox
    Returns:
        state (numpy 4x4 array of uint_8 elements): reverse subbed block
    '''
    def _rev_sub_bytes(self, old_state):
        state = np.copy(old_state)

        for r in range(4):
            for c in range(4):
                state[r, c] = self.rsbox[state[r, c]]

        return state

    '''
    Method: _shift_rows (private)
    Parameters:
        old_state (numpy 4x4 array of uint_8 elements): block to be shifted
    Returns:
        state (numpy 4x4 array of uint_8 elements): shifted block
    '''
    def _shift_rows(self, old_state):
        state = np.copy(old_state)

        for r in range(4):
            for i in range(r):
                temp = state[r, 0]
                state[r, 0] = state[r, 1]
                state[r, 1] = state[r, 2]
                state[r, 2] = state[r, 3]
                state[r, 3] = temp

        return state
    
    '''
    Method: _rev_shift_rows (private)
    Parameters:
        old_state (numpy 4x4 array of uint_8 elements): block to be reverse shifted
    Returns:
        state (numpy 4x4 array of uint_8 elements): reverse shifted block
    '''
    def _rev_shift_rows(self, old_state):
        state = np.copy(old_state)

        for r in range(4):
            for i in range(r):
                temp = state[r, 3]
                state[r, 3] = state[r, 2]
                state[r, 2] = state[r, 1]
                state[r, 1] = state[r, 0]
                state[r, 0] = temp

        return state
    
    '''
    Method: _mix_columns (private)
    Parameters:
        state (numpy 4x4 array of uint_8 elements): block to be column mixed
    Returns:
        new_state (numpy 4x4 array of uint_8 elements): column mixed block
    '''
    def _mix_columns(self, state):
        new_state = np.zeros((4, 4), dtype=np.uint8)

        for c in range(4):
            new_state[0, c] = self._gf256_multiply(0x02, state[0, c]) ^ self._gf256_multiply(0x03, state[1, c]) ^ state[2, c] ^ state[3, c]
            new_state[1, c] = state[0, c] ^ self._gf256_multiply(0x02, state[1, c]) ^ self._gf256_multiply(0x03, state[2, c]) ^ state[3, c]
            new_state[2, c] = state[0, c] ^ state[1, c] ^ self._gf256_multiply(0x02, state[2, c]) ^ self._gf256_multiply(0x03, state[3, c])
            new_state[3, c] = self._gf256_multiply(0x03, state[0, c]) ^ state[1, c] ^ state[2, c] ^ self._gf256_multiply(0x02, state[3, c])

        return new_state
    
    '''
    Method: _rev_mix_columns (private)
    Parameters:
        state (numpy 4x4 array of uint_8 elements): block to be reverse column mixed
    Returns:
        new_state (numpy 4x4 array of uint_8 elements): reverse column mixed block
    '''
    def _rev_mix_columns(self, state):
        new_state = np.zeros((4, 4), dtype=np.uint8)

        for c in range(4):
            new_state[0, c] = self._gf256_multiply(0x0e, state[0, c]) ^ self._gf256_multiply(0x0b, state[1, c]) ^ self._gf256_multiply(0x0d, state[2, c]) ^ self._gf256_multiply(0x09, state[3, c])
            new_state[1, c] = self._gf256_multiply(0x09, state[0, c]) ^ self._gf256_multiply(0x0e, state[1, c]) ^ self._gf256_multiply(0x0b, state[2, c]) ^ self._gf256_multiply(0x0d, state[3, c])
            new_state[2, c] = self._gf256_multiply(0x0d, state[0, c]) ^ self._gf256_multiply(0x09, state[1, c]) ^ self._gf256_multiply(0x0e, state[2, c]) ^ self._gf256_multiply(0x0b, state[3, c])
            new_state[3, c] = self._gf256_multiply(0x0b, state[0, c]) ^ self._gf256_multiply(0x0d, state[1, c]) ^ self._gf256_multiply(0x09, state[2, c]) ^ self._gf256_multiply(0x0e, state[3, c])

        return new_state
    
    '''
    Method: _add_round_key (private)
    Parameters:
        state (numpy 4x4 array of uint_8 elements): block to have round key application
        w (numpy 4x4 array of uint_8 elements): subset of extended key
    Returns:
        new_state (numpy 4x4 array of uint_8 elements): block with round key application
    '''
    def _add_round_key(self, state, w):
        new_state = np.zeros((4, 4), dtype=np.uint8)

        for c in range(4):
            new_state[0, c] = state[0, c] ^ w[c][0]
            new_state[1, c] = state[1, c] ^ w[c][1]
            new_state[2, c] = state[2, c] ^ w[c][2]
            new_state[3, c] = state[3, c] ^ w[c][3]

        return new_state
    
    '''
    Method: _rev_add_round_key (private)
    Parameters:
        state (numpy 4x4 array of uint_8 elements): block to have round key application
        w (numpy 4x4 array of uint_8 elements): subset of extended key
    Returns:
        new_state (numpy 4x4 array of uint_8 elements): block with round key application
    '''
    def _rev_add_round_key(self, state, w):

        # reverse of function is itself
        return self._add_round_key(state, w)
    
    '''
    Method: _key_expansion (private)
    Parameters:
        key (32 byte array): initial (unexpanded) key
    Returns:
        w (numpy 60x4 array of uint_8 elements): expanded key formatted into numpy array
    '''
    def _key_expansion(self, key):
        w = np.zeros((60, 4), dtype=np.uint8)

        for i in range(8):
            wi_uint8 = np.frombuffer(key[4*i : 4*i+4], dtype=np.uint8)
            w[i] = wi_uint8

        for i in range(8, 60):
            temp = w[i-1]

            if i % 8 == 0:
                f0 = self.sbox[temp[1]].tobytes()
                f1 = self.sbox[temp[2]].tobytes()
                f2 = self.sbox[temp[3]].tobytes()
                f3 = self.sbox[temp[0]].tobytes()

                temp = f0[0:1] + f1[0:1] + f2[0:1] + f3[0:1]
                
                temp_uint8 = np.frombuffer(temp, dtype=np.uint8)
                rcon_uint8 = np.frombuffer(self.rcon[1], dtype=np.uint8)

                temp = temp_uint8 ^ rcon_uint8
            elif i % 8 == 4:
                f0 = self.sbox[temp[0]].tobytes()
                f1 = self.sbox[temp[1]].tobytes()
                f2 = self.sbox[temp[2]].tobytes()
                f3 = self.sbox[temp[3]].tobytes()

                temp = f0[0:1] + f1[0:1] + f2[0:1] + f3[0:1]
                
                temp_uint8 = np.frombuffer(temp, dtype=np.uint8)
                rcon_uint8 = np.frombuffer(self.rcon[1], dtype=np.uint8)

                temp = temp_uint8 ^ rcon_uint8

            w[i] = w[i - 8] ^ temp

        return w
    
    '''
    Method: _gf256_multiply (private)
    Parameters:
        a (uint_8): first byte for multiplication
        b (uint_8): second byte for multiplication
    Returns:
        p (uint_8): result of GF(2^8) multiplication between a and b
    Code Source:
        ChatGPT
    '''
    def _gf256_multiply(self, a, b):
        p = 0
        # Polynomial multiplication in GF(2^8)
        for i in range(8):
            if b & 1:
                p ^= a
            a <<= 1
            b >>= 1
            if a & 0x100:
                a ^= 0x11B  # Irreducible polynomial for GF(2^8)

        return p % 0x100
    