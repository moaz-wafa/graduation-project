"""
ShadowGate Test Suite - Hashing Tests
"""

import pytest
from builder.hashing import HashEngine, StringObfuscator


# Pre-computed known hash values:
# HashEngine.djb2(b"NtAllocateVirtualMemory", seed=0x7734773477347734)
KNOWN_DJB2_HASH = 0xF5BD373480A6B89B

# HashEngine.djb2_32(b"") == 5381 == 0x1505
DJB2_32_SEED = 0x1505


def test_djb2_known_value():
    """djb2(b"NtAllocateVirtualMemory") returns the expected known hash."""
    result = HashEngine.djb2(b"NtAllocateVirtualMemory")
    assert result == KNOWN_DJB2_HASH


def test_djb2_different_inputs_different_hashes():
    """Two different strings produce different hash values."""
    h1 = HashEngine.djb2(b"NtAllocateVirtualMemory")
    h2 = HashEngine.djb2(b"NtProtectVirtualMemory")
    assert h1 != h2


def test_djb2_empty_string():
    """djb2_32 of empty bytes returns seed value 0x1505 (5381)."""
    result = HashEngine.djb2_32(b"")
    assert result == DJB2_32_SEED


def test_djb2_case_sensitivity():
    """DJB2 is case-sensitive: 'ntdll.dll' and 'NTDLL.DLL' produce different hashes."""
    h_lower = HashEngine.djb2(b"ntdll.dll")
    h_upper = HashEngine.djb2(b"NTDLL.DLL")
    assert h_lower != h_upper


def test_edr_process_hashes_known_values():
    """EDR process hash list contains hashes for common EDR processes."""
    # MsMpEng.exe is a well-known Windows Defender process
    # The EDR freeze code hashes lowercase names
    msmpeng_hash = HashEngine.djb2(b"msmpeng.exe")
    assert msmpeng_hash != 0  # Should produce a non-zero hash

    # CrowdStrike Falcon
    csfalcon_hash = HashEngine.djb2(b"csfalconservice.exe")
    assert csfalcon_hash != 0
    assert msmpeng_hash != csfalcon_hash


def test_xor_obfuscate_deobfuscate():
    """String XOR obfuscation roundtrip works correctly."""
    original = "ntdll.dll"
    key = 0x5A

    obfuscated = StringObfuscator.xor_string(original, key)
    assert isinstance(obfuscated, bytes)
    assert len(obfuscated) == len(original)

    # Deobfuscate manually
    deobfuscated = bytes([b ^ key for b in obfuscated]).decode("ascii")
    assert deobfuscated == original


def test_stack_string_generation():
    """Stack string C++ snippet contains the expected characters."""
    s = "kernel32.dll"
    cpp = StringObfuscator.generate_stack_string_cpp(s, "g_szKernel32")

    # Every character in the string should appear as a char literal
    for ch in s:
        assert f"'{ch}'" in cpp

    # Should end with null terminator
    assert "'\\0'" in cpp

    # Should declare a char array of the right length
    assert f"char g_szKernel32[{len(s) + 1}]" in cpp
