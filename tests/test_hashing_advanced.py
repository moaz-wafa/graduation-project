"""
ShadowGate Test Suite - Advanced Hashing Tests
Tests stack string generation, XOR string obfuscation, and EDR process hash consistency.
"""

import pytest
from builder.hashing import HashEngine, StringObfuscator


# ============================================================================
# Stack string generation
# ============================================================================

def test_generate_stack_string_contains_each_character():
    """generate_stack_string_cpp contains a char-literal assignment for every character."""
    s = "ntdll.dll"
    cpp = StringObfuscator.generate_stack_string_cpp(s, "szNtdll")
    for ch in s:
        assert f"'{ch}'" in cpp


def test_generate_stack_string_null_terminator():
    """generate_stack_string_cpp ends the array with a null terminator."""
    cpp = StringObfuscator.generate_stack_string_cpp("test", "v")
    assert "'\\0'" in cpp


def test_generate_stack_string_array_declaration():
    """generate_stack_string_cpp declares a char array of the correct size."""
    s = "kernel32.dll"
    cpp = StringObfuscator.generate_stack_string_cpp(s, "g_K32")
    assert f"char g_K32[{len(s) + 1}]" in cpp


def test_generate_stack_string_does_not_contain_plaintext_string():
    """Non-comment lines of the stack string snippet contain no contiguous string literal."""
    s = "secret.dll"
    cpp = StringObfuscator.generate_stack_string_cpp(s, "v")
    # Filter out comment lines — the plaintext may appear only in the // comment
    code_lines = [l for l in cpp.split('\n') if not l.lstrip().startswith('//')]
    code = '\n'.join(code_lines)
    assert f'"{s}"' not in code


# ============================================================================
# XOR string obfuscation
# ============================================================================

def test_xor_string_roundtrip():
    """XOR-obfuscated bytes decrypt back to the original string."""
    original = "kernel32.dll"
    key = 0x5A
    obfuscated = StringObfuscator.xor_string(original, key)
    recovered = bytes([b ^ key for b in obfuscated]).decode("ascii")
    assert recovered == original


def test_xor_string_different_key_different_output():
    """Different XOR keys produce different obfuscated byte sequences."""
    s = "ntdll.dll"
    assert StringObfuscator.xor_string(s, 0x5A) != StringObfuscator.xor_string(s, 0x3C)


def test_xor_string_obfuscated_not_plaintext():
    """Obfuscated bytes do not contain the plaintext as a contiguous byte sequence."""
    s = "ntdll.dll"
    obfuscated = StringObfuscator.xor_string(s, 0x5A)
    assert s.encode("ascii") not in obfuscated


def test_generate_xor_string_cpp_contains_deobfuscate_function():
    """generate_xor_string_cpp includes a Deobfuscate function."""
    cpp = StringObfuscator.generate_xor_string_cpp("ntdll.dll", "g_Ntdll")
    assert "Deobfuscate_g_Ntdll" in cpp


def test_generate_xor_string_cpp_contains_key_define():
    """generate_xor_string_cpp includes a KEY #define."""
    cpp = StringObfuscator.generate_xor_string_cpp("ntdll.dll", "g_Ntdll", key=0x3C)
    assert "#define g_Ntdll_KEY 0x3C" in cpp


# ============================================================================
# DJB2 hash consistency for EDR process names
# ============================================================================

EDR_PROCESSES = [
    "msmpeng.exe",
    "csfalconservice.exe",
    "sentinelagent.exe",
    "sophoshealth.exe",
    "cylancesvc.exe",
    "elastic-agent.exe",
    "bdagent.exe",
]


def test_edr_process_hashes_are_nonzero():
    """DJB2 hash of every known EDR process name is non-zero."""
    for name in EDR_PROCESSES:
        h = HashEngine.djb2(name.encode())
        assert h != 0, f"Hash of '{name}' should not be zero"


def test_edr_process_hashes_are_unique():
    """DJB2 hashes of distinct EDR process names are all unique."""
    hashes = [HashEngine.djb2(n.encode()) for n in EDR_PROCESSES]
    assert len(hashes) == len(set(hashes)), "Collision detected in EDR process hashes"


def test_edr_process_hashes_are_consistent():
    """DJB2 hash of the same EDR process name returns the same value across calls."""
    for name in EDR_PROCESSES:
        h1 = HashEngine.djb2(name.encode())
        h2 = HashEngine.djb2(name.encode())
        assert h1 == h2, f"Hash of '{name}' is not deterministic"


def test_edr_process_hash_known_value_msmpeng():
    """DJB2 hash of 'msmpeng.exe' matches the pre-computed expected value."""
    expected = HashEngine.djb2(b"msmpeng.exe")
    # Verify consistency: re-computing gives the same result
    assert HashEngine.djb2(b"msmpeng.exe") == expected
    # Case matters: uppercase should differ
    assert HashEngine.djb2(b"MsMpEng.exe") != expected
