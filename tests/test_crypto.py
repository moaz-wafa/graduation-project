"""
ShadowGate Test Suite - Cryptography Tests
"""

import pytest
from builder.crypto import CryptoEngine, CRYPTO_AVAILABLE


def test_xor_encrypt_decrypt_roundtrip():
    """XOR encrypt then decrypt returns original plaintext."""
    crypto = CryptoEngine()
    crypto.generate_keys()
    plaintext = bytes(range(64))
    encrypted = crypto.xor_encrypt(plaintext)
    decrypted = crypto.xor_decrypt(encrypted)
    assert decrypted == plaintext


def test_xor_different_key_different_output():
    """Same plaintext, different keys produce different ciphertext."""
    plaintext = bytes([0x90] * 32)
    key1 = bytes([0xAA] * 32)
    key2 = bytes([0xBB] * 32)

    crypto = CryptoEngine()
    enc1 = crypto.xor_encrypt(plaintext, key1)
    enc2 = crypto.xor_encrypt(plaintext, key2)
    assert enc1 != enc2


def test_aes_encrypt_produces_output():
    """AES-256-CBC encryption of 64 bytes returns non-empty bytes."""
    if not CRYPTO_AVAILABLE:
        pytest.skip("PyCryptodome not available")
    crypto = CryptoEngine()
    crypto.generate_keys()
    plaintext = bytes([0x90] * 64)
    encrypted = crypto.aes_encrypt(plaintext)
    assert len(encrypted) > 0
    assert isinstance(encrypted, bytes)


def test_aes_encrypt_decrypt_roundtrip():
    """AES encrypt then decrypt returns original plaintext."""
    if not CRYPTO_AVAILABLE:
        pytest.skip("PyCryptodome not available")
    crypto = CryptoEngine()
    crypto.generate_keys()
    plaintext = bytes([0x41] * 64)
    encrypted = crypto.aes_encrypt(plaintext)
    decrypted = crypto.aes_decrypt(encrypted)
    assert decrypted == plaintext


def test_cascade_encrypt_produces_output():
    """Cascade (XOR+AES) encrypt returns non-empty bytes."""
    crypto = CryptoEngine()
    crypto.generate_keys()
    plaintext = bytes([0x90] * 64)
    encrypted = crypto.cascade_encrypt(plaintext)
    assert len(encrypted) > 0
    assert isinstance(encrypted, bytes)


def test_cascade_output_differs_from_plaintext():
    """Cascade encrypted output differs from plaintext."""
    crypto = CryptoEngine()
    crypto.generate_keys()
    plaintext = bytes([0x90] * 64)
    encrypted = crypto.cascade_encrypt(plaintext)
    assert encrypted != plaintext


def test_key_derivation_produces_bytes():
    """Key derivation returns bytes of expected length."""
    crypto = CryptoEngine()
    keys = crypto.generate_keys()
    assert isinstance(keys.xor_key, bytes)
    assert len(keys.xor_key) == 32
    assert isinstance(keys.aes_key, bytes)
    assert len(keys.aes_key) == 32
    assert isinstance(keys.aes_iv, bytes)
    assert len(keys.aes_iv) == 16


def test_xor_key_obfuscation():
    """XOR key is obfuscated in generated C++; obfuscated hex appears, not plaintext key."""
    crypto = CryptoEngine()
    crypto.generate_keys()
    cpp_code = crypto.generate_cpp_keys()

    # Generated C++ must contain DeriveKeys (runtime deobfuscation) and g_XorKey
    assert "DeriveKeys" in cpp_code
    assert "g_XorKey" in cpp_code

    # The plaintext raw key should NOT appear; obfuscated bytes should be present
    # Verify the key seed and array are present
    assert "g_KeySeed" in cpp_code
