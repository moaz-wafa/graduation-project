"""
ShadowGate Test Suite - Entropy Tests
"""

import os
import pytest
from builder.entropy import EntropyAnalyzer, TARGET_ENTROPY


def test_entropy_all_zeros_is_zero():
    """Shannon entropy of all-zero bytes is 0.0."""
    assert EntropyAnalyzer.calculate_entropy(b'\x00' * 1000) == 0.0


def test_entropy_random_bytes_is_high():
    """Shannon entropy of random bytes is > 6.0."""
    data = os.urandom(1024)
    assert EntropyAnalyzer.calculate_entropy(data) > 6.0


def test_encrypted_entropy_higher_than_plaintext():
    """Encrypting patterned data raises entropy above the plaintext value."""
    # Low-entropy plaintext: only 4 distinct byte values
    plaintext = bytes([i % 4 for i in range(512)])
    # XOR each byte with a rotating key: produces 256 distinct byte values → entropy ≈ 8.0
    key = bytes(range(256)) * 2
    encrypted = bytes([b ^ k for b, k in zip(plaintext, key)])
    assert EntropyAnalyzer.calculate_entropy(encrypted) > EntropyAnalyzer.calculate_entropy(plaintext)


def test_entropy_empty_input():
    """Entropy analyzer returns 0.0 for empty input without raising."""
    result = EntropyAnalyzer.calculate_entropy(b'')
    assert result == 0.0


def test_analyze_sections_returns_correct_offsets():
    """Per-section analysis returns (offset, entropy) tuples with correct offsets."""
    data = bytes(range(256)) * 4  # 1024 bytes
    section_size = 256
    sections = EntropyAnalyzer.analyze_sections(data, section_size=section_size)

    assert len(sections) == 4
    for i, (offset, entropy) in enumerate(sections):
        assert offset == i * section_size
        assert 0.0 <= entropy <= 8.0


def test_analyze_sections_single_section():
    """analyze_sections handles data smaller than one section."""
    data = b'\x41' * 10
    sections = EntropyAnalyzer.analyze_sections(data, section_size=256)
    assert len(sections) == 1
    assert sections[0][0] == 0


def test_entropy_rating_thresholds():
    """get_entropy_rating returns expected strings for low/normal/high/very-high."""
    assert "LOW" in EntropyAnalyzer.get_entropy_rating(2.0)
    assert "NORMAL" in EntropyAnalyzer.get_entropy_rating(5.0)
    assert "HIGH" in EntropyAnalyzer.get_entropy_rating(6.5)
    assert "VERY HIGH" in EntropyAnalyzer.get_entropy_rating(7.5)


def test_is_acceptable_below_target():
    """is_acceptable returns True when entropy is below or equal to target."""
    assert EntropyAnalyzer.is_acceptable(TARGET_ENTROPY) is True
    assert EntropyAnalyzer.is_acceptable(TARGET_ENTROPY - 0.1) is True


def test_is_acceptable_above_target():
    """is_acceptable returns False when entropy exceeds the target."""
    assert EntropyAnalyzer.is_acceptable(TARGET_ENTROPY + 0.1) is False


def test_analyze_and_report_keys():
    """analyze_and_report returns a dict with expected keys."""
    analyzer = EntropyAnalyzer()
    report = analyzer.analyze_and_report(b'\x00' * 100, name="TestData")
    for key in ("name", "size", "entropy", "rating", "acceptable", "target"):
        assert key in report
    assert report["name"] == "TestData"
    assert report["size"] == 100
