"""
ShadowGate Test Suite - Shellcode Encoder Tests
"""

import re
import pytest
from builder.encoder import ShellcodeEncoder


@pytest.fixture
def shellcode_64():
    """64 bytes of 0x90 NOP shellcode."""
    return bytes([0x90] * 64)


def test_uuid_encode_produces_string_list(shellcode_64):
    """UUID encoding returns a list of UUID strings."""
    encoder = ShellcodeEncoder()
    uuids, _cpp, _orig = encoder.encode_uuid(shellcode_64)
    assert isinstance(uuids, list)
    assert len(uuids) > 0
    assert all(isinstance(u, str) for u in uuids)


def test_uuid_encode_count(shellcode_64):
    """64 bytes encodes to exactly 4 UUIDs (16 bytes each)."""
    encoder = ShellcodeEncoder()
    uuids, _cpp, _orig = encoder.encode_uuid(shellcode_64)
    assert len(uuids) == 4


def test_uuid_string_format(shellcode_64):
    """Each UUID matches the xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format."""
    uuid_re = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE,
    )
    encoder = ShellcodeEncoder()
    uuids, _cpp, _orig = encoder.encode_uuid(shellcode_64)
    for u in uuids:
        assert uuid_re.match(u), f"UUID '{u}' does not match expected format"


def test_mac_encode_produces_string_list(shellcode_64):
    """MAC encoding returns a list of string items."""
    encoder = ShellcodeEncoder()
    macs, _cpp, _orig = encoder.encode_mac(shellcode_64)
    assert isinstance(macs, list)
    assert len(macs) > 0
    assert all(isinstance(m, str) for m in macs)


def test_mac_string_format(shellcode_64):
    """Each MAC address matches XX-XX-XX-XX-XX-XX (dash-separated uppercase hex)."""
    mac_re = re.compile(r'^[0-9A-F]{2}(-[0-9A-F]{2}){5}$')
    encoder = ShellcodeEncoder()
    macs, _cpp, _orig = encoder.encode_mac(shellcode_64)
    for m in macs:
        assert mac_re.match(m), f"MAC '{m}' does not match expected format"


def test_ipv4_encode_produces_string_list(shellcode_64):
    """IPv4 encoding returns a list of IP strings."""
    encoder = ShellcodeEncoder()
    ips, _cpp, _orig = encoder.encode_ipv4(shellcode_64)
    assert isinstance(ips, list)
    assert len(ips) > 0
    assert all(isinstance(ip, str) for ip in ips)


def test_ipv4_string_format(shellcode_64):
    """Each IPv4 string matches dotted-decimal format (d.d.d.d)."""
    ipv4_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    encoder = ShellcodeEncoder()
    ips, _cpp, _orig = encoder.encode_ipv4(shellcode_64)
    for ip in ips:
        assert ipv4_re.match(ip), f"IP '{ip}' does not match expected format"


def test_raw_encode_produces_hex_array(shellcode_64):
    """Raw encoding returns a C-style hex byte array in the C++ string."""
    encoder = ShellcodeEncoder()
    raw_data, cpp, _orig = encoder.encode_raw(shellcode_64)
    assert "0x90" in cpp  # NOP bytes appear as hex
    assert "g_EncodedShellcode" in cpp


def test_encode_padding():
    """Payloads not a multiple of chunk size are padded correctly."""
    encoder = ShellcodeEncoder()
    # 10 bytes is not a multiple of 16 (UUID) — should be padded to 16
    sc = bytes([0xCC] * 10)
    uuids, _cpp, orig = encoder.encode_uuid(sc)
    assert orig == 10  # original size preserved
    assert len(uuids) == 1  # ceil(10/16) = 1 UUID
