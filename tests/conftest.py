"""
ShadowGate Test Suite - Shared Fixtures
"""

import pytest
import os
import tempfile
from pathlib import Path
from builder.config import BuildConfig
from builder.hashing import HashEngine
from builder.crypto import CryptoEngine
from builder.encoder import ShellcodeEncoder


@pytest.fixture
def dummy_shellcode():
    """64 bytes of dummy shellcode (all 0x90 NOP sled)"""
    return bytes([0x90] * 64)


@pytest.fixture
def temp_shellcode_file(dummy_shellcode, tmp_path):
    """Write dummy shellcode to a temp file and return the path"""
    sc_file = tmp_path / "payload.bin"
    sc_file.write_bytes(dummy_shellcode)
    return sc_file


@pytest.fixture
def default_config(temp_shellcode_file, tmp_path):
    """A default BuildConfig with all defaults"""
    return BuildConfig(
        input_file=str(temp_shellcode_file),
        output_file=str(tmp_path / "implant.exe"),
    )


@pytest.fixture
def hasher():
    return HashEngine()


@pytest.fixture
def crypto():
    return CryptoEngine()


@pytest.fixture
def encoder():
    return ShellcodeEncoder()
