"""
ShadowGate Test Suite - Builder Coverage Tests
Tests _generate_* methods in CodeGenerator that are not exercised by other test files.
"""

import pytest
from pathlib import Path
from builder.builder import CodeGenerator
from builder.config import BuildConfig

BASE_DIR = Path(__file__).parent.parent


def make_gen(**kwargs) -> CodeGenerator:
    """Create a CodeGenerator with optional BuildConfig overrides."""
    config = BuildConfig(**kwargs)
    return CodeGenerator(config, BASE_DIR)


# ============================================================================
# _generate_sleep_obf_files
# ============================================================================

def test_sleep_obf_files_keys():
    """_generate_sleep_obf_files returns sleep_obf.h and sleep_obf.cpp."""
    gen = make_gen()
    files = gen._generate_sleep_obf_files()
    assert "sleep_obf.h" in files
    assert "sleep_obf.cpp" in files


def test_sleep_obf_h_has_include_guard():
    """sleep_obf.h contains the expected include guard."""
    gen = make_gen()
    h = gen._generate_sleep_obf_files()["sleep_obf.h"]
    assert "#ifndef _SLEEP_OBF_H" in h
    assert "#include <windows.h>" in h


def test_sleep_obf_cpp_has_obfuscated_sleep_function():
    """sleep_obf.cpp defines the ObfuscatedSleep function."""
    gen = make_gen()
    cpp = gen._generate_sleep_obf_files()["sleep_obf.cpp"]
    assert "ObfuscatedSleep" in cpp


# ============================================================================
# _generate_callstack_spoof_files
# ============================================================================

def test_callstack_spoof_files_keys():
    """_generate_callstack_spoof_files returns callstack.h and callstack.cpp."""
    gen = make_gen()
    files = gen._generate_callstack_spoof_files()
    assert "callstack.h" in files
    assert "callstack.cpp" in files


def test_callstack_h_has_include_guard():
    """callstack.h contains the expected include guard."""
    gen = make_gen()
    h = gen._generate_callstack_spoof_files()["callstack.h"]
    assert "#ifndef _CALLSTACK_H" in h
    assert "#include <windows.h>" in h


def test_callstack_cpp_has_create_spoofed_thread():
    """callstack.cpp defines CreateSpoofedThread."""
    gen = make_gen()
    cpp = gen._generate_callstack_spoof_files()["callstack.cpp"]
    assert "CreateSpoofedThread" in cpp


# ============================================================================
# _generate_dynapi_files
# ============================================================================

def test_dynapi_files_keys():
    """_generate_dynapi_files returns dynapi.h and dynapi.cpp."""
    gen = make_gen()
    files = gen._generate_dynapi_files()
    assert "dynapi.h" in files
    assert "dynapi.cpp" in files


def test_dynapi_h_has_include_guard():
    """dynapi.h contains the expected include guard."""
    gen = make_gen()
    h = gen._generate_dynapi_files()["dynapi.h"]
    assert "#ifndef _DYNAPI_H" in h
    assert "InitializeDynamicAPIs" in h


def test_dynapi_cpp_has_init_function():
    """dynapi.cpp defines InitializeDynamicAPIs."""
    gen = make_gen()
    cpp = gen._generate_dynapi_files()["dynapi.cpp"]
    assert "InitializeDynamicAPIs" in cpp
    assert "VirtualAlloc" in cpp


# ============================================================================
# _generate_common_files / _generate_common_h
# ============================================================================

def test_common_files_key():
    """_generate_common_files returns common.h."""
    gen = make_gen()
    files = gen._generate_common_files()
    assert "common.h" in files


def test_common_h_has_nt_structures():
    """common.h contains core NT structure definitions."""
    gen = make_gen()
    h = gen._generate_common_h()
    assert "UNICODE_STRING" in h
    assert "PEB_LDR_DATA" in h
    assert "#ifndef _COMMON_H" in h


def test_common_h_has_debug_macros():
    """common.h contains LOG_INFO and LOG_ERROR debug macros."""
    gen = make_gen()
    h = gen._generate_common_h()
    assert "LOG_INFO" in h
    assert "LOG_ERROR" in h


# ============================================================================
# full generate() with optional features enabled
# ============================================================================

def test_generate_with_sleep_obfuscation_includes_files():
    """generate() with sleep_obfuscation=True includes sleep_obf.h and sleep_obf.cpp."""
    config = BuildConfig(sleep_obfuscation=True)
    gen = CodeGenerator(config, BASE_DIR)
    files = gen.generate(b'\x90' * 64)
    assert "sleep_obf.h" in files
    assert "sleep_obf.cpp" in files


def test_generate_with_callstack_spoof_includes_files():
    """generate() with callstack_spoof=True includes callstack.h and callstack.cpp."""
    config = BuildConfig(callstack_spoof=True)
    gen = CodeGenerator(config, BASE_DIR)
    files = gen.generate(b'\x90' * 64)
    assert "callstack.h" in files
    assert "callstack.cpp" in files


def test_generate_with_dynapi_includes_files():
    """generate() with dynapi=True includes dynapi.h and dynapi.cpp."""
    config = BuildConfig(dynapi=True)
    gen = CodeGenerator(config, BASE_DIR)
    files = gen.generate(b'\x90' * 64)
    assert "dynapi.h" in files
    assert "dynapi.cpp" in files


def test_generate_with_edr_freeze_includes_files():
    """generate() with edr_freeze=True includes edr_freeze.h and edr_freeze.cpp."""
    config = BuildConfig(edr_freeze=True)
    gen = CodeGenerator(config, BASE_DIR)
    files = gen.generate(b'\x90' * 64)
    assert "edr_freeze.h" in files
    assert "edr_freeze.cpp" in files
