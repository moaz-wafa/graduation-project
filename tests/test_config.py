"""
ShadowGate Test Suite - BuildConfig Validation Tests
"""

import pytest
from builder.config import BuildConfig


def test_default_config_valid():
    """Default config passes validate() without errors."""
    config = BuildConfig()
    valid, msg = config.validate()
    assert valid is True, f"Default config should be valid, got: {msg}"


@pytest.mark.parametrize("inject", [
    "stomp", "earlybird", "remotethread", "hollowing",
    "mapping", "threadpool_real", "earlycascade", "callback",
])
def test_inject_values(inject, temp_shellcode_file, tmp_path):
    """All valid inject values are accepted."""
    config = BuildConfig(
        input_file=str(temp_shellcode_file),
        inject=inject,
    )
    valid, msg = config.validate()
    assert valid is True, f"inject='{inject}' should be valid, got: {msg}"


def test_inject_invalid(temp_shellcode_file):
    """Invalid inject value returns validation error."""
    config = BuildConfig(input_file=str(temp_shellcode_file), inject="invalid_method")
    valid, msg = config.validate()
    assert valid is False
    assert "injection" in msg.lower() or "invalid" in msg.lower()


@pytest.mark.parametrize("syscall", ["direct", "indirect"])
def test_syscall_values(syscall, temp_shellcode_file):
    """'direct' and 'indirect' syscall values are accepted."""
    config = BuildConfig(input_file=str(temp_shellcode_file), syscall=syscall)
    valid, msg = config.validate()
    assert valid is True, f"syscall='{syscall}' should be valid, got: {msg}"


@pytest.mark.parametrize("encrypt", ["xor", "aes", "cascade"])
def test_encrypt_values(encrypt, temp_shellcode_file):
    """'xor', 'aes', 'cascade' encryption values are accepted."""
    config = BuildConfig(input_file=str(temp_shellcode_file), encrypt=encrypt)
    valid, msg = config.validate()
    assert valid is True, f"encrypt='{encrypt}' should be valid, got: {msg}"


@pytest.mark.parametrize("encode", ["uuid", "mac", "ipv4", "raw"])
def test_encode_values(encode, temp_shellcode_file):
    """'uuid', 'mac', 'ipv4', 'raw' encode values are accepted."""
    config = BuildConfig(input_file=str(temp_shellcode_file), encode=encode)
    valid, msg = config.validate()
    assert valid is True, f"encode='{encode}' should be valid, got: {msg}"


@pytest.mark.parametrize("resolver", ["peb", "fresh", "hybrid"])
def test_resolver_values(resolver, temp_shellcode_file):
    """'peb', 'fresh', 'hybrid' resolver values are accepted."""
    config = BuildConfig(input_file=str(temp_shellcode_file), resolver=resolver)
    valid, msg = config.validate()
    assert valid is True, f"resolver='{resolver}' should be valid, got: {msg}"


@pytest.mark.parametrize("strings", ["none", "djb2", "xor", "stack"])
def test_strings_values(strings, temp_shellcode_file):
    """'none', 'djb2', 'xor', 'stack' string-hiding values are accepted."""
    config = BuildConfig(input_file=str(temp_shellcode_file), strings=strings)
    valid, msg = config.validate()
    assert valid is True, f"strings='{strings}' should be valid, got: {msg}"


@pytest.mark.parametrize("output_format", ["pe", "dll", "svc"])
def test_output_format_values(output_format, temp_shellcode_file):
    """'pe', 'dll', 'svc' output format values are accepted."""
    config = BuildConfig(input_file=str(temp_shellcode_file), output_format=output_format)
    valid, msg = config.validate()
    assert valid is True, f"output_format='{output_format}' should be valid, got: {msg}"


def test_output_format_invalid(temp_shellcode_file):
    """Invalid output format returns validation error."""
    config = BuildConfig(input_file=str(temp_shellcode_file), output_format="elf")
    valid, msg = config.validate()
    assert valid is False
    assert "format" in msg.lower() or "invalid" in msg.lower()


def test_ppid_spoof_must_end_with_exe(temp_shellcode_file):
    """ppid_spoof without .exe returns validation error; with .exe passes."""
    # Without .exe - should fail
    config_bad = BuildConfig(input_file=str(temp_shellcode_file), ppid_spoof="explorer")
    valid, msg = config_bad.validate()
    assert valid is False, "ppid_spoof='explorer' should fail validation"
    assert ".exe" in msg.lower() or "ppid" in msg.lower()

    # With .exe - should pass
    config_good = BuildConfig(input_file=str(temp_shellcode_file), ppid_spoof="explorer.exe")
    valid2, msg2 = config_good.validate()
    assert valid2 is True, f"ppid_spoof='explorer.exe' should be valid, got: {msg2}"


def test_sleep_must_be_non_negative(temp_shellcode_file):
    """sleep field defaults to 0 (non-negative)."""
    config = BuildConfig(input_file=str(temp_shellcode_file), sleep=0)
    valid, msg = config.validate()
    assert valid is True

    # Also test a positive value
    config2 = BuildConfig(input_file=str(temp_shellcode_file), sleep=5)
    valid2, msg2 = config2.validate()
    assert valid2 is True


def test_all_bool_flags():
    """All boolean flags default to their expected values."""
    config = BuildConfig()

    # Sandbox and ETW default to True (from DEFAULT_PROFILE)
    assert config.sandbox is True
    assert config.etw is True

    # Others default to False
    assert config.unhook is False
    assert config.edr_freeze is False
    assert config.edr_preload is False
    assert config.disable_preloaded_edr is False
    assert config.freeze is False
    assert config.spoof_cmdline is False
    assert config.block_dlls is False
    assert config.syscall_hash is False
    assert config.debug is False

    # All are booleans
    for attr in [
        "sandbox", "etw", "unhook", "edr_freeze", "edr_preload",
        "disable_preloaded_edr", "freeze", "spoof_cmdline",
        "block_dlls", "syscall_hash", "debug",
    ]:
        assert isinstance(getattr(config, attr), bool), f"{attr} should be bool"
