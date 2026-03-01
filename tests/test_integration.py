"""
ShadowGate Test Suite - Full Pipeline Integration Tests
"""

import pytest
from pathlib import Path
from builder.builder import CodeGenerator, ShadowGateBuilder
from builder.config import BuildConfig


BASE_DIR = Path(__file__).parent.parent
SHELLCODE = bytes([0x90] * 64)


def run_builder_no_compile(config: BuildConfig) -> dict:
    """Run the code generator (no compile), return dict of {filename: content}."""
    gen = CodeGenerator(config, BASE_DIR)
    return gen.generate(SHELLCODE)


def test_default_build_generates_expected_files():
    """Default config generates all expected source files."""
    files = run_builder_no_compile(BuildConfig())
    expected = [
        "main.cpp",
        "injection.cpp",
        "injection.h",
        "evasion.cpp",
        "evasion.h",
        "syscalls.h",
        "resolver.cpp",
    ]
    for fname in expected:
        assert fname in files, f"Expected file '{fname}' not found in generated output"


@pytest.mark.parametrize("inject", [
    "stomp", "earlybird", "remotethread", "hollowing",
    "mapping", "threadpool_real", "earlycascade", "callback",
])
def test_all_injection_methods_generate_without_error(inject):
    """All injection methods generate without raising exceptions."""
    config = BuildConfig(inject=inject)
    files = run_builder_no_compile(config)
    assert len(files) > 0, f"No files generated for inject='{inject}'"


@pytest.mark.parametrize("encrypt", ["xor", "aes", "cascade"])
def test_all_encrypt_modes_generate_without_error(encrypt):
    """All encryption modes generate without raising exceptions."""
    config = BuildConfig(encrypt=encrypt)
    files = run_builder_no_compile(config)
    assert len(files) > 0, f"No files generated for encrypt='{encrypt}'"


@pytest.mark.parametrize("encode", ["uuid", "mac", "ipv4", "raw"])
def test_all_encode_modes_generate_without_error(encode):
    """All encoding modes generate without raising exceptions."""
    config = BuildConfig(encode=encode)
    files = run_builder_no_compile(config)
    assert len(files) > 0, f"No files generated for encode='{encode}'"


@pytest.mark.parametrize("output_format", ["pe", "dll", "svc"])
def test_all_output_formats_generate_without_error(output_format):
    """All output formats generate without raising exceptions."""
    config = BuildConfig(output_format=output_format)
    files = run_builder_no_compile(config)
    assert len(files) > 0, f"No files generated for output_format='{output_format}'"


@pytest.mark.parametrize("syscall", ["direct", "indirect"])
def test_all_syscall_modes_generate_without_error(syscall):
    """Both syscall modes generate without raising exceptions."""
    config = BuildConfig(syscall=syscall)
    files = run_builder_no_compile(config)
    assert len(files) > 0, f"No files generated for syscall='{syscall}'"


def test_max_stealth_build():
    """All stealth flags enabled simultaneously — all files generated, all defines are 1."""
    import re

    config = BuildConfig(
        inject="earlycascade",
        syscall="indirect",
        encrypt="cascade",
        encode="uuid",
        resolver="hybrid",
        strings="djb2",
        sandbox=True,
        etw=True,
        unhook=True,
        edr_freeze=True,
        edr_preload=True,
        disable_preloaded_edr=True,
        freeze=True,
        spoof_cmdline=True,
        ppid_spoof="explorer.exe",
        block_dlls=True,
        syscall_hash=True,
        output_format="pe",
    )
    files = run_builder_no_compile(config)
    assert "main.cpp" in files

    main = files["main.cpp"]
    for define in [
        "ENABLE_EDR_FREEZE",
        "ENABLE_EDR_PRELOAD",
        "ENABLE_DISABLE_PRELOADED_EDR",
        "ENABLE_FREEZE",
        "ENABLE_CMDLINE_SPOOF",
        "ENABLE_PPID_SPOOF",
        "ENABLE_BLOCK_DLLS",
        "ENABLE_SYSCALL_HASH",
        "ENABLE_SANDBOX",
        "ENABLE_ETW_PATCH",
        "ENABLE_UNHOOK",
    ]:
        match = re.search(rf'#define\s+{define}\s+(\d+)', main)
        assert match, f"{define} not found as #define in main.cpp"
        assert match.group(1) == "1", f"{define} should be 1 but is {match.group(1)}"


def test_dll_max_stealth_build():
    """All stealth flags + output_format=dll — dllmain.cpp generated with correct defines."""
    import re

    config = BuildConfig(
        inject="earlycascade",
        syscall="indirect",
        encrypt="cascade",
        encode="uuid",
        edr_freeze=True,
        edr_preload=True,
        disable_preloaded_edr=True,
        freeze=True,
        spoof_cmdline=True,
        ppid_spoof="svchost.exe",
        block_dlls=True,
        syscall_hash=True,
        output_format="dll",
    )
    files = run_builder_no_compile(config)
    assert "dllmain.cpp" in files
    dll = files["dllmain.cpp"]
    assert "DllMain" in dll
    for define in ["ENABLE_EDR_FREEZE", "ENABLE_SYSCALL_HASH", "ENABLE_BLOCK_DLLS"]:
        match = re.search(rf'#define\s+{define}\s+(\d+)', dll)
        assert match and match.group(1) == "1", f"{define} should be 1 in dllmain.cpp"


def test_svc_max_stealth_build():
    """All stealth flags + output_format=svc — svcmain.cpp generated with correct defines."""
    import re

    config = BuildConfig(
        inject="earlycascade",
        syscall="indirect",
        encrypt="cascade",
        encode="uuid",
        edr_freeze=True,
        block_dlls=True,
        syscall_hash=True,
        output_format="svc",
    )
    files = run_builder_no_compile(config)
    assert "svcmain.cpp" in files
    svc = files["svcmain.cpp"]
    assert "ServiceMain" in svc
    for define in ["ENABLE_EDR_FREEZE", "ENABLE_SYSCALL_HASH", "ENABLE_BLOCK_DLLS"]:
        match = re.search(rf'#define\s+{define}\s+(\d+)', svc)
        assert match and match.group(1) == "1", f"{define} should be 1 in svcmain.cpp"


def test_generated_source_has_no_raw_shellcode():
    """With encryption enabled, raw NOP sled bytes do not appear verbatim in UUID-encoded source."""
    config = BuildConfig(encrypt="cascade", encode="uuid")
    files = run_builder_no_compile(config)
    # UUID encoding stores strings not raw hex bytes in the array,
    # so raw "0x90, 0x90" should not appear in the main source
    main = files["main.cpp"]
    # UUID format uses quoted strings like "90909090-..." not raw hex arrays
    # The raw NOP bytes should not be the final form stored
    assert "g_EncodedShellcode" in main  # Encoded form is present
    # Raw C hex array of 0x90 bytes would only appear in 'raw' encoding mode
    # In UUID mode, content is string-based, verify no raw 0x90 C array
    assert '{ 0x90, 0x90' not in main


def test_builder_source_files_are_utf8():
    """All generated source files are valid UTF-8 (no binary garbage)."""
    files = run_builder_no_compile(BuildConfig())
    for filename, content in files.items():
        assert isinstance(content, str), f"{filename} content is not a string"
        try:
            content.encode("utf-8")
        except UnicodeEncodeError as e:
            pytest.fail(f"{filename} contains invalid UTF-8: {e}")


def test_callback_injection_randomization():
    """Callback injection builder produces multiple different callback methods across runs."""
    methods_seen = set()
    known_methods = [
        "EnumCalendarInfoA",
        "CertEnumSystemStore",
        "EnumChildWindows",
        "CreateFiber",
        "EnumWindows",
        "EnumDesktopWindows",
        "SetTimer",
        "CryptEnumOIDInfo",
        "EnumResourceTypesA",
    ]

    config = BuildConfig(inject="callback")
    # 10 iterations is sufficient to observe at least 2 different methods
    for _ in range(10):
        files = run_builder_no_compile(config)
        cb = files.get("callback.cpp", "")
        for method in known_methods:
            if method in cb:
                methods_seen.add(method)

    assert len(methods_seen) >= 2, (
        f"Expected at least 2 different callback methods across runs, "
        f"but only saw: {methods_seen}"
    )
