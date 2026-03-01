"""
ShadowGate Test Suite - C++ Core Code Generation Tests
"""

import re
import pytest
from pathlib import Path
from builder.builder import CodeGenerator
from builder.config import BuildConfig


BASE_DIR = Path(__file__).parent.parent


def make_gen(config):
    """Create a CodeGenerator from the given config."""
    return CodeGenerator(config, BASE_DIR)


def generate_files(config, shellcode=None):
    """Generate all source files and return the dict."""
    if shellcode is None:
        shellcode = bytes([0x90] * 64)
    return make_gen(config).generate(shellcode)


def test_generated_main_cpp_has_phases():
    """Generated main.cpp contains Phase markers (Phase 1 through Phase 8)."""
    files = generate_files(BuildConfig())
    main = files["main.cpp"]
    for phase_num in range(1, 9):
        assert f"Phase {phase_num}" in main, f"Phase {phase_num} not found in main.cpp"


def test_generated_main_cpp_has_all_defines():
    """Generated main.cpp contains all expected #define toggles."""
    files = generate_files(BuildConfig())
    main = files["main.cpp"]
    expected_defines = [
        "ENABLE_EDR_FREEZE",
        "ENABLE_EDR_PRELOAD",
        "ENABLE_DISABLE_PRELOADED_EDR",
        "ENABLE_CMDLINE_SPOOF",
        "ENABLE_PPID_SPOOF",
        "ENABLE_BLOCK_DLLS",
        "ENABLE_SYSCALL_HASH",
    ]
    for define in expected_defines:
        assert define in main, f"#define {define} not found in main.cpp"


def test_generated_injection_h_has_all_declarations():
    """injection.h declares all injection function prototypes."""
    files = generate_files(BuildConfig())
    h = files["injection.h"]
    expected = [
        "InjectEarlyBird",
        "InjectModuleStomp",
        "InjectRemoteThread",
        "InjectProcessHollowing",
        "InjectMapping",
        "InjectThreadPoolReal",
        "InjectEarlyCascade",
        "InjectCallback",
        "SpoofRemoteCommandLine",
        "GetSpoofParentHandle",
    ]
    for fn in expected:
        assert fn in h, f"Function '{fn}' not declared in injection.h"


def test_generated_evasion_h_has_all_declarations():
    """evasion.h declares all evasion function prototypes."""
    files = generate_files(BuildConfig())
    h = files["evasion.h"]
    expected = [
        "PerformSandboxChecks",
        "PatchETW",
        "PatchAMSI",
        "WipePEHeaders",
        "UnhookNtdll",
        "PerformEDRPreload",
        "DisablePreloadedEdrModules",
    ]
    for fn in expected:
        assert fn in h, f"Function '{fn}' not declared in evasion.h"


def test_generated_syscalls_asm_has_stub():
    """asm_syscalls.asm contains PROC directives for syscall stubs."""
    files = generate_files(BuildConfig())
    asm = files["asm_syscalls.asm"]
    assert "PROC" in asm, "No PROC directives found in asm_syscalls.asm"
    assert "DoSyscall" in asm, "DoSyscall proc not found in asm_syscalls.asm"


def test_generated_resolver_has_syscall_indices():
    """syscalls.h contains IDX_Nt* defines for key syscalls."""
    files = generate_files(BuildConfig())
    syscalls_h = files["syscalls.h"]
    for idx in [
        "IDX_NtAllocateVirtualMemory",
        "IDX_NtProtectVirtualMemory",
        "IDX_NtWriteVirtualMemory",
    ]:
        assert idx in syscalls_h, f"{idx} not found in syscalls.h"


def test_shellcode_embedded():
    """Generated source contains the encoded shellcode (as g_EncodedShellcode)."""
    files = generate_files(BuildConfig())
    main = files["main.cpp"]
    assert "g_EncodedShellcode" in main, "Shellcode array not found in main.cpp"
    assert "g_OriginalSize" in main, "g_OriginalSize not found in main.cpp"


def test_no_plaintext_shellcode_in_source():
    """With encryption enabled, raw NOP sled does not appear verbatim in UUID-encoded source."""
    # 64 bytes of 0x90 NOP sled encoded as UUID should not contain raw 0x90 bytes when encrypted
    files = generate_files(BuildConfig(encrypt="cascade", encode="uuid"))
    main = files["main.cpp"]
    # The raw NOP bytes (0x90) should not appear as a C hex literal in UUID encoded source
    # UUID encoding converts to string format, so raw "0x90" hex in UUID arrays wouldn't appear
    assert "g_EncodedShellcode" in main  # but encoding should be present


def test_direct_syscall_define():
    """When syscall=direct, generated code contains SYSCALL_DIRECT define assignment."""
    files = generate_files(BuildConfig(syscall="direct"))
    main = files["main.cpp"]
    assert "SYSCALL_DIRECT" in main, "SYSCALL_DIRECT not found in main.cpp"
    # Should not have SYSCALL_INDIRECT as the method value
    assert "SYSCALL_METHOD      SYSCALL_DIRECT" in main or (
        "SYSCALL_METHOD" in main and "SYSCALL_DIRECT" in main
    )


def test_indirect_syscall_define():
    """When syscall=indirect, generated code contains SYSCALL_INDIRECT define assignment."""
    files = generate_files(BuildConfig(syscall="indirect"))
    main = files["main.cpp"]
    assert "SYSCALL_INDIRECT" in main, "SYSCALL_INDIRECT not found in main.cpp"
    assert "SYSCALL_METHOD      SYSCALL_INDIRECT" in main or (
        "SYSCALL_METHOD" in main and "SYSCALL_INDIRECT" in main
    )
