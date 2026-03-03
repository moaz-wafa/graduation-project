"""
ShadowGate Test Suite - Evasion Feature Code Generation Tests
"""

import re
import pytest
from pathlib import Path
from builder.builder import CodeGenerator
from builder.config import BuildConfig


BASE_DIR = Path(__file__).parent.parent


def generate_files(config):
    """Generate source files for the given config."""
    shellcode = bytes([0x90] * 64)
    gen = CodeGenerator(config, BASE_DIR)
    return gen.generate(shellcode)


def get_define_value(source: str, define_name: str) -> str:
    """Extract the integer value of a #define from source."""
    match = re.search(rf'#define\s+{define_name}\s+(\d+)', source)
    return match.group(1) if match else None


def test_edr_freeze_codegen():
    """--edr-freeze → ENABLE_EDR_FREEZE 1, FreezeEDRProcesses, hash list present."""
    files = generate_files(BuildConfig(edr_freeze=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_EDR_FREEZE") == "1"
    # EDR freeze file generated
    assert "edr_freeze.cpp" in files
    edr = files["edr_freeze.cpp"]
    assert "FreezeEDRProcesses" in edr
    # Hash array is present (EDR process hashes)
    assert "g_EdpProcessHashes" in edr


def test_edr_preload_codegen():
    """--edr-preload → ENABLE_EDR_PRELOAD 1, PerformEDRPreload in source."""
    files = generate_files(BuildConfig(edr_preload=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_EDR_PRELOAD") == "1"
    evasion = files["evasion.cpp"]
    assert "PerformEDRPreload" in evasion
    # g_CascadeStub should appear in earlycascade.cpp (always generated)
    ec = files.get("earlycascade.cpp", "")
    assert "g_CascadeStub" in ec


def test_disable_preloaded_edr_codegen():
    """--disable-preloaded-edr → ENABLE_DISABLE_PRELOADED_EDR 1, DisablePreloadedEdrModules."""
    files = generate_files(BuildConfig(disable_preloaded_edr=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_DISABLE_PRELOADED_EDR") == "1"
    evasion_h = files["evasion.h"]
    assert "DisablePreloadedEdrModules" in evasion_h
    # g_StubPlaceholder bytes appear in earlycascade.cpp
    ec = files.get("earlycascade.cpp", "")
    assert "g_StubPlaceholder" in ec


def test_freeze_codegen():
    """--freeze → ENABLE_FREEZE 1, FreezeRemoteThreads/ThawRemoteThreads in injection.h."""
    files = generate_files(BuildConfig(freeze=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_FREEZE") == "1"
    inj_h = files["injection.h"]
    assert "FreezeRemoteThreads" in inj_h
    assert "ThawRemoteThreads" in inj_h


def test_spoof_cmdline_codegen():
    """--spoof-cmdline → ENABLE_CMDLINE_SPOOF 1, SpoofRemoteCommandLine declared, svchost in source."""
    files = generate_files(BuildConfig(spoof_cmdline=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_CMDLINE_SPOOF") == "1"
    # SpoofRemoteCommandLine is declared in injection.h
    inj_h = files["injection.h"]
    assert "SpoofRemoteCommandLine" in inj_h
    assert "svchost" in main.lower()


def test_ppid_spoof_codegen():
    """--ppid-spoof explorer.exe → ENABLE_PPID_SPOOF 1, GetSpoofParentHandle declared, PPID_SPOOF_TARGET."""
    files = generate_files(BuildConfig(ppid_spoof="explorer.exe"))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_PPID_SPOOF") == "1"
    # GetSpoofParentHandle is declared in injection.h
    inj_h = files["injection.h"]
    assert "GetSpoofParentHandle" in inj_h
    assert "PPID_SPOOF_TARGET" in main
    assert "explorer.exe" in main


def test_block_dlls_codegen():
    """--block-dlls → ENABLE_BLOCK_DLLS 1, PROCESS_CREATION_MITIGATION policy in source."""
    files = generate_files(BuildConfig(block_dlls=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_BLOCK_DLLS") == "1"
    # The mitigation policy constant should appear in injection.cpp or earlycascade.cpp
    inj = files["injection.cpp"]
    ec = files.get("earlycascade.cpp", "")
    assert (
        "PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON" in inj
        or "PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON" in ec
    )


def test_etw_patching_codegen():
    """ETW enabled → EtwEventWrite patch sequence present in evasion.cpp."""
    files = generate_files(BuildConfig(etw=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_ETW_PATCH") == "1"
    evasion = files["evasion.cpp"]
    assert "EtwEventWrite" in evasion
    # xor eax,eax; ret patch bytes
    assert "0x33, 0xC0, 0xC3" in evasion


def test_amsi_bypass_codegen():
    """AMSI enabled → AmsiScanBuffer and AMSI patch bytes in evasion.cpp."""
    files = generate_files(BuildConfig(amsi=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_AMSI_PATCH") == "1"
    evasion = files["evasion.cpp"]
    assert "AmsiScanBuffer" in evasion
    # AMSI patch: mov eax, E_INVALIDARG; ret
    assert "0xB8" in evasion


def test_unhook_codegen():
    """--unhook → GetFreshNtdll in resolver source."""
    files = generate_files(BuildConfig(unhook=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_UNHOOK") == "1"
    resolver = files["resolver.cpp"]
    assert "GetFreshNtdll" in resolver


def test_sandbox_evasion_codegen():
    """sandbox enabled → uptime/CPU check present in evasion.cpp."""
    files = generate_files(BuildConfig(sandbox=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_SANDBOX") == "1"
    evasion = files["evasion.cpp"]
    assert "PerformSandboxChecks" in evasion
    # Uptime check is part of sandbox checks
    assert "CheckUptime" in evasion or "GetTickCount" in evasion


def test_syscall_hash_codegen():
    """--syscall-hash → ENABLE_SYSCALL_HASH 1, Djb2HashExportName in resolver.cpp."""
    files = generate_files(BuildConfig(syscall_hash=True))
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_SYSCALL_HASH") == "1"
    resolver = files["resolver.cpp"]
    assert "Djb2HashExportName" in resolver


def test_edr_freeze_disabled_by_default():
    """Default config → ENABLE_EDR_FREEZE 0."""
    files = generate_files(BuildConfig())
    main = files["main.cpp"]
    assert get_define_value(main, "ENABLE_EDR_FREEZE") == "0"


def test_multiple_evasion_flags_combined():
    """All evasion flags combined → all defines are 1, all function declarations present."""
    config = BuildConfig(
        edr_freeze=True,
        edr_preload=True,
        disable_preloaded_edr=True,
        freeze=True,
        spoof_cmdline=True,
        ppid_spoof="explorer.exe",
        block_dlls=True,
    )
    files = generate_files(config)
    main = files["main.cpp"]

    for define in [
        "ENABLE_EDR_FREEZE",
        "ENABLE_EDR_PRELOAD",
        "ENABLE_DISABLE_PRELOADED_EDR",
        "ENABLE_FREEZE",
        "ENABLE_CMDLINE_SPOOF",
        "ENABLE_PPID_SPOOF",
        "ENABLE_BLOCK_DLLS",
    ]:
        assert get_define_value(main, define) == "1", (
            f"{define} should be 1 when all evasion flags are enabled"
        )
