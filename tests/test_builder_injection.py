"""
ShadowGate Test Suite - Injection Method Code Generation Tests
"""

import pytest
from pathlib import Path
from builder.builder import CodeGenerator
from builder.config import BuildConfig


BASE_DIR = Path(__file__).parent.parent


def generate_files(inject_method):
    """Generate source files for a given injection method."""
    shellcode = bytes([0x90] * 64)
    config = BuildConfig(inject=inject_method)
    gen = CodeGenerator(config, BASE_DIR)
    return gen.generate(shellcode)


def test_earlybird_injection_codegen():
    """earlybird inject → InjectEarlyBird, NtQueueApcThread, CREATE_SUSPENDED in source."""
    files = generate_files("earlybird")
    inj = files["injection.cpp"]
    assert "InjectEarlyBird" in inj
    assert "NtQueueApcThread" in inj
    assert "CREATE_SUSPENDED" in inj


def test_earlycascade_injection_codegen():
    """earlycascade inject → InjectEarlyCascade, EncodeSystemPtr, .mrdata in source."""
    files = generate_files("earlycascade")
    ec = files["earlycascade.cpp"]
    assert "InjectEarlyCascade" in ec
    assert "EncodeSystemPtr" in ec
    assert ".mrdata" in ec


def test_callback_injection_codegen():
    """callback inject → InjectCallback and at least one callback method in source."""
    files = generate_files("callback")
    cb = files["callback.cpp"]
    assert "InjectCallback" in cb
    # At least one of the known callback methods should be used
    callback_methods = [
        "EnumCalendarInfoA",
        "CertEnumSystemStore",
        "EnumChildWindows",
        "CreateFiber",
        "EnumWindows",
        "SetTimer",
        "CryptEnumOIDInfo",
        "EnumResourceTypesA",
    ]
    assert any(m in cb for m in callback_methods), (
        f"No known callback method found in callback.cpp. Content snippet: {cb[:500]}"
    )


def test_hollowing_injection_codegen():
    """hollowing inject → InjectProcessHollowing, NtUnmapViewOfSection in source."""
    files = generate_files("hollowing")
    inj = files["injection.cpp"]
    assert "InjectProcessHollowing" in inj
    assert "NtUnmapViewOfSection" in inj


def test_mapping_injection_codegen():
    """mapping inject → InjectMapping, NtCreateSection, NtMapViewOfSection in source."""
    files = generate_files("mapping")
    inj = files["injection.cpp"]
    assert "InjectMapping" in inj
    assert "NtCreateSection" in inj
    assert "NtMapViewOfSection" in inj


def test_remotethread_injection_codegen():
    """remotethread inject → InjectRemoteThread, NtCreateThreadEx in source."""
    files = generate_files("remotethread")
    inj = files["injection.cpp"]
    assert "InjectRemoteThread" in inj
    assert "NtCreateThreadEx" in inj


def test_stomp_injection_codegen():
    """stomp inject → InjectModuleStomp in source."""
    files = generate_files("stomp")
    inj = files["injection.cpp"]
    assert "InjectModuleStomp" in inj


def test_threadpool_injection_codegen():
    """threadpool_real inject → InjectThreadPoolReal in source."""
    files = generate_files("threadpool_real")
    inj = files["injection.cpp"]
    assert "InjectThreadPoolReal" in inj


def test_inject_method_dispatch():
    """injection.cpp has a dispatcher that references all injection method constants."""
    files = generate_files("earlycascade")
    inj = files["injection.cpp"]
    # The dispatcher should reference each injection constant
    assert "INJECT_STOMP" in inj
    assert "INJECT_EARLYBIRD" in inj
    assert "INJECT_HOLLOWING" in inj
    assert "INJECT_MAPPING" in inj
    assert "INJECT_EARLYCASCADE" in inj
    assert "INJECT_CALLBACK" in inj
    # The main dispatcher function
    assert "PerformInjection" in inj
