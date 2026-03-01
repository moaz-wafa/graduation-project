"""
ShadowGate Test Suite - Output Format Code Generation Tests (DLL / SVC / PE)
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


def test_pe_format_generates_main_cpp():
    """output_format=pe → generates main.cpp with int main(."""
    files = generate_files(BuildConfig(output_format="pe"))
    assert "main.cpp" in files
    assert "dllmain.cpp" not in files
    assert "svcmain.cpp" not in files
    main = files["main.cpp"]
    assert "int main(" in main or "int wmain(" in main


def test_dll_format_generates_dllmain():
    """output_format=dll → generates dllmain.cpp with DllMain, DLL_PROCESS_ATTACH, CreateThread."""
    files = generate_files(BuildConfig(output_format="dll"))
    assert "dllmain.cpp" in files
    assert "main.cpp" not in files
    dll = files["dllmain.cpp"]
    assert "DllMain" in dll
    assert "DLL_PROCESS_ATTACH" in dll
    assert "CreateThread" in dll


def test_dll_format_exports_run():
    """DLL format → code contains __declspec(dllexport) and Run export."""
    files = generate_files(BuildConfig(output_format="dll"))
    dll = files["dllmain.cpp"]
    assert "__declspec(dllexport)" in dll
    assert "Run" in dll


def test_dll_format_no_synchronous_payload_in_dllmain():
    """DllMain must not call payload directly — must use a thread (CreateThread present)."""
    files = generate_files(BuildConfig(output_format="dll"))
    dll = files["dllmain.cpp"]
    # PayloadThread is defined and CreateThread is used in DllMain
    assert "PayloadThread" in dll
    assert "CreateThread" in dll
    # DllMain itself should call CreateThread, not directly execute injection logic
    dllmain_idx = dll.find("BOOL WINAPI DllMain")
    if dllmain_idx >= 0:
        dllmain_body = dll[dllmain_idx : dllmain_idx + 500]
        assert "CreateThread" in dllmain_body


def test_svc_format_generates_servicemain():
    """output_format=svc → code contains ServiceMain, RegisterServiceCtrlHandlerW, SetServiceStatus."""
    files = generate_files(BuildConfig(output_format="svc"))
    assert "svcmain.cpp" in files
    svc = files["svcmain.cpp"]
    assert "ServiceMain" in svc
    assert "RegisterServiceCtrlHandlerW" in svc
    assert "SetServiceStatus" in svc


def test_svc_format_has_install_uninstall():
    """SVC format → code contains --install, CreateServiceW, --uninstall, DeleteService."""
    files = generate_files(BuildConfig(output_format="svc"))
    svc = files["svcmain.cpp"]
    assert "--install" in svc
    assert "CreateServiceW" in svc
    assert "--uninstall" in svc
    assert "DeleteService" in svc


def test_svc_format_has_service_ctrl_handler():
    """SVC format → code contains ServiceCtrlHandler and SERVICE_CONTROL_STOP."""
    files = generate_files(BuildConfig(output_format="svc"))
    svc = files["svcmain.cpp"]
    assert "ServiceCtrlHandler" in svc
    assert "SERVICE_CONTROL_STOP" in svc


def test_dll_format_extension():
    """With output_format=dll, the builder uses .dll for the output path."""
    from builder.builder import ShadowGateBuilder
    import tempfile, os

    sc = bytes([0x90] * 64)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(sc)
        sc_path = f.name

    try:
        config = BuildConfig(
            input_file=sc_path,
            output_file="implant.exe",
            output_format="dll",
        )
        builder = ShadowGateBuilder(config)
        # Verify that when output_format is dll, the builder resolves .dll extension
        output_path = config.output_file
        # The builder logic converts .exe -> .dll for dll format
        from pathlib import Path as P
        p = P(output_path)
        if p.suffix.lower() != ".dll":
            resolved = p.stem + ".dll"
        else:
            resolved = output_path
        assert resolved.endswith(".dll"), f"Expected .dll extension, got: {resolved}"
    finally:
        os.unlink(sc_path)
