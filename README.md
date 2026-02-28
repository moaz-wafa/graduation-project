# ShadowGate v3.0

**EDR/AV Evasion Research Framework — Graduation Project**

> ⚠️ **Disclaimer:** This project is intended **for educational and authorized security research only**. Use only in environments you own or have explicit written permission to test. The authors assume no liability for misuse.

---

## Features

- **Direct & Indirect Syscalls** — Hell's Gate / HookChain-style SSN resolution
- **Multiple NTDLL Resolvers** — PEB walk, fresh disk copy, or hybrid
- **Injection Methods** — Module Stomping, Early Bird APC, Remote Thread (NtCreateThreadEx), Process Hollowing, Section Mapping, Thread Pool, Early Cascade, Callback Execution
- **Early Cascade Injection** — Shim Engine `g_pfnSE_DllLoaded` hijack with AppVerifier `AvrfpAPILookupCallbackRoutine` fallback
- **Callback Execution** — 7 callback methods (EnumCalendarInfoA, CertEnumSystemStore, EnumChildWindows, CreateFiber, EnumResourceTypesA, CryptEnumOIDInfo, SetTimer), randomly selected per build for unique signatures
- **EDR Process Freezing** — DJB2 hash-based identification + NtSuspendProcess via indirect syscall (zero plaintext strings in binary)
- **Hook Integrity Verification** — Post-injection syscall stub check for EDR hooks
- **Multi-Layer Encryption** — XOR, AES-256-CBC, or cascade (both)
- **Shellcode Encoding** — UUID, MAC address, IPv4, or raw formats
- **String Obfuscation** — DJB2 hashing, XOR, stack strings, or none
- **Sandbox Evasion** — Uptime, user interaction, and environment checks
- **ETW Patching** — Silences `EtwEventWrite` and `EtwEventWriteFull`
- **Runtime Key Derivation** — Keys are XOR-obfuscated at build time and derived at runtime
- **NTDLL Unhooking** — Optional restore of hooked `.text` section

---

## Requirements

- Python 3.10+
- [PyCryptodome](https://pypi.org/project/pycryptodome/) (`pip install pycryptodome`)
- Visual Studio 2019 or 2022 with the **Desktop development with C++** workload (MSVC + ml64)

---

## Quick Start

```bash
# Install Python dependencies
pip install -r requirements.txt

# Default build now uses Early Cascade injection
python run.py -i payload.bin -o implant.exe

# Full stealth build: indirect syscalls, cascade encryption, UUID encoding, early cascade injection, EDR freeze
python run.py -i payload.bin -o implant.exe --syscall indirect --encrypt cascade --encode uuid --inject earlycascade --edr-freeze

# Callback-based local execution (method randomly selected at build time)
python run.py -i payload.bin -o implant.exe --inject callback

# Remote thread injection into notepad.exe
python run.py -i payload.bin -o implant.exe --inject remotethread --target notepad.exe

# Generate source only (no compilation)
python run.py -i payload.bin --no-compile

# Save and reuse a profile
python run.py --save-profile stealth --syscall indirect --inject earlycascade --encrypt cascade
python run.py -i payload.bin -o implant.exe --profile stealth
```

---

## Architecture

```
run.py  →  builder/builder.py  (CLI + orchestration)
               ├── config.py       (BuildConfig, profiles)
               ├── crypto.py       (XOR / AES-256 encryption + key derivation)
               ├── encoder.py      (UUID / MAC / IPv4 / raw encoding)
               ├── hashing.py      (DJB2 API hashing, string obfuscation)
               ├── entropy.py      (entropy analysis)
               └── compiler.py     (MSVC cl.exe / ml64.exe invocation)
```

The builder generates a self-contained C++ project (syscalls, resolver, injection, evasion, main), then invokes MSVC to compile it into a single executable.

---

## Configuration Options

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `--syscall` | `direct`, `indirect` | `indirect` | Syscall invocation method |
| `--resolver` | `peb`, `fresh`, `hybrid` | `hybrid` | NTDLL base resolver |
| `--strings` | `none`, `djb2`, `xor`, `stack` | `djb2` | String obfuscation method |
| `--encrypt` | `xor`, `aes`, `cascade` | `cascade` | Shellcode encryption |
| `--encode` | `uuid`, `mac`, `ipv4`, `raw` | `uuid` | Shellcode encoding format |
| `--inject` | `stomp`, `earlybird`, `remotethread`, `hollowing`, `mapping`, `threadpool_real`, `earlycascade`, `callback` | `earlycascade` | Injection technique |
| `--target` | process name | `notepad.exe` | Target process |
| `--sleep` | seconds | `0` | Initial sleep before execution |
| `--sandbox` / `--no-sandbox` | — | enabled | Sandbox / VM evasion checks |
| `--etw` / `--no-etw` | — | enabled | ETW patching |
| `--unhook` | — | disabled | NTDLL unhooking |
| `--edr-freeze` | — | disabled | Freeze EDR processes (requires admin) |
| `--edr-preload` | — | disabled | Prevent EDR user-mode hooks via AvrfpAPILookupCallbackRoutine intercept |
| `--disable-preloaded-edr` | — | disabled | Clobber EntryPoints of non-essential loaded DLLs to prevent EDR DllMain initialization |
| `--freeze` | — | disabled | Freeze all remote threads before shellcode write |
| `--spoof-cmdline` | — | disabled | Spoof command line in remote process PEB (hides real arguments from tools like Process Hacker) |
| `--ppid-spoof <name>` | process name | disabled | Spoof parent PID by inheriting from named process (e.g. `explorer.exe`) |
| `--block-dlls` | — | disabled | Block non-Microsoft-signed DLLs from loading into spawned process |
| `--debug` | — | disabled | Verbose debug output |

---

## License

MIT License — see [LICENSE](LICENSE) for details.
