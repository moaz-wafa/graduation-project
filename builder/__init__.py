"""
ShadowGate Builder v3.0
BARBAROSSA + HookChain Integration
Ultimate EDR/AV Evasion Framework
"""

__version__ = "3.0.0"
__author__ = "ShadowGate Project"
__codename__ = "SHADOWGATE"

from .builder import ShadowGateBuilder
from .config import ConfigManager, DEFAULT_PROFILE
from .crypto import CryptoEngine
from .encoder import ShellcodeEncoder
from .hashing import HashEngine
from .entropy import EntropyAnalyzer
from .compiler import MSVCCompiler

__all__ = [
    'ShadowGateBuilder',
    'ConfigManager',
    'CryptoEngine',
    'ShellcodeEncoder',
    'HashEngine',
    'EntropyAnalyzer',
    'MSVCCompiler',
    'DEFAULT_PROFILE',
]