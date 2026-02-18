#!/usr/bin/env python3
"""
ShadowGate Builder - Quick Runner Script
Place this in the root directory of the project
"""

import sys
from pathlib import Path

# Add builder to path
sys.path.insert(0, str(Path(__file__).parent))

from builder.builder import main

if __name__ == '__main__':
    sys.exit(main())