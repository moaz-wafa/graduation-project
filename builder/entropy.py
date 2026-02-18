"""
ShadowGate - Entropy Analysis Module
Ensures generated payloads have acceptable entropy levels
"""

import math
from collections import Counter
from typing import Tuple, List

# ============================================================================
# Constants
# ============================================================================

ENTROPY_LOW = 4.0       # Typical text/code
ENTROPY_NORMAL = 6.0    # Normal executable
ENTROPY_HIGH = 7.0      # Compressed/encrypted
ENTROPY_MAX = 8.0       # Maximum (truly random)

TARGET_ENTROPY = 6.0    # Our target maximum

# ============================================================================
# Entropy Analyzer
# ============================================================================

class EntropyAnalyzer:
    """Analyzes and manages entropy of data"""
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        Returns value between 0.0 and 8.0
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        counter = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def analyze_sections(data: bytes, section_size: int = 256) -> List[Tuple[int, float]]:
        """
        Analyze entropy of data sections
        Returns list of (offset, entropy) tuples
        """
        sections = []
        for i in range(0, len(data), section_size):
            section = data[i:i + section_size]
            entropy = EntropyAnalyzer.calculate_entropy(section)
            sections.append((i, entropy))
        return sections
    
    @staticmethod
    def get_entropy_rating(entropy: float) -> str:
        """Get human-readable entropy rating"""
        if entropy < ENTROPY_LOW:
            return "LOW (text-like)"
        elif entropy < ENTROPY_NORMAL:
            return "NORMAL (executable)"
        elif entropy < ENTROPY_HIGH:
            return "HIGH (compressed/encrypted)"
        else:
            return "VERY HIGH (random/encrypted)"
    
    @staticmethod
    def is_acceptable(entropy: float, target: float = TARGET_ENTROPY) -> bool:
        """Check if entropy is within acceptable range"""
        return entropy <= target
    
    @staticmethod
    def add_padding_to_reduce_entropy(data: bytes, target: float = TARGET_ENTROPY) -> bytes:
        """
        Add padding to reduce entropy
        Uses repetitive patterns to lower overall entropy
        """
        current_entropy = EntropyAnalyzer.calculate_entropy(data)
        
        if current_entropy <= target:
            return data
        
        # Padding patterns (low entropy)
        patterns = [
            b'\x00' * 64,                          # Null bytes
            b'\x90' * 64,                          # NOPs
            b'PADDING_' * 8,                       # Readable pattern
            bytes(range(256)) * 2,                 # Sequential bytes (low entropy when repeated)
            b'\xCC' * 64,                          # INT3 (debugger)
            b'This program cannot be run in DOS mode.\r\n',  # DOS stub text
        ]
        
        result = bytearray(data)
        pattern_idx = 0
        
        # Add padding until entropy is acceptable
        while EntropyAnalyzer.calculate_entropy(bytes(result)) > target:
            pattern = patterns[pattern_idx % len(patterns)]
            result.extend(pattern)
            pattern_idx += 1
            
            # Safety limit
            if len(result) > len(data) * 3:
                break
        
        return bytes(result)
    
    @staticmethod
    def generate_low_entropy_padding(size: int) -> bytes:
        """Generate low-entropy padding of specified size"""
        # Mix of patterns for natural-looking padding
        patterns = [
            b'\x00',      # Null
            b'\x90',      # NOP
            b'\xCC',      # INT3
            b'X',         # Filler
        ]
        
        result = bytearray()
        pattern_idx = 0
        
        while len(result) < size:
            # Add pattern in chunks
            chunk_size = min(64, size - len(result))
            pattern = patterns[pattern_idx % len(patterns)]
            result.extend(pattern * chunk_size)
            pattern_idx += 1
        
        return bytes(result[:size])
    
    @staticmethod
    def interleave_with_low_entropy(data: bytes, ratio: float = 0.3) -> bytes:
        """
        Interleave high-entropy data with low-entropy padding
        ratio: portion of result that should be padding (0.0-1.0)
        """
        if ratio <= 0:
            return data
        
        padding_total = int(len(data) * ratio / (1 - ratio))
        chunk_size = max(16, len(data) // 10)
        padding_per_chunk = padding_total // (len(data) // chunk_size + 1)
        
        result = bytearray()
        padding = EntropyAnalyzer.generate_low_entropy_padding(padding_per_chunk)
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            result.extend(chunk)
            if i + chunk_size < len(data):  # Don't add padding at the end
                result.extend(padding)
        
        return bytes(result)
    
    def analyze_and_report(self, data: bytes, name: str = "Data") -> dict:
        """
        Full entropy analysis with report
        """
        entropy = self.calculate_entropy(data)
        rating = self.get_entropy_rating(entropy)
        acceptable = self.is_acceptable(entropy)
        
        report = {
            "name": name,
            "size": len(data),
            "entropy": round(entropy, 4),
            "rating": rating,
            "acceptable": acceptable,
            "target": TARGET_ENTROPY,
        }
        
        return report
    
    def print_report(self, data: bytes, name: str = "Data"):
        """Print formatted entropy report"""
        report = self.analyze_and_report(data, name)
        
        status = "✅" if report["acceptable"] else "⚠️"
        
        print(f"\n{'='*50}")
        print(f"Entropy Analysis: {report['name']}")
        print(f"{'='*50}")
        print(f"  Size:     {report['size']:,} bytes")
        print(f"  Entropy:  {report['entropy']:.4f} / 8.0")
        print(f"  Rating:   {report['rating']}")
        print(f"  Target:   < {report['target']}")
        print(f"  Status:   {status} {'ACCEPTABLE' if report['acceptable'] else 'TOO HIGH'}")
        print(f"{'='*50}\n")


# ============================================================================
# Test
# ============================================================================

if __name__ == "__main__":
    analyzer = EntropyAnalyzer()
    
    # Test with different data types
    test_cases = [
        ("Null bytes", b'\x00' * 1000),
        ("Text", b"Hello World! This is a test string." * 30),
        ("Random", bytes([i % 256 for i in range(1000)])),
        ("Encrypted", bytes([((i * 17 + 31) ^ 0xAB) % 256 for i in range(1000)])),
        ("True Random", __import__('os').urandom(1000)),
    ]
    
    for name, data in test_cases:
        analyzer.print_report(data, name)