"""
ShadowGate - MSVC Compiler Module
Handles automatic compilation using Microsoft Visual C++
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import List, Tuple, Optional


# ============================================================================
# MSVC Compiler
# ============================================================================

class MSVCCompiler:
    """Handles compilation using Microsoft Visual C++"""
    
    # Visual Studio paths to search
    VS_PATHS = [
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    ]
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.vcvars_path = None
        self.found_vs = False
        self._find_visual_studio()
    
    def _log(self, message: str):
        """Print message if verbose mode"""
        if self.verbose:
            print(message)
    
    def _find_visual_studio(self):
        """Find Visual Studio installation"""
        for path in self.VS_PATHS:
            if os.path.exists(path):
                self.vcvars_path = path
                self.found_vs = True
                self._log(f"[+] Found Visual Studio: {path}")
                return
        
        self._log("[!] Visual Studio not found automatically")
        self._log("[*] Please run from 'x64 Native Tools Command Prompt for VS'")
    
    def _run_command(self, command: str, cwd: str = None) -> Tuple[int, str, str]:
        """Run a command and return (returncode, stdout, stderr)"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Compilation timed out"
        except Exception as e:
            return -1, "", str(e)
    
    def compile(self,
                source_dir: str,
                output_file: str,
                cpp_files: List[str],
                asm_files: List[str] = None,
                include_dirs: List[str] = None,
                libs: List[str] = None,
                defines: List[str] = None,
                debug: bool = False,
                optimize: bool = True) -> bool:
        """
        Compile the project
        
        Args:
            source_dir: Directory containing source files
            output_file: Output executable path
            cpp_files: List of .cpp files to compile
            asm_files: List of .asm files to assemble
            include_dirs: Additional include directories
            libs: Libraries to link
            defines: Preprocessor definitions
            debug: Build with debug info
            optimize: Enable optimizations
        
        Returns:
            True if compilation successful
        """
        if asm_files is None:
            asm_files = []
        if include_dirs is None:
            include_dirs = []
        if libs is None:
            libs = []
        if defines is None:
            defines = []
        
        obj_files = []
        
        # Create batch script
        batch_lines = ['@echo off', 'setlocal EnableDelayedExpansion', '']
        
        # Set up VS environment
        if self.vcvars_path:
            batch_lines.append(f'call "{self.vcvars_path}" >nul 2>&1')
        
        batch_lines.append(f'cd /d "{source_dir}"')
        batch_lines.append('')
        
        # Compiler flags
        if debug:
            compile_flags = '/c /nologo /Od /MT /W3 /Zi /EHsc'
        else:
            compile_flags = '/c /nologo /O2 /MT /W0 /GS- /EHsc'
            if optimize:
                compile_flags += ' /GL'  # Whole program optimization
        
        # Add defines
        for d in defines:
            compile_flags += f' /D{d}'
        
        # Add include dirs
        for inc in include_dirs:
            compile_flags += f' /I"{inc}"'
        
        # Assemble .asm files
        for asm_file in asm_files:
            obj_file = asm_file.replace('.asm', '.obj')
            obj_files.append(obj_file)
            batch_lines.append(f'echo [*] Assembling {asm_file}...')
            batch_lines.append(f'ml64 /c /nologo /Fo"{obj_file}" "{asm_file}"')
            batch_lines.append('if !ERRORLEVEL! neq 0 (')
            batch_lines.append(f'    echo [!] Failed to assemble {asm_file}')
            batch_lines.append('    exit /b 1')
            batch_lines.append(')')
            batch_lines.append('')
        
        # Compile .cpp files
        for cpp_file in cpp_files:
            obj_file = cpp_file.replace('.cpp', '.obj')
            obj_files.append(obj_file)
            batch_lines.append(f'echo [*] Compiling {cpp_file}...')
            batch_lines.append(f'cl {compile_flags} /Fo"{obj_file}" "{cpp_file}"')
            batch_lines.append('if !ERRORLEVEL! neq 0 (')
            batch_lines.append(f'    echo [!] Failed to compile {cpp_file}')
            batch_lines.append('    exit /b 1')
            batch_lines.append(')')
            batch_lines.append('')
        
        # Link
        obj_list = ' '.join(f'"{o}"' for o in obj_files)
        lib_list = ' '.join(libs)
        
        link_flags = '/nologo /SUBSYSTEM:CONSOLE /MACHINE:X64'
        if debug:
            link_flags += ' /DEBUG'
        else:
            link_flags += ' /DEBUG:NONE /OPT:REF /OPT:ICF'
            if optimize:
                link_flags += ' /LTCG'  # Link-time code generation
        
        batch_lines.append('echo [*] Linking...')
        batch_lines.append(f'link {link_flags} /OUT:"{output_file}" {obj_list} {lib_list}')
        batch_lines.append('if !ERRORLEVEL! neq 0 (')
        batch_lines.append('    echo [!] Linking failed')
        batch_lines.append('    exit /b 1')
        batch_lines.append(')')
        batch_lines.append('')
        
        # Cleanup object files
        batch_lines.append('echo [*] Cleaning up...')
        for obj in obj_files:
            batch_lines.append(f'del /q "{obj}" 2>nul')
        
        batch_lines.append('')
        batch_lines.append('echo [+] Build successful!')
        batch_lines.append('exit /b 0')
        
        # Write batch file
        batch_path = os.path.join(source_dir, '_compile.bat')
        with open(batch_path, 'w') as f:
            f.write('\n'.join(batch_lines))
        
        # Execute compilation
        self._log("[*] Starting compilation...")
        returncode, stdout, stderr = self._run_command(f'cmd /c "{batch_path}"', source_dir)
        
        # Output results
        if stdout:
            for line in stdout.strip().split('\n'):
                if line.strip():
                    self._log(f"    {line}")
        
        if returncode != 0 and stderr:
            for line in stderr.strip().split('\n'):
                if line.strip():
                    self._log(f"    {line}")
        
        # Cleanup batch file
        try:
            os.remove(batch_path)
        except:
            pass
        
        # Check result
        if returncode == 0 and os.path.exists(output_file):
            file_size = os.path.getsize(output_file)
            self._log(f"[+] Output: {output_file} ({file_size:,} bytes)")
            return True
        else:
            self._log(f"[!] Compilation failed (exit code: {returncode})")
            return False
    
    def check_environment(self) -> dict:
        """Check compilation environment"""
        result = {
            "vs_found": self.found_vs,
            "vcvars_path": self.vcvars_path,
            "cl_available": False,
            "ml64_available": False,
            "link_available": False,
        }
        
        if not self.found_vs:
            return result
        
        # Test if tools are available
        batch_content = f'''@echo off
call "{self.vcvars_path}" >nul 2>&1
where cl >nul 2>&1 && echo CL_OK
where ml64 >nul 2>&1 && echo ML64_OK
where link >nul 2>&1 && echo LINK_OK
'''
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.bat', delete=False) as f:
            f.write(batch_content)
            temp_bat = f.name
        
        try:
            returncode, stdout, _ = self._run_command(f'cmd /c "{temp_bat}"')
            if "CL_OK" in stdout:
                result["cl_available"] = True
            if "ML64_OK" in stdout:
                result["ml64_available"] = True
            if "LINK_OK" in stdout:
                result["link_available"] = True
        finally:
            os.remove(temp_bat)
        
        return result


# ============================================================================
# Test
# ============================================================================

if __name__ == "__main__":
    compiler = MSVCCompiler()
    
    print("\n" + "=" * 60)
    print("Compilation Environment Check")
    print("=" * 60)
    
    env = compiler.check_environment()
    
    print(f"  Visual Studio Found: {'Yes' if env['vs_found'] else 'No'}")
    if env['vcvars_path']:
        print(f"  vcvars64.bat: {env['vcvars_path']}")
    print(f"  CL (C++ Compiler): {'Available' if env['cl_available'] else 'Not Found'}")
    print(f"  ML64 (Assembler): {'Available' if env['ml64_available'] else 'Not Found'}")
    print(f"  LINK (Linker): {'Available' if env['link_available'] else 'Not Found'}")
    
    if all([env['cl_available'], env['ml64_available'], env['link_available']]):
        print("\n[+] Environment ready for compilation!")
    else:
        print("\n[!] Some tools are missing. Please install Visual Studio Build Tools.")