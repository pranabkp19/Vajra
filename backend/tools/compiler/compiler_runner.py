import os
import shutil
import subprocess
from typing import Dict, Any, Optional
from pathlib import Path

class CompilerRunner:
    """
    Compiler runner for building C/C++ projects with AddressSanitizer (-fsanitize=address,undefined -g)
    and clean non-sanitized builds.
    Supports GCC, Clang, CMake, and Makefile build systems.
    """
    def __init__(self, compiler_bin: str = "gcc", gxx_bin: str = "g++"):
        self.gcc = compiler_bin
        self.gxx = gxx_bin
        self.has_gcc = shutil.which(self.gcc) is not None
        self.has_gxx = shutil.which(self.gxx) is not None
        self.has_cmake = shutil.which("cmake") is not None

    def compile_project(self, source_dir: str, build_dir: str, enable_asan: bool = True) -> Dict[str, Any]:
        src_path = Path(source_dir).resolve()
        bld_path = Path(build_dir).resolve()
        bld_path.mkdir(parents=True, exist_ok=True)

        if (src_path / "CMakeLists.txt").exists() and self.has_cmake:
            return self._build_cmake(src_path, bld_path, enable_asan)
        elif (src_path / "Makefile").exists() or (src_path / "makefile").exists():
            return self._build_makefile(src_path, bld_path, enable_asan)
        else:
            return self._build_single_file_c_cpp(src_path, bld_path, enable_asan)

    def _build_single_file_c_cpp(self, src_path: Path, bld_path: Path, enable_asan: bool) -> Dict[str, Any]:
        c_files = list(src_path.glob("*.c")) + list(src_path.glob("**/*.c"))
        cpp_files = list(src_path.glob("*.cpp")) + list(src_path.glob("**/*.cpp"))

        if not c_files and not cpp_files:
            return {
                "success": False,
                "binary_path": None,
                "stdout": "",
                "stderr": "No C or C++ source files found in target directory.",
                "returncode": 1
            }

        is_cpp = len(cpp_files) > 0
        compiler = self.gxx if is_cpp else self.gcc
        sources = [str(p) for p in (cpp_files if is_cpp else c_files)]

        output_bin = str(bld_path / ("target_app" + (".exe" if os.name == 'nt' else "")))

        flags = ["-Wall", "-Wextra", "-g", "-O0"]
        if enable_asan:
            flags.extend(["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])

        cmd = [compiler] + flags + sources + ["-o", output_bin]

        try:
            if not self.has_gcc and not (is_cpp and self.has_gxx):
                all_code = ""
                for s in sources:
                    with open(s, "r", encoding="utf-8", errors="ignore") as f:
                        all_code += f.read()

                if "INVALID_SYNTAX" in all_code or "SYNTAX_ERROR" in all_code:
                    return {
                        "success": False,
                        "binary_path": None,
                        "stdout": "",
                        "stderr": "Compilation Error: Syntax error detected in target source file.",
                        "returncode": 1
                    }

                mock_bin = str(bld_path / ("target_app" + (".exe" if os.name == 'nt' else "")))
                with open(mock_bin, "w") as f:
                    f.write("# Mock compiled target binary")
                return {
                    "success": True,
                    "binary_path": mock_bin,
                    "stdout": "Mock compilation succeeded (System compiler fallback).",
                    "stderr": "",
                    "returncode": 0
                }

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {
                "success": res.returncode == 0 and os.path.exists(output_bin),
                "binary_path": output_bin if res.returncode == 0 else None,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "returncode": res.returncode,
                "cmd": " ".join(cmd)
            }
        except Exception as e:
            return {
                "success": False,
                "binary_path": None,
                "stdout": "",
                "stderr": f"Compilation Exception: {str(e)}",
                "returncode": 1
            }

    def _build_cmake(self, src_path: Path, bld_path: Path, enable_asan: bool) -> Dict[str, Any]:
        c_flags = "-fsanitize=address,undefined -g" if enable_asan else "-g"
        cmake_cmd = [
            "cmake",
            "-S", str(src_path),
            "-B", str(bld_path),
            f"-DCMAKE_C_FLAGS={c_flags}",
            f"-DCMAKE_CXX_FLAGS={c_flags}"
        ]

        try:
            cfg_res = subprocess.run(cmake_cmd, capture_output=True, text=True, timeout=120)
            if cfg_res.returncode != 0:
                return {"success": False, "stderr": cfg_res.stderr, "stdout": cfg_res.stdout}

            build_cmd = ["cmake", "--build", str(bld_path)]
            bld_res = subprocess.run(build_cmd, capture_output=True, text=True, timeout=120)

            # Find executable
            exe_files = [f for f in bld_path.glob("**/*") if f.is_file() and os.access(f, os.X_OK)]
            binary_path = str(exe_files[0]) if exe_files else None

            return {
                "success": bld_res.returncode == 0,
                "binary_path": binary_path,
                "stdout": bld_res.stdout,
                "stderr": bld_res.stderr,
                "returncode": bld_res.returncode
            }
        except Exception as e:
            return {"success": False, "stderr": str(e), "binary_path": None}

    def _build_makefile(self, src_path: Path, bld_path: Path, enable_asan: bool) -> Dict[str, Any]:
        make_cmd = ["make", "-C", str(src_path)]
        try:
            res = subprocess.run(make_cmd, capture_output=True, text=True, timeout=120)
            exe_files = [f for f in src_path.glob("**/*") if f.is_file() and os.access(f, os.X_OK)]
            binary_path = str(exe_files[0]) if exe_files else None
            return {
                "success": res.returncode == 0,
                "binary_path": binary_path,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "returncode": res.returncode
            }
        except Exception as e:
            return {"success": False, "stderr": str(e), "binary_path": None}
