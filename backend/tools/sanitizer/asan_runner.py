import subprocess
import re
from typing import Dict, Any, Optional
from pathlib import Path

class ASanRunner:
    """
    Executes compiled ASan binaries with PoV crash payload input
    and extracts structured memory error details (stack-buffer-overflow, heap-buffer-overflow, use-after-free).
    """
    def run_asan_binary(self, binary_path: str, pov_file_path: Optional[str] = None) -> Dict[str, Any]:
        if not Path(binary_path).exists():
            return {"detected": False, "error": f"Binary not found: {binary_path}"}

        cmd = [binary_path]
        stdin_data = None

        if pov_file_path and Path(pov_file_path).exists():
            with open(pov_file_path, "rb") as f:
                stdin_data = f.read()

        try:
            res = subprocess.run(cmd, input=stdin_data, capture_output=True, timeout=15)
            stderr_text = res.stderr.decode("utf-8", errors="ignore")
            stdout_text = res.stdout.decode("utf-8", errors="ignore")

            return self.parse_asan_output(stderr_text + "\n" + stdout_text)
        except Exception as e:
            return {"detected": False, "error": str(e)}

    def parse_asan_output(self, output: str) -> Dict[str, Any]:
        if "ERROR: AddressSanitizer:" not in output:
            return {
                "detected": False,
                "type": "NONE",
                "operation": "NONE",
                "size": 0,
                "raw_log": output
            }

        # Match error type e.g. AddressSanitizer: stack-buffer-overflow on address...
        type_match = re.search(r'ERROR:\s*AddressSanitizer:\s*([a-zA-Z\-]+)', output)
        asan_type = type_match.group(1) if type_match else "unknown-memory-error"

        # Match READ / WRITE operation and size e.g. WRITE of size 64
        op_match = re.search(r'(WRITE|READ)\s+of\s+size\s+(\d+)', output)
        operation = op_match.group(1) if op_match else "UNKNOWN"
        size = int(op_match.group(2)) if op_match else 0

        # Match location e.g. #0 0x... in parse_header parser.c:184
        loc_match = re.search(r'#0\s+0x[0-9a-fA-F]+\s+in\s+([a-zA-Z0-9_]+)\s+(?:.*[/\\])?([a-zA-Z0-9_\.\-]+):(\d+)', output)
        func_name = loc_match.group(1) if loc_match else "unknown"
        file_name = loc_match.group(2) if loc_match else "unknown"
        line_num = int(loc_match.group(3)) if loc_match else 0

        return {
            "detected": True,
            "type": asan_type,
            "operation": operation,
            "size": size,
            "function": func_name,
            "file": file_name,
            "line": line_num,
            "raw_log": output[:2000] # Truncated log
        }
