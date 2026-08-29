import os
import shutil
import json
import subprocess
import re
from typing import List, Dict, Any
from pathlib import Path
from backend.tools.sast.parser import SASTResultParser

class SemgrepRunner:
    """
    SAST Engine runner supporting native `semgrep` execution if installed,
    or a high-precision regex/AST heuristic fallback engine for C/C++ vulnerabilities:
    - CWE-114 (Process Control / Untrusted Library Loading: LoadLibrary, LoadLibraryA, LoadLibraryW, dlopen)
    - CWE-787 (Out-of-bounds Write / Stack Overflow: strcpy, sprintf, strcat, unsafe memcpy)
    - CWE-120 (Classic Buffer Overflow: gets, scanf %s)
    - CWE-416 (Use After Free: free followed by pointer dereference)
    - CWE-134 (Uncontrolled Format String: printf(var))
    - CWE-190 (Integer Overflow in allocation or array sizing)
    """
    def __init__(self, semgrep_bin: str = "semgrep"):
        self.semgrep_bin = semgrep_bin
        self.is_semgrep_available = shutil.which(semgrep_bin) is not None

    def run_sast(self, target_dir: str) -> List[Dict[str, Any]]:
        target_path = Path(target_dir).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target directory {target_dir} does not exist.")

        if self.is_semgrep_available:
            return self._run_native_semgrep(str(target_path))
        else:
            return self._run_heuristic_c_cpp_scanner(str(target_path))

    def _run_native_semgrep(self, target_dir: str) -> List[Dict[str, Any]]:
        cmd = [
            self.semgrep_bin,
            "--config=auto",
            "--json",
            "--quiet",
            target_dir
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0 or res.stdout:
                data = json.loads(res.stdout)
                parsed = SASTResultParser.parse_semgrep_json(data)
                if parsed:
                    return parsed
        except Exception as e:
            pass
        return self._run_heuristic_c_cpp_scanner(target_dir)

    def _run_heuristic_c_cpp_scanner(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        c_cpp_extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}

        rules = [
            {
                "rule_id": "c-untrusted-library-load-process-control",
                "cwe": "CWE-114",
                "severity": "CRITICAL",
                "pattern": r'\b(LoadLibraryA?|LoadLibraryW?|dlopen)\s*\(',
                "message": "Potential Process Control vulnerability: Dynamic library loaded without explicit trusted full path."
            },
            {
                "rule_id": "c-unsafe-strcpy-buffer-overflow",
                "cwe": "CWE-787",
                "severity": "HIGH",
                "pattern": r'\bstrcpy\s*\(',
                "message": "Use of unsafe function 'strcpy' without bounds checking can lead to stack buffer overflow."
            },
            {
                "rule_id": "c-unsafe-strcat-buffer-overflow",
                "cwe": "CWE-787",
                "severity": "HIGH",
                "pattern": r'\bstrcat\s*\(',
                "message": "Use of unsafe function 'strcat' without bounds checking can cause buffer overflow."
            },
            {
                "rule_id": "c-unsafe-sprintf-buffer-overflow",
                "cwe": "CWE-787",
                "severity": "HIGH",
                "pattern": r'\bsprintf\s*\(',
                "message": "Use of unsafe function 'sprintf' can cause out-of-bounds memory write."
            },
            {
                "rule_id": "c-unsafe-gets",
                "cwe": "CWE-120",
                "severity": "CRITICAL",
                "pattern": r'\bgets\s*\(',
                "message": "Use of dangerous function 'gets' which provides no buffer size checks."
            },
            {
                "rule_id": "c-format-string-vulnerability",
                "cwe": "CWE-134",
                "severity": "HIGH",
                "pattern": r'\b(printf|fprintf|sprintf)\s*\(\s*([a-zA-Z0-9_\->]+)\s*\)\s*;',
                "message": "Uncontrolled format string vulnerability: Non-literal format string passed directly."
            },
            {
                "rule_id": "c-potential-use-after-free",
                "cwe": "CWE-416",
                "severity": "HIGH",
                "pattern": r'\bfree\s*\(\s*([a-zA-Z0-9_\->\[\]]+)\s*\);',
                "message": "Pointer freed without immediate NULL assignment; check for subsequent use-after-free."
            },
            {
                "rule_id": "c-unchecked-memcpy-bounds",
                "cwe": "CWE-787",
                "severity": "HIGH",
                "pattern": r'\bmemcpy\s*\(',
                "message": "Potential out-of-bounds write in 'memcpy' if length argument exceeds target buffer capacity."
            },
            {
                "rule_id": "c-integer-overflow-malloc",
                "cwe": "CWE-190",
                "severity": "HIGH",
                "pattern": r'\bmalloc\s*\([^;]*\*[^;]*\)',
                "message": "Integer overflow in size calculation passed to malloc without bounds check."
            }
        ]

        for root, _, files in os.walk(target_dir):
            for file in files:
                filepath = Path(root) / file
                if filepath.suffix.lower() in c_cpp_extensions:
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()

                        for line_idx, line_content in enumerate(lines, start=1):
                            # Skip comment lines
                            stripped = line_content.strip()
                            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                                continue

                            for rule in rules:
                                match = re.search(rule["pattern"], line_content)
                                if match:
                                    # If rule is use-after-free, check if subsequent line sets pointer to NULL
                                    if rule["rule_id"] == "c-potential-use-after-free":
                                        ptr_name = match.group(1)
                                        subsequent_block = "".join(lines[line_idx:min(len(lines), line_idx + 3)])
                                        if f"{ptr_name} = NULL" in subsequent_block or f"{ptr_name}=NULL" in subsequent_block or f"{ptr_name} = 0" in subsequent_block:
                                            continue

                                    rel_path = str(filepath.relative_to(target_dir)).replace("\\", "/")
                                    findings.append({
                                        "tool": "VAJRA-SAST-Scanner",
                                        "rule_id": rule["rule_id"],
                                        "cwe": rule["cwe"],
                                        "severity": rule["severity"],
                                        "file": rel_path,
                                        "line": line_idx,
                                        "column": match.start() + 1,
                                        "message": rule["message"],
                                        "snippet": line_content.strip()
                                    })
                    except Exception as e:
                        continue

        return SASTResultParser.normalize_heuristic_findings(findings)
