import re
from typing import List, Dict, Any

class SASTResultParser:
    """
    Parses output from Semgrep (or fallback parser) into SASTFinding schema objects.
    """
    @staticmethod
    def parse_semgrep_json(raw_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        results = raw_json.get("results", [])
        for item in results:
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})
            cwe_list = metadata.get("cwe", ["CWE-119"])
            cwe_str = cwe_list[0] if isinstance(cwe_list, list) and len(cwe_list) > 0 else str(cwe_list)
            
            # Map severity
            raw_sev = extra.get("severity", "WARNING").upper()
            sev_map = {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "INFO": "LOW"
            }
            severity = sev_map.get(raw_sev, "MEDIUM")

            findings.append({
                "tool": "Semgrep",
                "rule_id": item.get("check_id", "c-security-rule"),
                "cwe": cwe_str,
                "severity": severity,
                "file": item.get("path", ""),
                "line": item.get("start", {}).get("line", 1),
                "column": item.get("start", {}).get("col", 0),
                "message": extra.get("message", "Static analysis finding"),
                "snippet": extra.get("lines", "")
            })
        return findings

    @staticmethod
    def normalize_heuristic_findings(raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized = []
        for item in raw_findings:
            normalized.append({
                "tool": item.get("tool", "VAJRA-SAST-Heuristic"),
                "rule_id": item.get("rule_id", "buffer-overflow"),
                "cwe": item.get("cwe", "CWE-787"),
                "severity": item.get("severity", "HIGH"),
                "file": item.get("file", ""),
                "line": item.get("line", 1),
                "column": item.get("column", 0),
                "message": item.get("message", "Vulnerability detected"),
                "snippet": item.get("snippet", "")
            })
        return normalized
