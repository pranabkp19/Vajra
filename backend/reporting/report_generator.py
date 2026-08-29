import json
import time
from typing import Dict, Any, List, Optional
from pathlib import Path

class ReportGenerator:
    """
    Generates executive Markdown and JSON security audit reports for VAJRA runs.
    Enforces complete transparency for AI execution mode, model configuration,
    evidence compression statistics, and 4-stage deterministic verification breakdown.
    """
    def generate_final_report(
        self,
        project_id: str,
        project_name: str,
        findings: List[Dict[str, Any]],
        verifications: List[Dict[str, Any]],
        output_dir: str,
        ai_mode: str = "LOCAL_FALLBACK",
        model: str = "openai/gpt-oss-120b",
        audit_trail: Optional[List[Dict[str, Any]]] = None,
        compressed_packets: Optional[List[Dict[str, Any]]] = None,
        actions_log: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, str]:
        
        report_dir = Path(output_dir).resolve()
        report_dir.mkdir(parents=True, exist_ok=True)

        md_path = report_dir / "VAJRA_Security_Audit_Report.md"
        json_path = report_dir / "VAJRA_Security_Audit_Report.json"

        audit_trail = audit_trail or []
        compressed_packets = compressed_packets or []
        actions_log = actions_log or []

        # Construct JSON report
        json_data = {
            "report_title": "VAJRA Executive Security Assessment & Remediation Report",
            "project_id": project_id,
            "project_name": project_name,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ai_execution_mode": ai_mode,
            "configured_model": model,
            "summary": {
                "total_findings": len(findings),
                "verified_fixes": sum(1 for v in verifications if v.get("status") == "VERIFIED"),
                "failed_remediations": sum(1 for v in verifications if v.get("status") == "REMEDIATION_FAILED")
            },
            "findings": findings,
            "compressed_evidence_packets": compressed_packets,
            "ai_actions_log": actions_log,
            "verifications": verifications,
            "mission_audit_trail": audit_trail
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

        # Construct Markdown report
        md_content = f"""# VAJRA Executive Security Audit Report

**Project Name:** {project_name}  
**Project ID:** `{project_id}`  
**Date:** {json_data['generated_at']}  
**AI Execution Mode:** `{ai_mode}`  
**Configured AI Model:** `{model}`  
**Platform:** VAJRA (Verified Autonomous Joint Reasoning & Remediation Architecture)

---

## 1. Executive Summary

- **Total Findings Discovered:** `{json_data['summary']['total_findings']}`
- **Verified Remediations:** `{json_data['summary']['verified_fixes']}`
- **Remediation Failures:** `{json_data['summary']['failed_remediations']}`
- **Deterministic Verification Authority:** Granted strictly by local compiler, ASan, and SAST re-scanning checks.

---

## 2. Vulnerability & Evidence Breakdown

"""
        for f in findings:
            md_content += f"""### Finding {f.get('finding_id')}: {f.get('cwe')} in `{f.get('file')}`
- **Severity:** `{f.get('severity')}`
- **File & Line:** `{f.get('file')}:{f.get('line')}`
- **Function:** `{f.get('function')}`
- **Description:** {f.get('description')}
- **Remediation Status:** `{f.get('status')}`

"""

        if actions_log:
            md_content += f"""---

## 3. AI Reasoning & Selected Actions

"""
            for act in actions_log:
                safe_reason = str(act.get('reason', '')).encode('ascii', errors='ignore').decode('ascii')
                md_content += f"""- **Action Selected:** `{act.get('action_type')}`
- **Target File:** `{act.get('target')}`
- **Confidence Score:** `{act.get('confidence')}`
- **AI Reasoning:** {safe_reason}

"""

        if verifications:
            md_content += f"""---

## 4. Deterministic Verification Results

"""
            for v in verifications:
                md_content += f"""- **Status:** `{v.get('status')}`
- **Compilation Check:** `{"PASS" if v.get("compilation_passed") else "FAIL"}`
- **PoV Replay Check:** `{"PASS" if v.get("pov_replay_passed") else "FAIL"}`
- **AddressSanitizer Check:** `{"CLEAN" if v.get("asan_clean") else "FAIL"}`
- **SAST Re-scan Check:** `{"CLEAN" if v.get("sast_recheck_clean") else "FAIL"}`
- **Details:** {v.get('details')}

"""

        if audit_trail:
            md_content += f"""---

## 5. Mission Audit Trail

| Timestamp | Stage | Status | Details | AI Mode |
|:---|:---|:---:|:---|:---:|
"""
            for entry in audit_trail:
                md_content += f"| `{entry.get('timestamp')}` | **{entry.get('stage')}** | `{entry.get('status')}` | {entry.get('details')} | `{entry.get('ai_mode')}` |\n"

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return {
            "markdown_report": str(md_path),
            "json_report": str(json_path)
        }
