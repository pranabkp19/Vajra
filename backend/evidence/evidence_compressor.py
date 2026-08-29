import os
from typing import Dict, Any, List, Optional
from pathlib import Path
from backend.evidence.schemas import CorrelatedFinding, CompressedEvidencePacket

class EvidenceCompressor:
    """
    CRITICAL VAJRA COMPONENT: Evidence Compressor.
    
    Transforms huge raw security output (SAST findings, AFL++ corpora, ASan traces, GDB dumps)
    into a small, high-density JSON packet with extracted source code context before sending to GPT-OSS 120B.
    
    Responsibilities:
    1. Filter out raw boilerplate logs and redundant output.
    2. Extract relevant snippet of C/C++ target code (15-20 lines around target line).
    3. Retain crash IDs, stack frame pointers, and memory operation bounds.
    4. Enforce strict JSON schema for LLM input.
    """
    def __init__(self, context_lines_before: int = 10, context_lines_after: int = 10):
        self.context_before = context_lines_before
        self.context_after = context_lines_after

    def compress_evidence(
        self,
        finding: CorrelatedFinding,
        project_original_dir: str,
        workflow_state: str = "DISCOVERED",
        previous_actions: Optional[List[str]] = None
    ) -> CompressedEvidencePacket:
        
        # 1. Extract exact source snippet
        relevant_source = self._extract_source_snippet(
            project_dir=project_original_dir,
            rel_file_path=finding.file,
            target_line=finding.line
        )

        # 2. Extract compact summaries
        sast_summary = None
        if finding.sast:
            sast_summary = {
                "detected": True,
                "rule_id": finding.sast.rule_id,
                "summary": finding.sast.message,
                "line": finding.sast.line
            }

        fuzzing_summary = None
        if finding.fuzzing:
            fuzzing_summary = {
                "crash_found": finding.fuzzing.crash_found,
                "crash_id": finding.fuzzing.crash_id,
                "pov_input_file": finding.fuzzing.input_file
            }

        asan_summary = None
        if finding.asan:
            asan_summary = {
                "detected": finding.asan.detected,
                "type": finding.asan.type,
                "operation": finding.asan.operation,
                "size": finding.asan.size,
                "function": finding.asan.function,
                "line": finding.asan.line
            }

        gdb_summary = None
        if finding.gdb:
            gdb_summary = {
                "function": finding.gdb.function,
                "call_chain": finding.gdb.call_chain,
                "registers": finding.gdb.registers
            }

        return CompressedEvidencePacket(
            finding_id=finding.finding_id,
            project_id=finding.project_id,
            language=finding.language,
            cwe=finding.cwe,
            severity=finding.severity,
            file=finding.file,
            function=finding.function or "unknown",
            line=finding.line,
            sast_summary=sast_summary,
            fuzzing_summary=fuzzing_summary,
            asan_summary=asan_summary,
            gdb_summary=gdb_summary,
            relevant_source=relevant_source,
            workflow_state=workflow_state,
            previous_actions=previous_actions or []
        )

    def _extract_source_snippet(self, project_dir: str, rel_file_path: str, target_line: int) -> str:
        full_path = Path(project_dir) / rel_file_path
        if not full_path.exists():
            # Try recursive search if relative path doesn't match directly
            candidates = list(Path(project_dir).glob(f"**/{Path(rel_file_path).name}"))
            if candidates:
                full_path = candidates[0]
            else:
                return f"// Source file {rel_file_path} not found in workspace."

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            total_lines = len(lines)
            start_idx = max(0, target_line - 1 - self.context_before)
            end_idx = min(total_lines, target_line + self.context_after)

            snippet_lines = []
            for i in range(start_idx, end_idx):
                line_no = i + 1
                prefix = ">> " if line_no == target_line else "   "
                snippet_lines.append(f"{prefix}{line_no:4d} | {lines[i].rstrip()}")

            return "\n".join(snippet_lines)
        except Exception as e:
            return f"// Error reading source snippet: {str(e)}"
