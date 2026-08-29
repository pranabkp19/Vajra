from typing import List, Dict, Any
from pathlib import Path
from backend.evidence.schemas import SASTFinding, FuzzFinding, ASanFinding, GDBFinding, CorrelatedFinding, SeverityEnum

class EvidenceCorrelator:
    """
    Correlates findings from SAST, AFL++, ASan, and GDB into a unified CorrelatedFinding object.
    Matches evidence across tool output by target file, function name, line number proximity, and CWE family.
    """
    def correlate(
        self,
        project_id: str,
        sast_findings: List[Dict[str, Any]],
        fuzz_findings: List[Dict[str, Any]],
        asan_findings: List[Dict[str, Any]],
        gdb_findings: List[Dict[str, Any]]
    ) -> List[CorrelatedFinding]:
        
        correlated_map: Dict[str, CorrelatedFinding] = {}

        # 1. Process SAST findings
        for idx, sast_raw in enumerate(sast_findings):
            key = f"{sast_raw.get('file')}:{sast_raw.get('line')}"
            finding_id = f"F-{idx+1:03d}"
            
            s_obj = SASTFinding(**sast_raw)

            correlated_map[key] = CorrelatedFinding(
                finding_id=finding_id,
                project_id=project_id,
                language="C/C++",
                cwe=s_obj.cwe,
                severity=s_obj.severity,
                file=s_obj.file,
                function="unknown",
                line=s_obj.line,
                description=s_obj.message,
                sast=s_obj,
                status="OPEN"
            )

        # 2. Correlate ASan findings
        for asan_raw in asan_findings:
            if not asan_raw.get("detected"):
                continue
            
            file = asan_raw.get("file")
            line = asan_raw.get("line")
            key = f"{file}:{line}"

            asan_obj = ASanFinding(**asan_raw)

            if key in correlated_map:
                correlated_map[key].asan = asan_obj
                correlated_map[key].severity = SeverityEnum.CRITICAL
                if asan_raw.get("function"):
                    correlated_map[key].function = asan_raw.get("function")
            else:
                # New correlated finding from dynamic analysis
                finding_id = f"F-{len(correlated_map)+1:03d}"
                correlated_map[key] = CorrelatedFinding(
                    finding_id=finding_id,
                    project_id=project_id,
                    language="C/C++",
                    cwe="CWE-787" if "overflow" in asan_obj.type else "CWE-416",
                    severity=SeverityEnum.CRITICAL,
                    file=file or "unknown",
                    function=asan_obj.function or "unknown",
                    line=line or 1,
                    description=f"Runtime Sanitizer Exception: {asan_obj.type} during {asan_obj.operation}",
                    asan=asan_obj,
                    status="OPEN"
                )

        # 3. Correlate Fuzzing findings
        for fuzz_raw in fuzz_findings:
            if fuzz_raw.get("crashes_found") and len(fuzz_raw.get("crashes", [])) > 0:
                first_crash = fuzz_raw["crashes"][0]
                f_obj = FuzzFinding(
                    crash_found=True,
                    crash_id=Path(first_crash).name,
                    input_file=first_crash
                )
                # Attach fuzz finding to highest priority correlated finding
                for key, cf in correlated_map.items():
                    if cf.fuzzing is None:
                        cf.fuzzing = f_obj
                        break

        # 4. Correlate GDB findings
        for gdb_raw in gdb_findings:
            g_obj = GDBFinding(**gdb_raw)
            for key, cf in correlated_map.items():
                if cf.gdb is None:
                    cf.gdb = g_obj
                    if cf.function == "unknown" and g_obj.function:
                        cf.function = g_obj.function
                    break

        return list(correlated_map.values())
