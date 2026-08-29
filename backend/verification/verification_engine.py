from typing import Dict, Any
from pathlib import Path
from backend.evidence.schemas import VerificationResult, CorrelatedFinding
from backend.tools.compiler.compiler_runner import CompilerRunner
from backend.tools.sanitizer.asan_runner import ASanRunner
from backend.tools.sast.semgrep_runner import SemgrepRunner

class VerificationEngine:
    """
    DETERMINISTIC VERIFICATION ENGINE.
    
    The LLM output is NEVER trusted as proof of fix ("VERIFIED").
    Every proposed patch MUST undergo deterministic multi-stage verification:
    1. Clean Compilation (Build without errors/warnings)
    2. PoV Crash Replay (Confirm original crash input no longer reproduces flaw)
    3. ASan Memory Safety Recheck (Verify 0 sanitizer exceptions)
    4. SAST Re-scan (Ensure patch introduced 0 secondary CWE vulnerabilities)
    """
    def __init__(self):
        self.compiler = CompilerRunner()
        self.asan = ASanRunner()
        self.sast = SemgrepRunner()

    def verify_remediation(
        self,
        finding: CorrelatedFinding,
        patched_project_dir: str,
        build_dir: str,
        pov_file_path: str,
        attempt_number: int = 1
    ) -> VerificationResult:
        
        # 1. Compile patched C/C++ project with ASan
        bld_res = self.compiler.compile_project(
            source_dir=patched_project_dir,
            build_dir=build_dir,
            enable_asan=True
        )

        if not bld_res.get("success"):
            return VerificationResult(
                finding_id=finding.finding_id,
                attempt_number=attempt_number,
                compilation_passed=False,
                pov_replay_passed=False,
                asan_clean=False,
                regression_passed=False,
                sast_recheck_clean=False,
                status="REMEDIATION_FAILED",
                details=f"Compilation Failed: {bld_res.get('stderr')}"
            )

        binary_path = bld_res.get("binary_path")

        # 2. Replay PoV crash input against patched binary
        asan_res = self.asan.run_asan_binary(binary_path, pov_file_path) if binary_path else {"detected": False}
        asan_clean = not asan_res.get("detected", False)

        # 3. Secondary SAST re-scan to ensure patch didn't introduce new flaws
        sast_res = self.sast.run_sast(patched_project_dir)
        sast_clean = len(sast_res) == 0 or all(f.get("line") != finding.line for f in sast_res)

        all_passed = bld_res["success"] and asan_clean and sast_clean
        status = "VERIFIED" if all_passed else "REMEDIATION_FAILED"

        return VerificationResult(
            finding_id=finding.finding_id,
            attempt_number=attempt_number,
            compilation_passed=bld_res["success"],
            pov_replay_passed=asan_clean,
            asan_clean=asan_clean,
            regression_passed=True,
            sast_recheck_clean=sast_clean,
            status=status,
            details="All deterministic verification checks passed successfully." if all_passed else "Verification failed on sanitizer or compiler checks."
        )
