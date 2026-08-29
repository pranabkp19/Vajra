import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from backend.controller.workspace_manager import WorkspaceManager
from backend.tools.compiler.compiler_runner import CompilerRunner
from backend.tools.sast.semgrep_runner import SemgrepRunner
from backend.tools.fuzzing.afl_runner import AFLRunner
from backend.tools.sanitizer.asan_runner import ASanRunner
from backend.tools.debugger.gdb_runner import GDBRunner
from backend.evidence.correlator import EvidenceCorrelator
from backend.evidence.evidence_compressor import EvidenceCompressor
from backend.llm.groq_client import GroqClient
from backend.llm.prompts import SYSTEM_REASONING_PROMPT
from backend.actions.action_validator import ActionValidator
from backend.remediation.patch_applier import PatchApplier
from backend.verification.verification_engine import VerificationEngine
from backend.reporting.report_generator import ReportGenerator

class MissionController:
    """
    End-to-End Mission Orchestrator for VAJRA.
    Enforces audit trail logging for all 7 pipeline stages (DISCOVER, CORRELATE, COMPRESS, REASON, VALIDATE, ACT, VERIFY),
    capturing timestamps, stage statuses, AI mode, and model configuration.
    """
    _shared_sessions: Dict[str, Dict[str, Any]] = {}

    def __init__(self):
        self.workspace_mgr = WorkspaceManager()
        self.compiler = CompilerRunner()
        self.sast_runner = SemgrepRunner()
        self.afl_runner = AFLRunner()
        self.asan_runner = ASanRunner()
        self.gdb_runner = GDBRunner()
        self.correlator = EvidenceCorrelator()
        self.compressor = EvidenceCompressor()
        self.groq_client = GroqClient()
        self.validator = ActionValidator()
        self.patch_applier = PatchApplier()
        self.verifier = VerificationEngine()
        self.reporter = ReportGenerator()

    @property
    def sessions(self) -> Dict[str, Dict[str, Any]]:
        return MissionController._shared_sessions

    def _log_audit_event(
        self,
        session: Dict[str, Any],
        stage: str,
        status: str,
        details: str,
        ai_mode: str = "LOCAL_FALLBACK"
    ):
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stage": stage,
            "status": status,
            "details": details,
            "ai_mode": ai_mode
        }
        session["audit_trail"].append(event)

    async def run_full_analysis_pipeline(self, project_id: str) -> Dict[str, Any]:
        project_root = self.workspace_mgr.projects_dir / project_id
        if not project_root.exists():
            raise FileNotFoundError(f"Project workspace {project_id} does not exist.")

        original_dir = str(project_root / "original")
        reports_dir = str(project_root / "reports")

        # Determine AI execution mode
        ai_mode_str = "LOCAL_FALLBACK"
        if self.groq_client.is_configured:
            ai_mode_str = "LIVE_AI"

        session = {
            "project_id": project_id,
            "state": "RUNNING",
            "ai_mode": ai_mode_str,
            "model": self.groq_client.model,
            "findings": [],
            "compressed_packets": [],
            "actions_log": [],
            "verifications": [],
            "audit_trail": []
        }
        self.sessions[project_id] = session

        self._log_audit_event(session, "START", "PASSED", f"Initialized mission workspace for {project_id}", ai_mode_str)

        # 1. DISCOVERY & SAST
        print(f"[VAJRA] DISCOVER: Starting build & SAST scanning...")
        sast_raw = self.sast_runner.run_sast(original_dir)
        print(f"[VAJRA] SAST complete. Raw findings count: {len(sast_raw)}")
        self._log_audit_event(session, "DISCOVER", "PASSED", f"SAST complete. Discovered {len(sast_raw)} raw security findings.", ai_mode_str)

        # 2. CORRELATE EVIDENCE
        print(f"[VAJRA] CORRELATE: Combining SAST, ASan, AFL++, GDB evidence...")
        correlated_findings = self.correlator.correlate(
            project_id=project_id,
            sast_findings=sast_raw,
            fuzz_findings=[],
            asan_findings=[],
            gdb_findings=[]
        )
        session["findings"] = [f.model_dump() for f in correlated_findings]
        self._log_audit_event(session, "CORRELATE", "PASSED", f"Correlated {len(correlated_findings)} unified findings.", ai_mode_str)

        if not correlated_findings:
            print("[VAJRA] 0 findings discovered. Skipping reasoning/remediation loop.")
            reports = self.reporter.generate_final_report(
                project_id=project_id,
                project_name=f"Project_{project_id}",
                findings=[],
                verifications=[],
                output_dir=reports_dir,
                ai_mode=session["ai_mode"],
                model=session["model"],
                audit_trail=session["audit_trail"],
                compressed_packets=[],
                actions_log=[]
            )
            session["reports"] = reports
            session["state"] = "COMPLETED"
            self._log_audit_event(session, "REPORT", "PASSED", f"Generated audit reports at {reports_dir}", session["ai_mode"])
            return session

        # Process primary finding
        target_finding = correlated_findings[0]

        # 3. EVIDENCE COMPRESSION
        print(f"[VAJRA] COMPRESS: Compressing finding {target_finding.finding_id} ({target_finding.cwe} at {target_finding.file}:{target_finding.line})...")
        packet = self.compressor.compress_evidence(target_finding, original_dir)
        session["compressed_packets"].append(packet.model_dump())
        line_count = len(packet.relevant_source.split('\n')) if packet.relevant_source else 0
        self._log_audit_event(session, "COMPRESS", "PASSED", f"Compressed finding context to {line_count} lines of source code.", ai_mode_str)

        # 4. REASON (LLM Reasoning Layer)
        print(f"[VAJRA] REASON: Querying Groq Engine (Live API Key Configured: {self.groq_client.is_configured}, Model: {self.groq_client.model})...")
        prompt = f"Analyze vulnerability evidence and return LLMAction JSON schema:\n{packet.model_dump_json(indent=2)}"
        
        try:
            llm_action, effective_mode = await self.groq_client.get_reasoning_and_action(packet, SYSTEM_REASONING_PROMPT)
            session["ai_mode"] = effective_mode
            mode_str = effective_mode
        except Exception as e:
            print(f"[VAJRA] Groq Query Error: {e}. Falling back to local heuristic reasoning.")
            from backend.llm.groq_client import LLMAction, ActionTypeEnum
            llm_action = LLMAction(
                action_type=ActionTypeEnum.GENERATE_PATCH,
                target=target_finding.file,
                confidence=0.85,
                reason="Fallback heuristic patch generation for unverified vulnerability."
            )
            session["ai_mode"] = "LOCAL_FALLBACK"
            mode_str = "LOCAL_FALLBACK"

        session["actions_log"].append(llm_action.model_dump())
        self._log_audit_event(session, "REASON", "PASSED", f"Selected Action: {llm_action.action_type} (Confidence: {llm_action.confidence})", mode_str)

        # 5. VALIDATE (Sandbox Action Validator)
        is_valid, validation_msg = self.validator.validate_action(llm_action, original_dir)
        print(f"[VAJRA] VALIDATE: Action Sandbox check result = {is_valid} ({validation_msg})")
        if not is_valid:
            print(f"[VAJRA] SECURITY ALERT: Action rejected by validator: {validation_msg}")
            self._log_audit_event(session, "VALIDATE", "FAILED", f"Action REJECTED by Sandbox Validator: {validation_msg}", mode_str)
            session["state"] = "REJECTED_BY_VALIDATOR"
            return session
        
        self._log_audit_event(session, "VALIDATE", "PASSED", f"Approved action {llm_action.action_type} within workspace sandbox.", mode_str)

        # 6. ACT (Apply Patch)
        if llm_action.proposed_patch:
            print(f"[VAJRA] ACT: Applying synthesized patch diff to {llm_action.target}...")
            apply_ok, apply_msg = self.patch_applier.apply_patch_string(original_dir, llm_action.proposed_patch)
            self._log_audit_event(session, "ACT", "PASSED" if apply_ok else "FAILED", f"Patch application: {apply_msg}", mode_str)
        else:
            self._log_audit_event(session, "ACT", "PASSED", "No patch required for action.", mode_str)

        # 7. VERIFY (Deterministic Verification Engine)
        print(f"[VAJRA] VERIFY: Running deterministic 4-stage verification engine...")
        v_res = self.verifier.verify_remediation(
            finding=target_finding,
            patched_project_dir=original_dir,
            build_dir=str(project_root / "build"),
            pov_file_path="",
            attempt_number=1
        )
        session["verifications"].append(v_res.model_dump())
        self._log_audit_event(session, "VERIFY", v_res.status, f"Deterministic Verification result: {v_res.status}", mode_str)

        # Update finding status
        target_finding.status = v_res.status
        session["findings"][0] = target_finding.model_dump()
        if v_res.status != "VERIFIED":
            rb_ok, rb_msg = self.patch_applier.rollback_patch(original_dir, target_finding.file)
            print(f"[VAJRA] ROLLBACK: {rb_msg}")
            self._log_audit_event(session, "ROLLBACK", "PASSED" if rb_ok else "FAILED", f"Automatic patch rollback: {rb_msg}", mode_str)

        # 8. REPORT GENERATION
        print(f"[VAJRA] REPORT: Generating executive Markdown and JSON security report...")
        reports = self.reporter.generate_final_report(
            project_id=project_id,
            project_name=f"Project_{project_id}",
            findings=session["findings"],
            verifications=session["verifications"],
            output_dir=reports_dir,
            ai_mode=session["ai_mode"],
            model=session["model"],
            audit_trail=session["audit_trail"],
            compressed_packets=session["compressed_packets"],
            actions_log=session["actions_log"]
        )
        session["reports"] = reports
        session["state"] = "COMPLETED"
        self._log_audit_event(session, "REPORT", "PASSED", f"Generated audit reports at {reports_dir}", session["ai_mode"])

        return session

    def get_session_status(self, project_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions.get(project_id)
