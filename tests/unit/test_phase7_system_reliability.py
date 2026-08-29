import os
import pytest
import asyncio
import hashlib
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from backend.actions.action_validator import ActionValidator
from backend.evidence.schemas import LLMAction, ActionTypeEnum, CorrelatedFinding, SeverityEnum
from backend.remediation.patch_applier import PatchApplier
from backend.verification.verification_engine import VerificationEngine
from backend.reporting.report_generator import ReportGenerator
from backend.llm.groq_client import GroqClient
from backend.controller.mission_controller import MissionController
from backend.controller.workspace_manager import WorkspaceManager

def get_hash(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def test_encoded_and_mixed_slash_path_traversal(tmp_path):
    validator = ActionValidator(workspace_root=str(tmp_path))
    project_dir = tmp_path / "projects" / "p1"
    project_dir.mkdir(parents=True)

    attack_targets = [
        "%2e%2e%2f%2e%2e%2fwindows%2fsystem32%2fcmd.exe",
        "%252e%252e%252foutside.c",
        "..\\..\\windows\\system32\\cmd.exe",
        "../..\\outside/file.c",
        "folder/%2e%2e/%2e%2e/etc/passwd",
        " ..\\..\\etc\\passwd "
    ]

    for target in attack_targets:
        action = LLMAction(
            action_type=ActionTypeEnum.RUN_ASAN,
            target=target,
            reason="Encoded/mixed path traversal attempt",
            confidence=0.9
        )
        ok, msg = validator.validate_action(action, str(project_dir))
        assert ok is False, f"Target '{target}' was incorrectly approved!"
        assert ("Path traversal" in msg or "Extension" in msg or "Security Boundary" in msg)

def test_whitespace_and_empty_target_rejection(tmp_path):
    validator = ActionValidator(workspace_root=str(tmp_path))
    project_dir = tmp_path / "projects" / "p1"
    project_dir.mkdir(parents=True)

    bad_targets = ["", "   ", "\t", "\n"]
    for bt in bad_targets:
        action = LLMAction(
            action_type=ActionTypeEnum.RUN_ASAN,
            target=bt,
            reason="Whitespace target test",
            confidence=0.9
        )
        ok, msg = validator.validate_action(action, str(project_dir))
        assert ok is False
        assert "null or empty" in msg

def test_patch_applier_rollback_missing_backup_handled_safely(tmp_path):
    applier = PatchApplier()
    # Attempt rollback when no .orig exists
    ok, msg = applier.rollback_patch(str(tmp_path), "nonexistent.c")
    assert ok is False
    assert "No backup file found" in msg

def test_patch_applier_rollback_path_traversal_blocked(tmp_path):
    applier = PatchApplier()
    # Attempt rollback with path traversal target
    ok, msg = applier.rollback_patch(str(tmp_path), "../../outside.c")
    assert ok is False
    assert "Path traversal" in msg

def test_report_generator_handles_failure_and_fallback_modes(tmp_path):
    reporter = ReportGenerator()
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()

    findings = [{
        "finding_id": "F-001",
        "cwe": "CWE-787",
        "severity": "HIGH",
        "file": "target.c",
        "line": 10,
        "description": "Stack buffer overflow",
        "status": "REMEDIATION_FAILED"
    }]
    verifications = [{
        "finding_id": "F-001",
        "attempt_number": 1,
        "compilation_passed": False,
        "pov_replay_passed": False,
        "asan_clean": False,
        "sast_recheck_clean": False,
        "status": "REMEDIATION_FAILED",
        "details": "Compilation failed"
    }]
    audit_trail = [
        {"stage": "START", "status": "PASSED", "timestamp": "2026-08-28T20:00:00Z", "detail": "Mission started"},
        {"stage": "VERIFY", "status": "FAILED", "timestamp": "2026-08-28T20:00:05Z", "detail": "Verification failed"}
    ]

    reports = reporter.generate_final_report(
        project_id="proj_test_fail",
        project_name="Project_Test_Fail",
        findings=findings,
        verifications=verifications,
        output_dir=str(reports_dir),
        ai_mode="RATE_LIMITED",
        model="openai/gpt-oss-120b",
        audit_trail=audit_trail,
        compressed_packets=[],
        actions_log=[]
    )

    assert "markdown_report" in reports
    assert "json_report" in reports

    md_content = Path(reports["markdown_report"]).read_text()
    assert "REMEDIATION_FAILED" in md_content
    assert "RATE_LIMITED" in md_content
    assert "LIVE_AI" not in md_content

def test_repeated_mission_execution_stability():
    async def run_repeated():
        wm = WorkspaceManager()
        mc = MissionController()

        p = wm.create_project_workspace("vulnerable_sample.c")
        src_path = os.path.join("tests/fixtures", "vulnerable_sample.c")
        dst_path = os.path.join(p["subdirs"]["original"], "vulnerable_sample.c")

        with open(src_path, "rb") as s, open(dst_path, "wb") as d:
            d.write(s.read())

        # Mission 1
        s1 = await mc.run_full_analysis_pipeline(p["project_id"])
        assert s1["state"] == "COMPLETED"
        assert len(s1["audit_trail"]) >= 8

        # Mission 2
        s2 = await mc.run_full_analysis_pipeline(p["project_id"])
        assert s2["state"] == "COMPLETED"
        assert len(s2["audit_trail"]) >= 4

    asyncio.run(run_repeated())
