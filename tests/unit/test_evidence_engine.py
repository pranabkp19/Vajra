import pytest
from pathlib import Path
from backend.evidence.schemas import SASTFinding, SeverityEnum, CorrelatedFinding, LLMAction, ActionTypeEnum
from backend.evidence.correlator import EvidenceCorrelator
from backend.evidence.evidence_compressor import EvidenceCompressor
from backend.actions.action_validator import ActionValidator
from backend.remediation.patch_applier import PatchApplier

def test_evidence_correlation():
    correlator = EvidenceCorrelator()
    sast_raw = [{
        "tool": "Semgrep",
        "rule_id": "c-unsafe-strcpy",
        "cwe": "CWE-787",
        "severity": "HIGH",
        "file": "parser.c",
        "line": 10,
        "message": "Unsafe strcpy call",
        "snippet": "strcpy(buf, in);"
    }]
    
    correlated = correlator.correlate("proj_test", sast_raw, [], [], [])
    assert len(correlated) == 1
    assert correlated[0].cwe == "CWE-787"
    assert correlated[0].file == "parser.c"

def test_evidence_compression(tmp_path):
    # Setup test file
    src_file = tmp_path / "parser.c"
    src_file.write_text("#include <stdio.h>\nvoid parse_header() {\n  char buf[64];\n  strcpy(buf, in);\n}\n")

    finding = CorrelatedFinding(
        finding_id="F-001",
        project_id="proj_test",
        language="C",
        cwe="CWE-787",
        severity=SeverityEnum.HIGH,
        file="parser.c",
        function="parse_header",
        line=4,
        description="Unsafe strcpy call"
    )

    compressor = EvidenceCompressor()
    packet = compressor.compress_evidence(finding, str(tmp_path), workflow_state="DISCOVERED")
    
    assert packet.finding_id == "F-001"
    assert "strcpy" in packet.relevant_source
    assert packet.line == 4

def test_action_validator_sandbox(tmp_path):
    validator = ActionValidator(workspace_root=str(tmp_path))
    project_dir = tmp_path / "projects" / "p1"
    project_dir.mkdir(parents=True)

    # Valid action
    action_valid = LLMAction(
        action_type=ActionTypeEnum.RUN_ASAN,
        target="parser.c",
        reason="Testing ASan execution",
        confidence=0.9
    )
    ok, msg = validator.validate_action(action_valid, str(project_dir))
    assert ok is True

    # Path traversal attack action
    action_invalid = LLMAction(
        action_type=ActionTypeEnum.RUN_ASAN,
        target="../../etc/passwd",
        reason="Malicious path traversal attempt",
        confidence=0.9
    )
    ok_inv, msg_inv = validator.validate_action(action_invalid, str(project_dir))
    assert ok_inv is False
    assert "Path traversal" in msg_inv

def test_action_validator_disallowed_extension(tmp_path):
    validator = ActionValidator(workspace_root=str(tmp_path))
    project_dir = tmp_path / "projects" / "p1"
    project_dir.mkdir(parents=True)

    action_disallowed_ext = LLMAction(
        action_type=ActionTypeEnum.RUN_ASAN,
        target="script.exe",
        reason="Unauthorized binary execution attempt",
        confidence=0.9
    )
    ok, msg = validator.validate_action(action_disallowed_ext, str(project_dir))
    assert ok is False
    assert "Extension" in msg

def test_patch_applier_rollback(tmp_path):
    src_file = tmp_path / "target.c"
    original_code = "int main() { char b[10]; strcpy(b, 'test'); }"
    src_file.write_text(original_code)

    applier = PatchApplier()
    # Apply patch
    patch_str = "--- a/target.c\n+++ b/target.c\n@@ -1,1 +1,1 @@\n-strcpy(b, 'test');\n+strncpy(b, 'test', 9);"
    success, msg = applier.apply_patch_string(str(tmp_path), patch_str)
    assert success is True

    # Confirm backup exists
    backup_file = tmp_path / "target.c.orig"
    assert backup_file.exists()

    # Perform rollback
    rb_ok, rb_msg = applier.rollback_patch(str(tmp_path), "target.c")
    assert rb_ok is True
    assert src_file.read_text() == original_code
