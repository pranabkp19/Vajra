import hashlib
import pytest
from pathlib import Path
from backend.actions.action_validator import ActionValidator
from backend.evidence.schemas import LLMAction, ActionTypeEnum, CorrelatedFinding, SeverityEnum
from backend.remediation.patch_applier import PatchApplier
from backend.verification.verification_engine import VerificationEngine

def get_file_hash(filepath: Path) -> str:
    return hashlib.sha256(filepath.read_bytes()).hexdigest()

def test_action_validator_absolute_windows_path(tmp_path):
    validator = ActionValidator(workspace_root=str(tmp_path))
    project_dir = tmp_path / "projects" / "p1"
    project_dir.mkdir(parents=True)

    action = LLMAction(
        action_type=ActionTypeEnum.RUN_ASAN,
        target="C:\\Windows\\System32\\cmd.exe",
        reason="Absolute Windows path traversal attempt",
        confidence=0.9
    )
    ok, msg = validator.validate_action(action, str(project_dir))
    assert ok is False
    assert "Path traversal" in msg

def test_action_validator_unc_path(tmp_path):
    validator = ActionValidator(workspace_root=str(tmp_path))
    project_dir = tmp_path / "projects" / "p1"
    project_dir.mkdir(parents=True)

    action = LLMAction(
        action_type=ActionTypeEnum.RUN_ASAN,
        target="\\\\localhost\\C$\\Windows\\System32\\cmd.exe",
        reason="UNC path traversal attempt",
        confidence=0.9
    )
    ok, msg = validator.validate_action(action, str(project_dir))
    assert ok is False
    assert "Path traversal" in msg

def test_action_validator_disallowed_extensions_comprehensive(tmp_path):
    validator = ActionValidator(workspace_root=str(tmp_path))
    project_dir = tmp_path / "projects" / "p1"
    project_dir.mkdir(parents=True)

    bad_exts = [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".com", ".scr", ".EXE", ".Ps1"]
    for ext in bad_exts:
        action = LLMAction(
            action_type=ActionTypeEnum.RUN_ASAN,
            target=f"malicious{ext}",
            reason=f"Disallowed extension test for {ext}",
            confidence=0.9
        )
        ok, msg = validator.validate_action(action, str(project_dir))
        assert ok is False
        assert "Extension" in msg

def test_action_validator_null_or_empty_target(tmp_path):
    validator = ActionValidator(workspace_root=str(tmp_path))
    project_dir = tmp_path / "projects" / "p1"
    project_dir.mkdir(parents=True)

    action = LLMAction(
        action_type=ActionTypeEnum.RUN_ASAN,
        target="",
        reason="Empty target test",
        confidence=0.9
    )
    ok, msg = validator.validate_action(action, str(project_dir))
    assert ok is False
    assert "null or empty" in msg

def test_rollback_hash_exact_match(tmp_path):
    src_file = tmp_path / "vulnerable.c"
    original_content = "int main() {\n  char buf[10];\n  strcpy(buf, 'input');\n  return 0;\n}\n"
    src_file.write_text(original_content)

    orig_hash = get_file_hash(src_file)

    applier = PatchApplier()
    # Apply patch
    patch_str = "--- a/vulnerable.c\n+++ b/vulnerable.c\n@@ -3,1 +3,1 @@\n-  strcpy(buf, 'input');\n+  strncpy(buf, 'input', 9);"
    applier.apply_patch_string(str(tmp_path), patch_str)

    patched_hash = get_file_hash(src_file)
    assert patched_hash != orig_hash

    # Execute rollback
    rb_ok, rb_msg = applier.rollback_patch(str(tmp_path), "vulnerable.c")
    assert rb_ok is True

    restored_hash = get_file_hash(src_file)
    assert restored_hash == orig_hash

def test_llm_cannot_set_verified_status(tmp_path):
    # Setup uncompilable source code
    src_file = tmp_path / "broken.c"
    src_file.write_text("int main() { INVALID_SYNTAX___; return 0; }")

    finding = CorrelatedFinding(
        finding_id="F-999",
        project_id="p1",
        language="C",
        cwe="CWE-787",
        severity=SeverityEnum.HIGH,
        file="broken.c",
        function="main",
        line=1,
        description="Test finding"
    )

    engine = VerificationEngine()
    bld_dir = tmp_path / "build"
    bld_dir.mkdir()

    v_res = engine.verify_remediation(finding, str(tmp_path), str(bld_dir), str(tmp_path / "crash.bin"))
    
    # Verify status is REMEDIATION_FAILED regardless of any external claims
    assert v_res.status == "REMEDIATION_FAILED"
    assert v_res.compilation_passed is False

def test_llm_action_invalid_confidence():
    from pydantic import ValidationError

    # Confidence > 1.0
    with pytest.raises(ValidationError):
        LLMAction(
            action_type=ActionTypeEnum.RUN_ASAN,
            target="parser.c",
            reason="Confidence out of range test",
            confidence=1.5
        )

    # Confidence < 0.0
    with pytest.raises(ValidationError):
        LLMAction(
            action_type=ActionTypeEnum.RUN_ASAN,
            target="parser.c",
            reason="Negative confidence test",
            confidence=-0.5
        )
