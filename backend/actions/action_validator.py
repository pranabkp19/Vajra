import urllib.parse
from typing import List, Dict, Any, Tuple
from pathlib import Path
from backend.evidence.schemas import LLMAction, ActionTypeEnum

class ActionValidator:
    """
    SECURITY BOUNDARY: Action Validator.
    
    Ensures LLM output NEVER executes arbitrary commands.
    Validates:
    - Action type against strict allowlist.
    - Workspace path containment (prevent ZipSlip / Path Traversal / LFI).
    - Target file extensions (.c, .cpp, .h, .hpp, .bin, .patch).
    - Workspace boundaries.
    """
    def __init__(self, workspace_root: str = "D:/VAJRA/workspace"):
        self.workspace_root = Path(workspace_root).resolve()
        self.allowed_actions = {action.value for action in ActionTypeEnum}
        self.allowed_extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".txt", ".cmake", ".patch", ".bin", ".in"}

    def validate_action(self, action: LLMAction, project_workspace_dir: str) -> Tuple[bool, str]:
        project_dir = Path(project_workspace_dir).resolve()

        # 1. Containment check: Project dir must be inside workspace root
        if not str(project_dir).startswith(str(self.workspace_root)):
            return False, f"Security Boundary Error: Workspace directory {project_workspace_dir} is outside authorized root {self.workspace_root}"

        # 2. Allowlist Action Check
        if action.action_type.value not in self.allowed_actions:
            return False, f"Security Boundary Error: Action type '{action.action_type}' is not in allowed actions list."

        # 3. Target File Traversal & Null Target Check
        if not action.target or str(action.target).strip() == "":
            return False, "Security Boundary Error: Target cannot be null or empty."

        if action.target not in ["all", "project"]:
            # Iteratively URL-unquote target to handle double/triple-encoded traversal attempts (%252e%252e%252f)
            raw_target = str(action.target).strip()
            for _ in range(5):
                decoded = urllib.parse.unquote(raw_target)
                if decoded == raw_target:
                    break
                raw_target = decoded

            target_path = (project_dir / raw_target).resolve()
            
            # Check for path traversal attempts (e.g. ../../etc/passwd)
            if not str(target_path).startswith(str(project_dir)):
                return False, f"Security Boundary Violation: Path traversal detected in target '{action.target}'"

            # Check extension if target is a file
            if target_path.suffix and target_path.suffix.lower() not in self.allowed_extensions:
                return False, f"Security Boundary Violation: Extension '{target_path.suffix}' not permitted."

        return True, "Action approved by VAJRA Security Boundary Validator."
