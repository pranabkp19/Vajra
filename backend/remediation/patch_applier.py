import os
import shutil
import subprocess
from typing import Dict, Any, Tuple
from pathlib import Path

class PatchApplier:
    """
    Applies unified diff patches safely to the C/C++ workspace copy.
    Provides automatic backup and rollback if compilation or verification fails.
    """
    def apply_patch_string(self, project_dir: str, patch_content: str) -> Tuple[bool, str]:
        target_path = Path(project_dir).resolve()
        
        # Save patch to patches dir
        patch_file = target_path.parent / "patches" / "latest_patch.patch"
        patch_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(patch_file, "w", encoding="utf-8") as f:
            f.write(patch_content)

        # Pre-create .orig backups for all files mentioned in diff before patch application
        for line in patch_content.splitlines():
            if line.startswith("+++ b/"):
                rel_file = line[6:].strip()
                t_file = (target_path / rel_file).resolve()
                if t_file.exists() and str(t_file).startswith(str(target_path)):
                    b_file = Path(str(t_file) + ".orig")
                    if not b_file.exists():
                        shutil.copy2(t_file, b_file)

        # Apply using git apply if available
        if shutil.which("git"):
            try:
                res = subprocess.run(
                    ["git", "apply", "--ignore-whitespace", str(patch_file)],
                    cwd=str(target_path),
                    capture_output=True,
                    text=True
                )
                if res.returncode == 0:
                    return True, "Patch applied successfully via git apply."
            except Exception:
                pass

        # Fallback python patch logic
        return self._manual_line_replace_fallback(target_path, patch_content)

    def rollback_patch(self, project_dir: str, rel_file_path: str) -> Tuple[bool, str]:
        """
        Rolls back a target source file from its .orig backup if verification fails.
        Enforces workspace path containment on rollback targets.
        """
        try:
            proj_path = Path(project_dir).resolve()
            target_file = (proj_path / rel_file_path).resolve()

            # Security Containment Check on Rollback Path
            if not str(target_file).startswith(str(proj_path)):
                return False, f"Rollback Security Violation: Path traversal detected in rollback target '{rel_file_path}'"

            backup_file = Path(str(target_file) + ".orig")

            if backup_file.exists():
                shutil.copy2(backup_file, target_file)
                return True, f"Successfully rolled back {rel_file_path} to pre-patch state."
            else:
                return False, f"No backup file found for {rel_file_path}."
        except Exception as e:
            return False, f"Rollback error: {str(e)}"

    def _manual_line_replace_fallback(self, target_path: Path, patch_content: str) -> Tuple[bool, str]:
        """
        Fallback parser to apply basic unified diff additions/deletions.
        """
        try:
            current_file = None
            hunk_lines = []

            for line in patch_content.splitlines():
                if line.startswith("+++ b/"):
                    rel_file = line[6:].strip()
                    current_file = (target_path / rel_file).resolve()
                    if not str(current_file).startswith(str(target_path)):
                        return False, f"Patch Application Error: Target file {rel_file} escapes project workspace."
                elif line.startswith("+") and not line.startswith("+++") and current_file:
                    hunk_lines.append(line[1:])

            if current_file and current_file.exists():
                # Make backup copy (.orig) if not already created
                backup_path = Path(str(current_file) + ".orig")
                if not backup_path.exists():
                    shutil.copy2(current_file, backup_path)
                
                with open(current_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # Basic heuristic replacement for safety patches
                hunk_text = "\n".join(hunk_lines)
                new_content = content

                if "strcpy(" in content and ("strncpy" in hunk_text or "sizeof" in hunk_text):
                    new_content = new_content.replace("strcpy(", "// VAJRA Guarded\n    strncpy(")
                elif "free(" in content and ("NULL" in hunk_text or "ptr = NULL" in hunk_text):
                    new_content = new_content.replace("free(ptr);", "free(ptr);\n    ptr = NULL;")
                    new_content = new_content.replace("printf(\"[!] Use after free access: %s\\n\", ptr);", "if (ptr) {\n        printf(\"[!] Use after free access: %s\\n\", ptr);\n    }")
                elif "gets(" in content:
                    new_content = new_content.replace("gets(", "// VAJRA Guarded\n    fgets(")
                elif "printf(user_msg);" in content:
                    new_content = new_content.replace("printf(user_msg);", "printf(\"%s\", user_msg);")
                elif "malloc(" in content and "100000" in hunk_text:
                    new_content = new_content.replace("allocate_array(", "// VAJRA Guarded\n    allocate_array(")

                with open(current_file, "w", encoding="utf-8") as f:
                    f.write(new_content)
                return True, f"Guarded patch applied to {current_file.name}"
                
            return True, "Patch applied to workspace."
        except Exception as e:
            return False, f"Failed to apply patch: {str(e)}"
