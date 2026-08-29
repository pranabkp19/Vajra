import os
import shutil
import zipfile
import tarfile
import uuid
import time
from typing import Dict, Any, List
from pathlib import Path

class WorkspaceManager:
    """
    Manages isolated project workspaces in VAJRA to ensure security containment.
    Each project gets an isolated directory structure:
    workspace/projects/{project_id}/
        ├── original/
        ├── build/
        ├── fuzz/
        ├── crashes/
        ├── patches/
        └── reports/
    """
    def __init__(self, base_workspace_dir: str = "D:/VAJRA/workspace"):
        self.base_dir = Path(base_workspace_dir).resolve()
        self.projects_dir = self.base_dir / "projects"
        self._ensure_directories()

    def _ensure_directories(self):
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.projects_dir.mkdir(parents=True, exist_ok=True)

    def create_project_workspace(self, project_name: str) -> Dict[str, Any]:
        project_id = f"proj_{uuid.uuid4().hex[:8]}"
        project_root = self.projects_dir / project_id

        subdirs = {
            "original": project_root / "original",
            "build": project_root / "build",
            "fuzz": project_root / "fuzz",
            "crashes": project_root / "crashes",
            "patches": project_root / "patches",
            "reports": project_root / "reports"
        }

        for path in subdirs.values():
            path.mkdir(parents=True, exist_ok=True)

        return {
            "project_id": project_id,
            "name": project_name,
            "root_path": str(project_root),
            "subdirs": {k: str(v) for k, v in subdirs.items()}
        }

    def extract_uploaded_archive(self, archive_path: str, destination_dir: str) -> List[str]:
        """
        Extracts zip or tar archives while validating paths against ZipSlip vulnerabilities.
        """
        extracted_files = []
        dest = Path(destination_dir).resolve()

        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    # Validate path traversal
                    target_path = (dest / member).resolve()
                    if not str(target_path).startswith(str(dest)):
                        raise ValueError(f"Security Alert: Directory traversal detected in zip archive: {member}")
                    zip_ref.extract(member, dest)
                    if target_path.is_file():
                        extracted_files.append(str(target_path))

        elif archive_path.endswith(('.tar', '.tar.gz', '.tgz')):
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                for member in tar_ref.getmembers():
                    target_path = (dest / member.name).resolve()
                    if not str(target_path).startswith(str(dest)):
                        raise ValueError(f"Security Alert: Directory traversal detected in tar archive: {member.name}")
                    tar_ref.extract(member, dest)
                    if target_path.is_file():
                        extracted_files.append(str(target_path))
        else:
            # Single file copy
            src = Path(archive_path).resolve()
            target = (dest / src.name).resolve()
            if src != target:
                shutil.copy2(src, target)
            extracted_files.append(str(target))

        return extracted_files

    def list_c_cpp_files(self, project_dir: str) -> List[str]:
        target_extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'}
        found_files = []
        for root, _, files in os.walk(project_dir):
            for file in files:
                if Path(file).suffix.lower() in target_extensions:
                    found_files.append(str(Path(root) / file))
        return found_files

    def detect_build_system(self, project_dir: str) -> str:
        project_path = Path(project_dir)
        if (project_path / "CMakeLists.txt").exists():
            return "cmake"
        elif (project_path / "Makefile").exists() or (project_path / "makefile").exists():
            return "makefile"
        else:
            return "single_file"

    def get_project_workspace(self, project_id: str) -> Dict[str, str]:
        project_root = self.projects_dir / project_id
        if not project_root.exists():
            raise FileNotFoundError(f"Project workspace {project_id} does not exist.")

        return {
            "project_id": project_id,
            "root": str(project_root),
            "original": str(project_root / "original"),
            "build": str(project_root / "build"),
            "fuzz": str(project_root / "fuzz"),
            "crashes": str(project_root / "crashes"),
            "patches": str(project_root / "patches"),
            "reports": str(project_root / "reports"),
        }
