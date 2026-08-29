import os
import shutil
import time
from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import Dict, Any, List
from backend.controller.workspace_manager import WorkspaceManager

router = APIRouter(prefix="/api/projects", tags=["Projects"])
workspace_mgr = WorkspaceManager()

@router.post("/upload")
async def upload_project(file: UploadFile = File(...)) -> Dict[str, Any]:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename missing.")

    # Create workspace
    project_meta = workspace_mgr.create_project_workspace(file.filename)
    project_id = project_meta["project_id"]
    original_dir = project_meta["subdirs"]["original"]

    filename = file.filename
    target_dest = os.path.join(original_dir, filename)

    # Read binary bytes
    file_bytes = await file.read()
    await file.close()

    if filename.endswith(('.zip', '.tar', '.gz', '.tgz')):
        # Save temp archive file outside target dest
        temp_archive = os.path.join(original_dir, f"temp_{filename}")
        with open(temp_archive, "wb") as f:
            f.write(file_bytes)
        try:
            workspace_mgr.extract_uploaded_archive(temp_archive, original_dir)
        finally:
            if os.path.exists(temp_archive):
                os.remove(temp_archive)
    else:
        # Single C/C++ source file
        with open(target_dest, "wb") as f:
            f.write(file_bytes)

    source_files = workspace_mgr.list_c_cpp_files(original_dir)
    build_system = workspace_mgr.detect_build_system(original_dir)

    return {
        "status": "success",
        "project_id": project_id,
        "name": filename,
        "build_system": build_system,
        "source_files_count": len(source_files),
        "source_files": [os.path.basename(sf) for sf in source_files[:10]],
        "workspace": project_meta
    }

@router.get("/{project_id}")
async def get_project_details(project_id: str) -> Dict[str, Any]:
    try:
        ws = workspace_mgr.get_project_workspace(project_id)
        source_files = workspace_mgr.list_c_cpp_files(ws["original"])
        return {
            "project_id": project_id,
            "workspace": ws,
            "source_files": source_files,
            "build_system": workspace_mgr.detect_build_system(ws["original"])
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Project not found")
