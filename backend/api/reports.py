from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, Response
import os
from pathlib import Path
from typing import Dict, Any
from backend.controller.mission_controller import MissionController

router = APIRouter(prefix="/api/reports", tags=["Reports"])
controller = MissionController()

def _get_markdown_report_path(project_id: str) -> str:
    session = controller.get_session_status(project_id)
    if session and "reports" in session and session["reports"].get("markdown_report"):
        md_path = session["reports"]["markdown_report"]
        if os.path.exists(md_path):
            return md_path
            
    # Direct disk fallback check
    project_root = controller.workspace_mgr.projects_dir / project_id
    disk_md = project_root / "reports" / "VAJRA_Security_Audit_Report.md"
    if disk_md.exists():
        return str(disk_md)
        
    return None

@router.get("/{project_id}")
async def get_report_status(project_id: str) -> Dict[str, Any]:
    md_path = _get_markdown_report_path(project_id)
    if not md_path:
        raise HTTPException(status_code=404, detail="Reports not generated yet.")
    return {
        "markdown_report": md_path,
        "json_report": str(Path(md_path).with_suffix(".json"))
    }

@router.get("/{project_id}/view")
async def view_markdown_report(project_id: str):
    """
    Returns plain Markdown content so opening this URL directly in a browser tab
    displays clean, human-readable text instead of raw JSON with escaped newlines.
    """
    md_file = _get_markdown_report_path(project_id)
    if md_file and os.path.exists(md_file):
        with open(md_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return Response(content=content, media_type="text/markdown; charset=utf-8")
    raise HTTPException(status_code=404, detail="Report file not found on disk.")

@router.get("/{project_id}/download/markdown")
async def download_markdown_report(project_id: str):
    md_file = _get_markdown_report_path(project_id)
    if md_file and os.path.exists(md_file):
        return FileResponse(md_file, media_type="text/markdown", filename=f"VAJRA_Report_{project_id}.md")
    raise HTTPException(status_code=404, detail="Markdown report missing on disk.")

@router.get("/{project_id}/download/patch")
async def download_patch_file(project_id: str):
    session = controller.get_session_status(project_id)
    if session:
        actions = session.get("actions_log", [])
        if actions and actions[0].get("proposed_patch"):
            patch_text = actions[0]["proposed_patch"]
            return Response(
                content=patch_text,
                media_type="text/x-diff",
                headers={"Content-Disposition": f"attachment; filename=VAJRA_Patch_{project_id}.patch"}
            )
    
    # Check disk patches folder
    project_root = controller.workspace_mgr.projects_dir / project_id
    patch_file = project_root / "patches" / "latest_patch.patch"
    if patch_file.exists():
        return FileResponse(str(patch_file), media_type="text/x-diff", filename=f"VAJRA_Patch_{project_id}.patch")

    raise HTTPException(status_code=404, detail="No synthesized patch available for this project.")

@router.get("/{project_id}/view/corrected-code")
async def view_corrected_code(project_id: str):
    """
    Returns plain C/C++ source code text so opening in a new tab or modal
    displays clean code instead of raw JSON.
    """
    project_root = controller.workspace_mgr.projects_dir / project_id
    original_dir = project_root / "original"
    
    if not original_dir.exists():
        raise HTTPException(status_code=404, detail="Project workspace directory not found.")
        
    c_cpp_files = controller.workspace_mgr.list_c_cpp_files(str(original_dir))
    if not c_cpp_files:
        raise HTTPException(status_code=404, detail="No target source code files found in project workspace.")
    
    target_file = c_cpp_files[0]
    with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
        code_content = f.read()
        
    return Response(content=code_content, media_type="text/plain; charset=utf-8")

@router.get("/{project_id}/download/corrected-code")
async def download_corrected_code(project_id: str):
    project_root = controller.workspace_mgr.projects_dir / project_id
    original_dir = project_root / "original"
    
    if not original_dir.exists():
        raise HTTPException(status_code=404, detail="Project workspace directory not found.")

    c_cpp_files = controller.workspace_mgr.list_c_cpp_files(str(original_dir))
    if not c_cpp_files:
        raise HTTPException(status_code=404, detail="No target source code files found in project workspace.")
    
    target_file = c_cpp_files[0]
    filename = f"Corrected_{os.path.basename(target_file)}"
    return FileResponse(target_file, media_type="text/plain", filename=filename)
