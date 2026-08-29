from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from backend.controller.mission_controller import MissionController

router = APIRouter(prefix="/api/findings", tags=["Findings"])
controller = MissionController()

@router.get("/{project_id}")
async def get_findings(project_id: str) -> List[Dict[str, Any]]:
    session = controller.get_session_status(project_id)
    if not session:
        return []
    return session.get("findings", [])

@router.get("/{project_id}/compressed-evidence")
async def get_compressed_evidence(project_id: str) -> List[Dict[str, Any]]:
    session = controller.get_session_status(project_id)
    if not session:
        return []
    return session.get("compressed_packets", [])
