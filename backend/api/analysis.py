from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, Any
from backend.controller.mission_controller import MissionController

router = APIRouter(prefix="/api/analysis", tags=["Analysis"])
controller = MissionController()

@router.post("/start/{project_id}")
async def start_analysis(project_id: str, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    try:
        # Run asynchronous analysis pipeline
        result = await controller.run_full_analysis_pipeline(project_id)
        return {
            "status": "completed",
            "project_id": project_id,
            "session": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")

@router.get("/status/{project_id}")
async def get_analysis_status(project_id: str) -> Dict[str, Any]:
    status = controller.get_session_status(project_id)
    if not status:
        return {"project_id": project_id, "state": "IDLE", "findings": []}
    return status
