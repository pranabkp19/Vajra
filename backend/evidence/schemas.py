from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum

class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ActionTypeEnum(str, Enum):
    RUN_SAST = "RUN_SAST"
    RUN_FUZZ = "RUN_FUZZ"
    RUN_ASAN = "RUN_ASAN"
    RUN_GDB = "RUN_GDB"
    REPLAY_POV = "REPLAY_POV"
    GENERATE_PATCH = "GENERATE_PATCH"
    RUN_BUILD = "RUN_BUILD"
    RUN_REGRESSION = "RUN_REGRESSION"
    VERIFY = "VERIFY"
    TRIAGE = "TRIAGE"
    STOP = "STOP"

class SASTFinding(BaseModel):
    tool: str = "Semgrep"
    rule_id: str
    cwe: str
    severity: SeverityEnum
    file: str
    line: int
    column: Optional[int] = 0
    message: str
    snippet: Optional[str] = ""

class FuzzFinding(BaseModel):
    tool: str = "AFL++"
    crash_found: bool = True
    crash_id: str
    input_file: str
    signal: Optional[str] = None
    execution_time_seconds: Optional[float] = 0.0

class ASanFinding(BaseModel):
    tool: str = "ASan"
    detected: bool = True
    type: str  # e.g., stack-buffer-overflow, heap-buffer-overflow, use-after-free
    operation: str  # READ or WRITE
    size: int
    file: Optional[str] = None
    line: Optional[int] = None
    function: Optional[str] = None
    shadow_bytes: Optional[str] = None

class GDBFinding(BaseModel):
    tool: str = "GDB"
    function: str
    file: Optional[str] = None
    line: Optional[int] = None
    call_chain: List[str] = Field(default_factory=list)
    registers: Dict[str, str] = Field(default_factory=dict)
    local_vars: Dict[str, str] = Field(default_factory=dict)

class CorrelatedFinding(BaseModel):
    finding_id: str
    project_id: str
    language: str = "C"
    cwe: str
    severity: SeverityEnum
    file: str
    function: Optional[str] = "unknown"
    line: int
    description: str
    sast: Optional[SASTFinding] = None
    fuzzing: Optional[FuzzFinding] = None
    asan: Optional[ASanFinding] = None
    gdb: Optional[GDBFinding] = None
    status: str = "OPEN" # OPEN, IN_PROGRESS, PATCH_PROPOSED, VERIFIED, REMEDIATION_FAILED

class CompressedEvidencePacket(BaseModel):
    finding_id: str
    project_id: str
    language: str
    cwe: str
    severity: SeverityEnum
    file: str
    function: str
    line: int
    sast_summary: Optional[Dict[str, Any]] = None
    fuzzing_summary: Optional[Dict[str, Any]] = None
    asan_summary: Optional[Dict[str, Any]] = None
    gdb_summary: Optional[Dict[str, Any]] = None
    relevant_source: str
    workflow_state: str
    previous_actions: List[str] = Field(default_factory=list)

class LLMAction(BaseModel):
    action_type: ActionTypeEnum
    target: str
    reason: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    proposed_patch: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)

class VerificationResult(BaseModel):
    finding_id: str
    attempt_number: int
    compilation_passed: bool
    pov_replay_passed: bool
    asan_clean: bool
    regression_passed: bool
    sast_recheck_clean: bool
    status: str # VERIFIED or REMEDIATION_FAILED
    details: str
    patch_diff: Optional[str] = None

class ProjectMetadata(BaseModel):
    project_id: str
    name: str
    uploaded_at: str
    workspace_path: str
    language: str = "C/C++"
    build_system: str  # cmake, makefile, single-file
    source_files: List[str] = Field(default_factory=list)
