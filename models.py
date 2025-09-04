from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime

class AnalysisFinding(BaseModel):
    tool: str
    contract: str
    category: str
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    recommendation: Optional[str] = None

class CompilationResult(BaseModel):
    success: bool
    framework: str
    artifacts: List[Dict] = []
    error: Optional[str] = None

class AnalysisResult(BaseModel):
    analysis_id: str
    timestamp: datetime
    input_file: str
    compilation: CompilationResult
    findings: List[AnalysisFinding]
    summary: Dict[str, Any]
    errors: List[Dict] = []

    contract_id: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
