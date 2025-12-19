"""
API Data Models
===============
Pydantic models for request/response validation.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class CommandCandidate(BaseModel):
    """Input model for command validation."""
    command: str = Field(..., description="NMAP command to validate", example="nmap -sV scanme.nmap.org")
    user_id: Optional[str] = Field(None, description="Optional user identifier")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")

class ValidationIssue(BaseModel):
    """Represents a validation issue."""
    type: str = Field(..., description="Type of issue")
    severity: str = Field(..., description="Severity level")
    message: str = Field(..., description="Issue description")
    suggestion: Optional[str] = Field(None, description="Suggested fix")

class ValidationResult(BaseModel):
    """Output model for validation results."""
    status: str = Field(..., description="Validation status")
    command: str = Field(..., description="Original command")
    valid: bool = Field(..., description="Whether command is valid")
    risk_score: int = Field(..., description="Risk score (0-100)")
    risk_level: str = Field(..., description="Risk level")
    issues: List[ValidationIssue] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    recommendation: str = Field(..., description="Overall recommendation")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class BatchValidationRequest(BaseModel):
    """Request model for batch validation."""
    commands: List[str] = Field(..., description="List of commands")

class BatchValidationResponse(BaseModel):
    """Response model for batch validation."""
    total: int
    valid: int
    invalid: int
    results: List[ValidationResult]

class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    timestamp: str