"""
API Routes with Autonomous Repair Support
==========================================
FastAPI route handlers with autonomous repair capability for M5 (Self-Correction Agent).
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any
import os
import logging
import sys

# Ajouter le chemin racine au sys.path pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# IMPORTS CORRECTS : Utiliser validator.py au lieu de validation_v2.py
from validation.json_scorer import ValidationScorer
from validation.security_rules import SecurityRules
from validation.validator import validate_nmap_command, CommandCandidate, validate_batch_commands, get_validation_summary

# Importer les modèles d'abord
try:
    from .models import (
        ValidationResult,
        UserQuery,
        ValidationIssue,
        BatchValidationRequest, 
        BatchValidationResponse,
        HealthResponse,
        CommandCandidate as APICandidate  # Renommer pour éviter conflit
    )
except ImportError as e:
    # Définir les modèles en ligne si l'import échoue
    from pydantic import BaseModel as _BaseModel
    class ValidationIssue(_BaseModel):
        type: str
        severity: str
        message: str
        suggestion: Optional[str] = None
    
    class ValidationResult(_BaseModel):
        status: str
        command: str
        valid: bool
        risk_score: float
        risk_level: str
        issues: List[ValidationIssue]
        warnings: List[str]
        recommendation: str
    
    class BatchValidationResponse(_BaseModel):
        total: int
        valid: int
        invalid: int
        results: List[ValidationResult]
    
    class HealthResponse(_BaseModel):
        status: str
        timestamp: str
        version: str

logger = logging.getLogger(__name__)

# ============================================================================
# NEW: Enhanced Models for Autonomous Repair
# ============================================================================

class CommandCandidateRequest(BaseModel):
    """Request for command validation"""
    command: str = Field(..., description="The Nmap command to validate")
    confidence: Optional[float] = Field(0.0, description="Confidence score from generator (0.0-1.0)")
    source_agent: Optional[str] = Field("unknown", description="Source agent that generated the command")
    user_id: Optional[str] = Field(None, description="User identifier")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")
    execute_real: Optional[bool] = Field(False, description="If True, actually execute the command")

class RepairRequest(BaseModel):
    """Request for self-correction repair with validation context"""
    command: str = Field(..., description="The Nmap command to repair")
    intent: str = Field(default="", description="Original user intent")
    validation_status: str = Field(..., description="Status from M4: 'Repairable', 'Invalid', or 'Valid'")
    issues: List[Dict[str, Any]] = Field(default_factory=list, description="Validation issues found")
    risk_level: str = Field(default="unknown", description="Risk level from validation")
    request_id: str = Field(..., description="Unique request identifier")
    user_id: Optional[str] = Field(default=None, description="User identifier")


class RepairResponse(BaseModel):
    """Response from autonomous/iterative repair"""
    request_id: str
    success: bool = Field(..., description="Whether repair was successful")
    original_command: str
    repaired_command: Optional[str] = None
    source_agent: str = Field(
        ..., 
        description="'SELF-CORR-AUTO' (autonomous), 'SELF-CORR-ITER' (iterative), or 'SELF-CORR-FAILED' (needs M3)"
    )
    is_autonomous_repair: bool = Field(..., description="Whether repair was autonomous (true) or iterative (false)")
    attempts: int = Field(..., description="Number of repair attempts made")
    changes_applied: List[str] = Field(default_factory=list, description="List of changes applied")
    feedback_for_m3: Optional[Dict[str, Any]] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    repair_type: Optional[str] = Field(default=None, description="Type of repair if autonomous (permission_fix, syntax_fix, etc)")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class CommandResponse(BaseModel):
    """Response for command validation with detailed scoring"""
    success: bool
    data: Dict[str, Any]
    metadata: Dict[str, Any]

# ============================================================================
# Router Setup
# ============================================================================

router = APIRouter()

# Initialize self-correction agent conditionally
try:
    from src.utils.agents.self_correction_agent import SelfCorrectionAgent
    self_correction_agent = SelfCorrectionAgent(max_attempts=3)
    AUTO_REPAIR_ENABLED = True
except ImportError:
    logger.warning("SelfCorrectionAgent not available. Autonomous repair disabled.")
    self_correction_agent = None
    AUTO_REPAIR_ENABLED = False

# ============================================================================
# Conversion and Helper Functions
# ============================================================================

def convert_to_validation_result(internal_result: dict) -> ValidationResult:
    """Convert your internal validation result to API format."""
    
    issues = []
    
    # Handle security issues
    if internal_result.get('blocked_by_security') and internal_result.get('issues'):
        for issue_text in internal_result['issues']:
            if "Forbidden flag" in str(issue_text):
                issue_type = "forbidden_flag"
                severity = "critical"
            elif "Unsafe target" in str(issue_text):
                issue_type = "unsafe_target"
                severity = "high"
            else:
                issue_type = "validation_error"
                severity = internal_result.get('severity', 'medium')
            
            issues.append(ValidationIssue(
                type=issue_type,
                severity=severity,
                message=str(issue_text),
                suggestion=None
            ))
    
    # Handle syntax errors
    if not internal_result.get('valid') and not internal_result.get('blocked_by_security'):
        error_msg = internal_result.get('error', 'Unknown validation error')
        issues.append(ValidationIssue(
            type="syntax_error",
            severity=internal_result.get('severity', 'high'),
            message=error_msg,
            suggestion="Check command syntax"
        ))
    
    # Determine status
    if internal_result.get('valid'):
        if internal_result.get('risk_level') in ['high', 'critical']:
            status = "warning"
        else:
            status = "valid"
    else:
        status = "invalid"
    
    # Handle warnings
    warnings = []
    if internal_result.get('warnings'):
        if isinstance(internal_result['warnings'], list):
            warnings = [str(w) for w in internal_result['warnings']]
        else:
            warnings = [str(internal_result['warnings'])]
    
    # Get risk information
    risk_score = internal_result.get('risk_score', 0)
    risk_level = internal_result.get('risk_level', 'unknown')
    recommendation = internal_result.get('recommendation', 'No recommendation')
    
    # If security analysis is available, use it
    if 'security' in internal_result:
        security = internal_result['security']
        risk_score = security.get('risk_score', risk_score)
        risk_level = security.get('risk_level', risk_level)
        recommendation = security.get('recommendation', recommendation)
    
    return ValidationResult(
        status=status,
        command=internal_result.get('command', ''),
        valid=internal_result.get('valid', False),
        risk_score=risk_score,
        risk_level=risk_level,
        issues=issues,
        warnings=warnings,
        recommendation=recommendation
    )


def _extract_all_changes(session) -> List[str]:
    """Extract all changes made across all repair attempts"""
    changes = []
    if hasattr(session, 'attempts'):
        for attempt in session.attempts:
            if hasattr(attempt, 'changes_made'):
                changes.extend(attempt.changes_made)
    return changes


def _prepare_m3_feedback(session) -> Optional[Dict[str, Any]]:
    """Prepare feedback for M3 when repair fails"""
    if not hasattr(session, 'feedback_generated') or not session.feedback_generated:
        return None
    
    feedback = session.feedback_generated[-1]
    return {
        "type": feedback.get("type"),
        "reason": feedback.get("reason"),
        "requires_m3_retry": True,
        "recommendations": feedback.get("recommendations", []),
        "persistent_errors": feedback.get("persistent_errors", []),
        "attempts_made": len(session.attempts) if hasattr(session, 'attempts') else 0
    }


def _get_repair_type(session) -> Optional[str]:
    """Extract repair type from session if autonomous"""
    if hasattr(session, 'attempts') and session.attempts and hasattr(session.attempts[0], 'repair_type'):
        return str(session.attempts[0].repair_type)
    return None


async def _log_repair_event(request_id: str, source_agent: str, command: str, success: bool):
    """Background task: Log repair event"""
    status = "✅" if success else "❌"
    logger.info(f"{status} REPAIR_EVENT | {request_id} | {source_agent} | {command}")


# ============================================================================
# Health Check Endpoint
# ============================================================================

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint with autonomous repair status."""
    return HealthResponse(
        status="healthy",
        version="2.1.0",
        timestamp=datetime.utcnow().isoformat(),
        features={
            "autonomous_repair": AUTO_REPAIR_ENABLED,
            "validation": True,
            "security_rules": True,
            "scoring": True
        }
    )


# ============================================================================
# Validation Endpoints
# ============================================================================

@router.post("/validate", response_model=CommandResponse)
async def validate_command(request: CommandCandidateRequest):
    """Validate a single NMAP command with detailed scoring."""
    try:
        logger.info(f"Validating command: {request.command}")
        
        # Create CommandCandidate object
        candidate = CommandCandidate(
            command=request.command,
            confidence=request.confidence,
            source_agent=request.source_agent
        )
        
        # Validate the command
        internal_result = validate_nmap_command(
            candidate,
            execute_real=request.execute_real,
            apply_security_rules=True
        )
        
        # Generate JSON score
        scorer = ValidationScorer()
        json_score = scorer.create_json_score(internal_result)
        
        # Return the result
        return CommandResponse(
            success=True,
            data=json_score,
            metadata={
                "validation_time": datetime.now().isoformat(),
                "confidence": request.confidence,
                "source_agent": request.source_agent,
                "auto_validated": internal_result.get("auto_validated", False)
            }
        )
        
    except Exception as e:
        logger.error(f"Validation error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")


@router.post("/validate/legacy", response_model=ValidationResult)
async def validate_command_legacy(request: CommandCandidateRequest):
    """Legacy endpoint: Validate a single NMAP command (simple format)."""
    try:
        logger.info(f"Validating command (legacy): {request.command}")
        
        # Create CommandCandidate object
        candidate = CommandCandidate(
            command=request.command,
            confidence=request.confidence,
            source_agent=request.source_agent
        )
        
        # Validate the command
        internal_result = validate_nmap_command(
            candidate,
            execute_real=request.execute_real,
            apply_security_rules=True
        )
        
        return convert_to_validation_result(internal_result)
        
    except Exception as e:
        logger.error(f"Validation error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")


@router.post("/validate/batch", response_model=BatchValidationResponse)
async def validate_batch(request: BatchValidationRequest):
    """Validate multiple NMAP commands."""
    try:
        # Convert to CommandCandidate objects
        candidates = []
        for cmd_data in request.commands:
            candidate = CommandCandidate(
                command=cmd_data.command,
                confidence=cmd_data.confidence or 0.0,
                source_agent=cmd_data.source_agent or "unknown"
            )
            candidates.append(candidate)
        
        # Validate batch
        results = validate_batch_commands(
            candidates,
            execute_real=False,
            apply_security_rules=True
        )
        
        # Convert results
        validation_results = [convert_to_validation_result(r) for r in results]
        valid_count = sum(1 for r in validation_results if r.valid)
        
        return BatchValidationResponse(
            total=len(validation_results),
            valid=valid_count,
            invalid=len(validation_results) - valid_count,
            results=validation_results
        )
        
    except Exception as e:
        logger.error(f"Batch validation error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Batch validation error: {str(e)}")


@router.get("/security/rules")
async def get_security_rules():
    """Get current security rules configuration."""
    try:
        rules = SecurityRules()
        return {
            "forbidden_flags": rules.FORBIDDEN_FLAGS,
            "warning_flags": rules.WARNING_FLAGS,
            "unsafe_ranges": rules.UNSAFE_RANGES,
            "safe_test_targets": rules.SAFE_TEST_TARGETS
        }
    except Exception as e:
        logger.error(f"Error getting security rules: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Enhanced Repair Endpoint with Autonomous Repair (M5 - Self-Correction)
# ============================================================================

@router.post("/repair", response_model=RepairResponse)
async def repair_command(request: RepairRequest, background_tasks: BackgroundTasks):
    """
    M5: Self-Correction Agent with Autonomous Repair
    """
    if not AUTO_REPAIR_ENABLED:
        raise HTTPException(
            status_code=501,
            detail="Autonomous repair feature not available. SelfCorrectionAgent not found."
        )
    
    logger.info(f"[{request.request_id}] Repair request received")
    
    try:
        # Execute self-correction
        logger.info(f"[{request.request_id}] Starting self-correction")
        
        session = self_correction_agent.correct_command(
            command=request.command,
            intent=request.intent,
            simulate_only=True,
            validation_status=request.validation_status
        )
        
        logger.info(f"[{request.request_id}] Self-correction completed: success={session.success}")
        
        # Build response based on outcome
        if session.success:
            source_agent = "SELF-CORR-AUTO" if session.is_autonomous_repair else "SELF-CORR-ITER"
            repair_type = _get_repair_type(session)
            
            response = RepairResponse(
                request_id=request.request_id,
                success=True,
                original_command=request.command,
                repaired_command=session.final_command,
                source_agent=source_agent,
                is_autonomous_repair=session.is_autonomous_repair,
                attempts=len(session.attempts) if hasattr(session, 'attempts') else 1,
                changes_applied=_extract_all_changes(session),
                feedback_for_m3=None,
                confidence=1.0,
                repair_type=repair_type
            )
            
            logger.info(f"[{request.request_id}] ✅ Repair successful via {source_agent}")
            
            background_tasks.add_task(
                _log_repair_event,
                request.request_id,
                source_agent,
                session.final_command,
                True
            )
            
            return response
        
        else:
            # Repair failed
            feedback = _prepare_m3_feedback(session)
            
            response = RepairResponse(
                request_id=request.request_id,
                success=False,
                original_command=request.command,
                repaired_command=None,
                source_agent="SELF-CORR-FAILED",
                is_autonomous_repair=False,
                attempts=len(session.attempts) if hasattr(session, 'attempts') else 1,
                changes_applied=_extract_all_changes(session),
                feedback_for_m3=feedback,
                confidence=0.0,
                repair_type=None
            )
            
            logger.warning(f"[{request.request_id}] ❌ Repair failed after {len(session.attempts) if hasattr(session, 'attempts') else 1} attempts")
            
            background_tasks.add_task(
                _log_repair_event,
                request.request_id,
                "SELF-CORR-FAILED",
                request.command,
                False
            )
            
            return response
    
    except Exception as e:
        logger.error(f"[{request.request_id}] Repair error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Repair failed: {str(e)}"
        )


# ============================================================================
# Statistics and Monitoring Endpoints
# ============================================================================

@router.get("/stats")
async def get_statistics():
    """Get API statistics."""
    try:
        # Simple statistics for now
        stats = {
            "api_version": "2.1.0",
            "features": {
                "autonomous_repair": AUTO_REPAIR_ENABLED,
                "confidence_based_validation": True,
                "security_rules": True,
                "json_scoring": True
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add repair statistics if available
        if AUTO_REPAIR_ENABLED:
            repair_stats = {
                "total_sessions": len(self_correction_agent.sessions),
                "autonomous_repairs": sum(1 for s in self_correction_agent.sessions if s.is_autonomous_repair),
                "iterative_repairs": sum(
                    1 for s in self_correction_agent.sessions 
                    if not s.is_autonomous_repair and s.success
                ),
                "failed_repairs": sum(1 for s in self_correction_agent.sessions if not s.success)
            }
            stats["repair"] = repair_stats
        
        return stats
        
    except Exception as e:
        logger.warning(f"Error getting statistics: {str(e)}")
        return {
            "error": str(e),
            "message": "Partial statistics available",
            "timestamp": datetime.utcnow().isoformat()
        }


@router.get("/demo")
async def demo_endpoint():
    """Demo endpoint with example commands."""
    examples = [
        {
            "command": "nmap -sV scanme.nmap.org",
            "description": "Safe command with service detection",
            "confidence": 0.95,
            "source_agent": "AI_Agent_v1"
        },
        {
            "command": "nmap -A 192.168.1.1",
            "description": "Aggressive scan on local network (might be blocked)",
            "confidence": 0.85,
            "source_agent": "AI_Agent_v1"
        },
        {
            "command": "nmap --script vuln 10.0.0.1",
            "description": "Vulnerability scan on private IP (will be blocked)",
            "confidence": 0.75,
            "source_agent": "AI_Agent_v1"
        }
    ]
    
    return {
        "examples": examples,
        "endpoints": {
            "validate": "POST /validate - Validate with detailed scoring",
            "validate_legacy": "POST /validate/legacy - Simple validation",
            "validate_batch": "POST /validate/batch - Batch validation",
            "repair": "POST /repair - Autonomous repair",
            "health": "GET /health - Health check",
            "security_rules": "GET /security/rules - Security rules",
            "stats": "GET /stats - Statistics"
        }
    }


# ============================================================================
# Root Endpoint
# ============================================================================

@router.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "NMAP AI Security Validation API",
        "version": "2.1.0",
        "description": "AI-powered NMAP command validation with autonomous repair",
        "author": "NMAP AI Security Team",
        "features": [
            "Command validation with security rules",
            "Confidence-based risk adjustment",
            "Autonomous repair capability",
            "JSON scoring output",
            "Batch processing"
        ],
        "endpoints": {
            "/validate": "POST - Validate command with detailed scoring",
            "/validate/legacy": "POST - Simple validation format",
            "/validate/batch": "POST - Batch validation",
            "/repair": "POST - Autonomous repair",
            "/health": "GET - Health check",
            "/security/rules": "GET - Security rules",
            "/stats": "GET - Statistics",
            "/demo": "GET - Demo examples",
            "/docs": "GET - Interactive API documentation"
        },
        "status": "operational" if AUTO_REPAIR_ENABLED else "limited (no repair)"
    }