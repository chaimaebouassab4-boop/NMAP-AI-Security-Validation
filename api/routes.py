"""
API Routes with Autonomous Repair Support
==========================================
FastAPI route handlers with autonomous repair capability for M5 (Self-Correction Agent).
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from .models import (
    CommandCandidate, 
    ValidationResult, 
    UserQuery,
    ValidationIssue,
    BatchValidationRequest, 
    BatchValidationResponse,
    HealthResponse
)
from datetime import datetime
from typing import Optional, List, Dict, Any
import os
import logging

from validation.validation_v2 import ValidationV2
from validation.security_rules import SecurityRules
from src.utils.agents.self_correction_agent import SelfCorrectionAgent
logger = logging.getLogger(__name__)

# ============================================================================
# NEW: Enhanced Models for Autonomous Repair
# ============================================================================

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


# ============================================================================
# Router Setup
# ============================================================================

router = APIRouter()

# Initialize validator
validator = ValidationV2()

# Initialize self-correction agent
self_correction_agent = SelfCorrectionAgent(max_attempts=3)


# ============================================================================
# Conversion and Helper Functions
# ============================================================================

def convert_to_validation_result(internal_result: dict) -> ValidationResult:
    """Convert your internal validation result to API format."""
    
    issues = []
    if internal_result.get('blocked_by_security') and 'security_issues' in internal_result:
        for issue_text in internal_result['security_issues']:
            if "Forbidden flag" in issue_text:
                issue_type = "forbidden_flag"
                severity = "critical"
            elif "Unsafe target" in issue_text:
                issue_type = "unsafe_target"
                severity = "high"
            else:
                issue_type = "validation_error"
                severity = internal_result.get('severity', 'medium')
            
            issues.append(ValidationIssue(
                type=issue_type,
                severity=severity,
                message=issue_text,
                suggestion=None
            ))
    
    if not internal_result.get('valid') and not internal_result.get('blocked_by_security'):
        issues.append(ValidationIssue(
            type="syntax_error",
            severity=internal_result.get('severity', 'high'),
            message=internal_result.get('error', 'Unknown validation error'),
            suggestion="Check command syntax"
        ))
    
    status = "valid" if internal_result.get('valid') else "invalid"
    if internal_result.get('valid') and internal_result.get('risk_level') in ['high', 'critical']:
        status = "warning"
    
    warnings = []
    if internal_result.get('warnings'):
        warnings = internal_result['warnings'] if isinstance(internal_result['warnings'], list) else [internal_result['warnings']]
    
    # Get risk_score and risk_level from security analysis
    risk_score = 0
    risk_level = "unknown"
    recommendation = "No recommendation"
    
    if 'security' in internal_result:
        risk_score = internal_result['security'].get('risk_score', 0)
        risk_level = internal_result['security'].get('risk_level', 'unknown')
        recommendation = internal_result['security'].get('recommendation', 'No recommendation')
    elif internal_result.get('risk_score') is not None:
        risk_score = internal_result.get('risk_score', 0)
        risk_level = internal_result.get('risk_level', 'unknown')
        recommendation = internal_result.get('recommendation', 'No recommendation')
    
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
    for attempt in session.attempts:
        changes.extend(attempt.changes_made)
    return changes


def _prepare_m3_feedback(session) -> Optional[Dict[str, Any]]:
    """Prepare feedback for M3 when repair fails"""
    if not session.feedback_generated:
        return None
    
    feedback = session.feedback_generated[-1]
    return {
        "type": feedback.get("type"),
        "reason": feedback.get("reason"),
        "requires_m3_retry": True,
        "recommendations": feedback.get("recommendations", []),
        "persistent_errors": feedback.get("persistent_errors", []),
        "attempts_made": len(session.attempts)
    }


def _get_repair_type(session) -> Optional[str]:
    """Extract repair type from session if autonomous"""
    if session.attempts and session.attempts[0].repair_type:
        return session.attempts[0].repair_type.value
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
        version="2.1.0",  # Updated version with autonomous repair
        timestamp=datetime.utcnow().isoformat()
    )


# ============================================================================
# Validation Endpoints (Unchanged)
# ============================================================================

@router.post("/validate", response_model=ValidationResult)
async def validate_command(candidate: CommandCandidate):
    """Validate a single NMAP command (M4 - Validation Agent)."""
    try:
        internal_result = validator.validate_single(
            candidate.command,
            execute=False,
            return_json=False
        )
        return convert_to_validation_result(internal_result)
    except Exception as e:
        logger.error(f"Validation error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")


@router.post("/validate/batch", response_model=BatchValidationResponse)
async def validate_batch(request: BatchValidationRequest):
    """Validate multiple NMAP commands."""
    try:
        internal_results = validator.validate_multiple(
            request.commands,
            execute=False,
            return_json=False
        )
        
        results = [convert_to_validation_result(r) for r in internal_results['results']]
        valid_count = sum(1 for r in results if r.valid)
        
        return BatchValidationResponse(
            total=len(results),
            valid=valid_count,
            invalid=len(results) - valid_count,
            results=results
        )
    except Exception as e:
        logger.error(f"Batch validation error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Batch validation error: {str(e)}")


@router.get("/security/rules")
async def get_security_rules():
    """Get current security rules configuration."""
    rules = SecurityRules()
    return {    
        "forbidden_flags": rules.FORBIDDEN_FLAGS,
        "warning_flags": rules.WARNING_FLAGS,
        "unsafe_ranges": rules.UNSAFE_RANGES,
        "safe_test_targets": rules.SAFE_TEST_TARGETS
    }


# ============================================================================
# NEW: Enhanced Repair Endpoint with Autonomous Repair (M5 - Self-Correction)
# ============================================================================

@router.post("/repair", response_model=RepairResponse)
async def repair_command(request: RepairRequest, background_tasks: BackgroundTasks):
    """
    M5: Self-Correction Agent with Autonomous Repair
    
    Intelligently repairs commands based on validation feedback:
    1. If status is "Repairable": Attempts autonomous repair first
    2. If autonomous repair succeeds: Returns immediately (source_agent=SELF-CORR-AUTO)
    3. If autonomous repair fails or status is "Invalid": Uses iterative correction
    4. If iterative fails: Generates feedback for M3 (Generative Agent) to regenerate
    
    Args:
        request: RepairRequest with command and validation context
        background_tasks: For async logging
        
    Returns:
        RepairResponse with repair results and routing information
    """
    
    logger.info(f"[{request.request_id}] Repair request received")
    logger.debug(f"[{request.request_id}] Command: {request.command}")
    logger.debug(f"[{request.request_id}] Validation Status: {request.validation_status}")
    
    try:
        # Convert validation issues to error format for self-correction agent
        errors = []
        if request.issues:
            for issue in request.issues:
                if isinstance(issue, dict):
                    errors.append(issue)
                else:
                    errors.append({
                        "type": issue.type if hasattr(issue, 'type') else "unknown",
                        "message": issue.message if hasattr(issue, 'message') else str(issue),
                        "severity": issue.severity if hasattr(issue, 'severity') else "medium"
                    })
        
        # Execute self-correction (attempts autonomous repair first, then iterative)
        logger.info(f"[{request.request_id}] Starting self-correction with status: {request.validation_status}")
        
        session = self_correction_agent.correct_command(
            command=request.command,
            intent=request.intent,
            simulate_only=True,
            validation_status=request.validation_status
        )
        
        logger.info(f"[{request.request_id}] Self-correction completed: success={session.success}")
        
             # ====================================================================
        # Build Response Based on Repair Outcome
        # ====================================================================
        
        if session.success:
            # Repair succeeded (either autonomous or iterative)
            source_agent = "SELF-CORR-AUTO" if session.is_autonomous_repair else "SELF-CORR-ITER"
            repair_type = _get_repair_type(session)
            
            response = RepairResponse(
                request_id=request.request_id,
                success=True,
                original_command=request.command,
                repaired_command=session.final_command,
                source_agent=source_agent,
                is_autonomous_repair=session.is_autonomous_repair,
                attempts=len(session.attempts),
                changes_applied=_extract_all_changes(session),
                feedback_for_m3=None,  # No feedback needed if successful
                confidence=1.0,
                repair_type=repair_type
            )
            
            logger.info(f"[{request.request_id}] ✅ Repair successful via {source_agent}")
            logger.debug(f"[{request.request_id}] Repaired command: {session.final_command}")
            
            # Log asynchronously (don't block response)
            background_tasks.add_task(
                _log_repair_event,
                request.request_id,
                source_agent,
                session.final_command,
                True
            )
            
            return response
        
        else:
            # Repair failed - generate feedback for M3
            feedback = _prepare_m3_feedback(session)
            
            response = RepairResponse(
                request_id=request.request_id,
                success=False,
                original_command=request.command,
                repaired_command=None,
                source_agent="SELF-CORR-FAILED",
                is_autonomous_repair=False,
                attempts=len(session.attempts),
                changes_applied=_extract_all_changes(session),
                feedback_for_m3=feedback,
                confidence=0.0,
                repair_type=None
            )
            
            logger.warning(f"[{request.request_id}] ❌ Repair failed after {len(session.attempts)} attempts")
            logger.warning(f"[{request.request_id}] Feedback for M3: {feedback.get('reason') if feedback else 'None'}")
            
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
# ORIGINAL: Repair Endpoint for Backward Compatibility
# ============================================================================

@router.post("/repair-legacy", response_model=CommandCandidate)
async def repair_command_legacy(query: UserQuery, candidate: CommandCandidate, result: ValidationResult):
    """
    DEPRECATED: Original repair logic for backward compatibility.
    New code should use /repair endpoint instead.
    
    Agent 7: Self-Correction logic (Legacy version).
    Refines the command based on validation issues found in Step 4.
    """
    # Build a plain text view of issues
    issue_text = " ".join([i.message for i in result.issues]) if result.issues else ""
    new_command = candidate.command or ""

    # Heuristic complexity scoring
    tokens = new_command.split()
    num_flags = sum(1 for t in tokens if t.startswith('-') and len(t) > 1)
    has_pipes = '|' in new_command or ';' in new_command
    long_command = len(tokens) > 10
    complexity_score = num_flags + (2 if has_pipes else 0) + (1 if long_command else 0)

    # Self-correction: Permission Error => switch scan type
    if "Permission Error" in issue_text or "-sS" in new_command:
        new_command = new_command.replace("-sS", "-sT")
        repair_rationale = "Privilege issue detected. Switched to TCP Connect scan (-sT)."
    else:
        repair_rationale = f"Refined command to address: {issue_text or 'no specific issues'}"

    # Decide whether to ask generator (M1/M3) to change strategy
    suggested_generation = None
    prev_agent = None
    if candidate.context and isinstance(candidate.context, dict) and "previous_agent" in candidate.context:
        prev_agent = candidate.context.get("previous_agent")
    elif query and getattr(query, "metadata", None) and isinstance(query.metadata, dict) and "previous_agent" in query.metadata:
        prev_agent = query.metadata.get("previous_agent")
    else:
        prev_agent = "DIFFUSION"

    generation_metadata = {
        "complexity_score": complexity_score,
        "reason": None,
        "previous_agent": prev_agent,
        "risk_level": getattr(result, "risk_level", "unknown")
    }

    # If complexity or high risk, suggest simpler, more deterministic generator (SLM)
    if complexity_score >= 5 or getattr(result, "risk_level", None) in ["high", "critical"]:
        suggested_generation = "SLM"
        generation_metadata["reason"] = "High complexity or risk; prefer simpler, more deterministic generation."
    else:
        suggested_generation = "Diffusion"
        generation_metadata["reason"] = "Command repair straightforward; keep high-capacity generation."

    return CommandCandidate(
        command=new_command,
        rationale=repair_rationale,
        source_agent="SELF-CORR",
        user_id=candidate.user_id,
        context=candidate.context,
        suggested_generation=suggested_generation,
        generation_metadata=generation_metadata
    )


# ============================================================================
# Session and Monitoring Endpoints
# ============================================================================

@router.get("/repair/session/{session_id}")
async def get_repair_session(session_id: str):
    """Retrieve a self-correction session report for debugging."""
    try:
        for session in self_correction_agent.sessions:
            if session.session_id == session_id:
                report = self_correction_agent.generate_report(session)
                return report
        
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving session {session_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_statistics():
    """Get validation and repair statistics."""
    try:
        validation_stats = validator.get_statistics()
        
        # Add repair statistics
        repair_stats = {
            "total_sessions": len(self_correction_agent.sessions),
            "autonomous_repairs": sum(1 for s in self_correction_agent.sessions if s.is_autonomous_repair),
            "iterative_repairs": sum(
                1 for s in self_correction_agent.sessions 
                if not s.is_autonomous_repair and s.success
            ),
            "failed_repairs": sum(1 for s in self_correction_agent.sessions if not s.success)
        }
        
        # Calculate success rates
        total_repairs = repair_stats["autonomous_repairs"] + repair_stats["iterative_repairs"] + repair_stats["failed_repairs"]
        if total_repairs > 0:
            repair_stats["success_rate"] = (
                (repair_stats["autonomous_repairs"] + repair_stats["iterative_repairs"]) / total_repairs
            )
            repair_stats["autonomous_rate"] = repair_stats["autonomous_repairs"] / total_repairs
        else:
            repair_stats["success_rate"] = 0.0
            repair_stats["autonomous_rate"] = 0.0
        
        return {
            "validation": validation_stats,
            "repair": repair_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.warning(f"Error getting statistics: {str(e)}")
        return {
            "error": str(e),
            "message": "Partial statistics available",
            "timestamp": datetime.utcnow().isoformat()
        }


# ============================================================================
# Debugging and Admin Endpoints
# ============================================================================

@router.get("/repair/autonomous-fixes")
async def get_autonomous_fixes():
    """
    Get list of supported autonomous repair types.
    Useful for debugging and understanding what errors can be fixed automatically.
    """
    fixes_info = {}
    
    for error_type, fix_config in self_correction_agent.AUTONOMOUS_FIXES.items():
        fixes_info[error_type] = {
            "description": fix_config.get("description"),
            "repair_type": fix_config.get("repair_type").value if fix_config.get("repair_type") else None,
            "example": f"Error type '{error_type}' can be autonomously repaired"
        }
    
    return {
        "total_autonomous_fix_types": len(fixes_info),
        "fixes": fixes_info,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/repair/recent-sessions/{limit}")
async def get_recent_sessions(limit: int = 10):
    """Get recent self-correction sessions for monitoring."""
    try:
        recent = self_correction_agent.sessions[-limit:] if limit > 0 else self_correction_agent.sessions
        
        return {
            "total_sessions": len(self_correction_agent.sessions),
            "returned": len(recent),
            "sessions": [
                {
                    "session_id": s.session_id,
                    "success": s.success,
                    "is_autonomous": s.is_autonomous_repair,
                    "attempts": len(s.attempts),
                    "original_command": s.original_command,
                    "final_command": s.final_command,
                    "start_time": s.start_time,
                    "end_time": s.end_time
                }
                for s in recent
            ]
        }
    except Exception as e:
        logger.error(f"Error retrieving recent sessions: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))