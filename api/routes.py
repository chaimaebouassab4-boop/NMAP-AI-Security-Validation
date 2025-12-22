"""
API Routes
==========
FastAPI route handlers that use your existing validation logic.
"""

from fastapi import APIRouter, HTTPException
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
import os

from validation.validation_v2 import ValidationV2
from validation.security_rules import SecurityRules

# Create router
router = APIRouter()

# Initialize validator
validator = ValidationV2()

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
    
    # 🔧 FIX: Get risk_score and risk_level from security analysis
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
@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="2.0.0",
        timestamp=datetime.utcnow().isoformat()
    )

@router.post("/validate", response_model=ValidationResult)
async def validate_command(candidate: CommandCandidate):
    """Validate a single NMAP command."""
    try:
        internal_result = validator.validate_single(
            candidate.command,
            execute=False,
            return_json=False
        )
        return convert_to_validation_result(internal_result)
    except Exception as e:
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


@router.post("/repair", response_model=CommandCandidate)
async def repair_command(query: UserQuery, candidate: CommandCandidate, result: ValidationResult):
    """
    Agent 7: Self-Correction logic.
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
    # Build generation metadata including previous agent and risk level so orchestrator can act
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

@router.get("/stats")
async def get_statistics():
    """Get validation statistics."""
    try:
        return validator.get_statistics()
    except Exception as e:
        return {"error": str(e), "message": "No validation history"}