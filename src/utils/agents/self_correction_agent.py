#!/usr/bin/env python3
"""
Enhanced Self-Correction Agent with Improved Autonomous Repair
===============================================================
Implements robust self-correction with enhanced permission handling,
syntax error correction, and comprehensive logging.
"""

import json
import time
import os
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import our modules
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'utils'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from execution_simulator import ExecutionSimulator
from .error_mapping_logic import ErrorAnalyzer, CorrectionType


class FeedbackType(Enum):
    """Types of feedback to upstream agents"""
    COMPLEXITY_REDUCTION = "complexity_reduction"
    PARAMETER_CHANGE = "parameter_change"
    ALTERNATIVE_APPROACH = "alternative_approach"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TARGET_MODIFICATION = "target_modification"
    COMPLETE_REGENERATION = "complete_regeneration"


class AutonomousRepairType(Enum):
    """Types of autonomous repairs supported"""
    PERMISSION_FIX = "permission_fix"
    SYNTAX_FIX = "syntax_fix"
    SCRIPT_WHITELIST = "script_whitelist"
    TIMING_ADJUSTMENT = "timing_adjustment"
    FLAG_REPLACEMENT = "flag_replacement"
    NO_FIX_AVAILABLE = "no_fix_available"


@dataclass
class CorrectionAttempt:
    """Record of a correction attempt"""
    attempt_number: int
    original_command: str
    corrected_command: str
    errors_before: List[Dict[str, Any]]
    errors_after: Optional[List[Dict[str, Any]]] = None
    success: bool = False
    changes_made: List[str] = field(default_factory=list)
    repair_type: Optional[AutonomousRepairType] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class CorrectionSession:
    """Complete correction session tracking"""
    session_id: str
    original_command: str
    original_intent: str
    attempts: List[CorrectionAttempt] = field(default_factory=list)
    final_command: Optional[str] = None
    success: bool = False
    is_autonomous_repair: bool = False
    feedback_generated: List[Dict[str, Any]] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None


class SelfCorrectionAgent:
    """Enhanced self-correction agent with robust autonomous repair capability"""
    
    # Enhanced fixes mapping with priority ordering
    AUTONOMOUS_FIXES = {
        "permission_denied": {
            "description": "Permission error - switching to non-privileged scan",
            "repair_type": AutonomousRepairType.PERMISSION_FIX,
            "priority": 1,
            "fixes": [
                {
                    "pattern": r"-sS\b",
                    "replacement": "-sT",
                    "reason": "SYN scan requires root - switching to TCP Connect scan"
                },
                {
                    "pattern": r"-sA\b",
                    "replacement": "-sT",
                    "reason": "ACK scan requires root - switching to TCP Connect scan"
                },
                {
                    "pattern": r"-sF\b",
                    "replacement": "-sT",
                    "reason": "FIN scan requires root - switching to TCP Connect scan"
                },
                {
                    "pattern": r"-sX\b",
                    "replacement": "-sT",
                    "reason": "Xmas scan requires root - switching to TCP Connect scan"
                },
                {
                    "pattern": r"-sN\b",
                    "replacement": "-sT",
                    "reason": "NULL scan requires root - switching to TCP Connect scan"
                },
                {
                    "pattern": r"-sO\b",
                    "replacement": "-sT",
                    "reason": "IP protocol scan requires root - switching to TCP Connect scan"
                },
                {
                    "pattern": r"-sW\b",
                    "replacement": "-sT",
                    "reason": "Window scan requires root - switching to TCP Connect scan"
                }
            ]
        },
        "invalid_port_range": {
            "description": "Invalid port range specification",
            "repair_type": AutonomousRepairType.SYNTAX_FIX,
            "priority": 2,
            "fixes": [
                {
                    "pattern": r"-p\s+(\d+)-(\d+)",
                    "check": lambda match: int(match.group(1)) > int(match.group(2)),
                    "replacement_func": lambda match: f"-p {match.group(2)}-{match.group(1)}",
                    "reason": "Reversed port range - correcting to ascending order"
                },
                {
                    "pattern": r"-p\s+(\d+),(\d+)",
                    "check": lambda match: int(match.group(1)) > 65535 or int(match.group(2)) > 65535,
                    "replacement": "-p 1-1000",
                    "reason": "Invalid port numbers - using common port range"
                }
            ]
        },
        "dangerous_script": {
            "description": "Using potentially dangerous NSE scripts",
            "repair_type": AutonomousRepairType.SCRIPT_WHITELIST,
            "priority": 3,
            "dangerous_scripts": ["exploit", "brute-force", "brute", "malware", "dos"],
            "fixes": [
                {
                    "pattern": r"--script\s+[^-\s]+",
                    "replacement": "--script default",
                    "reason": "Replacing unsafe scripts with default safe scripts"
                }
            ]
        },
        "timing_too_aggressive": {
            "description": "Timing template is too aggressive",
            "repair_type": AutonomousRepairType.TIMING_ADJUSTMENT,
            "priority": 4,
            "fixes": [
                {
                    "pattern": r"-T5\b",
                    "replacement": "-T3",
                    "reason": "Reducing timing from insane (T5) to moderate (T3)"
                },
                {
                    "pattern": r"-T4\b",
                    "replacement": "-T3",
                    "reason": "Reducing timing from aggressive (T4) to moderate (T3)"
                }
            ]
        },
        "invalid_flag_combination": {
            "description": "Invalid flag combination detected",
            "repair_type": AutonomousRepairType.FLAG_REPLACEMENT,
            "priority": 2,
            "fixes": [
                {
                    "pattern": r"(-sS|-sF|-sX|-sN)\s+(-sT)",
                    "replacement": "-sT",
                    "reason": "Cannot combine different scan types - using TCP Connect"
                },
                {
                    "pattern": r"-sV\s+-sV",
                    "replacement": "-sV",
                    "reason": "Removing duplicate -sV flag"
                }
            ]
        }
    }
    
    def __init__(self, max_attempts: int = 3):
        self.error_analyzer = ErrorAnalyzer()
        self.execution_simulator = ExecutionSimulator()
        self.max_attempts = max_attempts
        self.sessions: List[CorrectionSession] = []
        logger.info(f"SelfCorrectionAgent initialized with max_attempts={max_attempts}")
        
    def attempt_autonomous_repair(self, command: str, 
                                 error_type: str,
                                 errors: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Enhanced autonomous repair with comprehensive error handling.
        
        Args:
            command: The nmap command to repair
            error_type: Type of error detected
            errors: List of error details
            
        Returns:
            Dict with repaired command and metadata, or None if no fix available
        """
        logger.info(f"🔧 Attempting autonomous repair for error type: {error_type}")
        logger.debug(f"Original command: {command}")
        logger.debug(f"Errors: {errors}")
        
        if error_type not in self.AUTONOMOUS_FIXES:
            logger.warning(f"No autonomous fix available for error type: {error_type}")
            return None
        
        fix_config = self.AUTONOMOUS_FIXES[error_type]
        repaired_command = command
        changes_applied = []
        fixes_attempted = 0
        
        # Attempt each available fix
        for fix in fix_config.get("fixes", []):
            pattern = fix.get("pattern")
            fixes_attempted += 1
            
            logger.debug(f"Attempting fix {fixes_attempted}: pattern='{pattern}'")
            
            # Check if pattern exists in command
            if not re.search(pattern, repaired_command):
                logger.debug(f"Pattern not found in command, skipping")
                continue
            
            # Check if we have a conditional check
            if "check" in fix:
                match = re.search(pattern, repaired_command)
                if not match:
                    logger.debug("Pattern matched but no match object, skipping")
                    continue
                if not fix["check"](match):
                    logger.debug("Conditional check failed, skipping")
                    continue
            
            # Apply replacement
            try:
                if "replacement_func" in fix:
                    repaired_command = re.sub(
                        pattern,
                        lambda m: fix["replacement_func"](m),
                        repaired_command
                    )
                else:
                    replacement = fix.get("replacement", "")
                    repaired_command = re.sub(pattern, replacement, repaired_command)
                
                reason = fix.get("reason", "Applied fix")
                changes_applied.append(reason)
                logger.info(f"✅ Applied fix: {reason}")
                logger.debug(f"Command after fix: {repaired_command}")
                
            except Exception as e:
                logger.error(f"Error applying fix: {str(e)}", exc_info=True)
                continue
        
        # Handle dangerous scripts with explicit check
        if error_type == "dangerous_script":
            dangerous = fix_config.get("dangerous_scripts", [])
            for script in dangerous:
                if script in repaired_command.lower():
                    logger.warning(f"Dangerous script detected: {script}")
                    repaired_command = re.sub(
                        r"--script\s+[^-\s]+",
                        "--script default",
                        repaired_command
                    )
                    changes_applied.append(f"Replaced dangerous script '{script}' with default")
                    logger.info(f"✅ Replaced dangerous script: {script}")
                    break
        
        # Verify command was actually modified
        if repaired_command == command:
            if not changes_applied:
                logger.warning("No changes applied - repair failed")
                return None
            else:
                logger.warning("Changes logged but command unchanged - potential issue")
        
        logger.info(f"✅ Autonomous repair completed: {len(changes_applied)} changes applied")
        
        return {
            "repaired_command": repaired_command,
            "repair_type": fix_config["repair_type"].value,
            "changes": changes_applied,
            "description": fix_config["description"],
            "original_error_type": error_type,
            "fixes_attempted": fixes_attempted
        }
    
    def _detect_permission_issues(self, command: str) -> List[str]:
        """
        Proactively detect flags that require elevated privileges.
        
        Returns:
            List of problematic flags found
        """
        privileged_flags = ["-sS", "-sA", "-sF", "-sX", "-sN", "-sO", "-sW"]
        found_flags = []
        
        for flag in privileged_flags:
            if re.search(rf"{flag}\b", command):
                found_flags.append(flag)
        
        return found_flags
    
    def correct_command(self, command: str, intent: str = "", 
                       simulate_only: bool = True,
                       validation_status: str = "Unknown") -> CorrectionSession:
        """
        Enhanced correction loop with proactive permission handling.
        
        Args:
            command: Nmap command to correct
            intent: Original user intent (for feedback generation)
            simulate_only: If True, simulate execution; if False, real execution
            validation_status: Status from Validation Agent ("Repairable" or "Invalid")
            
        Returns:
            CorrectionSession with all attempts and results
        """
        session = CorrectionSession(
            session_id=f"session_{int(time.time())}_{id(self)}",
            original_command=command,
            original_intent=intent
        )
        
        current_command = command
        
        logger.info("=" * 70)
        logger.info(f"🔬 Starting Self-Correction Session: {session.session_id}")
        logger.info(f"Original Command: {command}")
        logger.info(f"Intent: {intent or 'Not specified'}")
        logger.info(f"Validation Status: {validation_status}")
        logger.info("=" * 70)
        
        # PROACTIVE PERMISSION CHECK
        permission_flags = self._detect_permission_issues(command)
        if permission_flags and validation_status == "Repairable":
            logger.warning(f"⚠️  Detected privileged flags: {permission_flags}")
            logger.info("🔧 Proactively applying permission fixes...")
            
            # Apply permission fixes preemptively
            repair_result = self.attempt_autonomous_repair(
                command, "permission_denied", []
            )
            
            if repair_result:
                current_command = repair_result["repaired_command"]
                logger.info(f"✅ Proactive permission fix applied")
                logger.info(f"Modified command: {current_command}")
        
        # AUTONOMOUS REPAIR ATTEMPT
        if validation_status == "Repairable":
            logger.info("\n🤖 Attempting Autonomous Repair...")
            
            # Execute original/modified command to identify errors
            exec_result = self._execute_command(current_command, simulate_only)
            errors = exec_result.get("errors", [])
            
            if errors:
                logger.warning(f"⚠️  Found {len(errors)} errors to repair")
                
                # Try to repair based on error types (priority ordered)
                sorted_fixes = sorted(
                    self.AUTONOMOUS_FIXES.items(),
                    key=lambda x: x[1].get("priority", 999)
                )
                
                for error in errors:
                    error_type = error.get("type", "")
                    logger.info(f"📋 Processing error: {error_type}")
                    
                    repair_result = self.attempt_autonomous_repair(
                        current_command, error_type, errors
                    )
                    
                    if repair_result:
                        logger.info(f"✅ Autonomous Repair Available for {error_type}!")
                        logger.info(f"Description: {repair_result['description']}")
                        
                        repaired_cmd = repair_result["repaired_command"]
                        
                        # Test the repaired command
                        test_result = self._execute_command(repaired_cmd, simulate_only)
                        
                        # Create attempt record
                        attempt = CorrectionAttempt(
                            attempt_number=1,
                            original_command=command,
                            corrected_command=repaired_cmd,
                            errors_before=errors,
                            errors_after=test_result.get("errors", []),
                            repair_type=AutonomousRepairType[repair_result['repair_type'].upper().replace('-', '_')]
                        )
                        
                        # Check if repair was successful
                        if self._is_successful_execution(test_result):
                            logger.info("✅ Repaired command executed successfully!")
                            attempt.success = True
                            attempt.changes_made = repair_result["changes"]
                            session.success = True
                            session.is_autonomous_repair = True
                            session.final_command = repaired_cmd
                            session.attempts.append(attempt)
                            session.end_time = datetime.utcnow().isoformat()
                            self.sessions.append(session)
                            
                            logger.info(f"🎉 Session completed successfully via autonomous repair")
                            return session
                        else:
                            remaining_errors = len(test_result.get('errors', []))
                            logger.info(f"⚠️  Repair partially successful ({remaining_errors} errors remain)")
                            attempt.changes_made = repair_result["changes"]
                            session.attempts.append(attempt)
                            current_command = repaired_cmd
                            break
                    else:
                        logger.debug(f"No repair available for error: {error_type}")
        
        # ITERATIVE CORRECTION LOOP
        logger.info("\n🔧 Starting Iterative Correction Loop...")
        
        for attempt_num in range(1, self.max_attempts + 1):
            logger.info(f"\n{'='*70}")
            logger.info(f"🔍 Attempt {attempt_num}/{self.max_attempts}")
            logger.info(f"Testing: {current_command}")
            logger.info(f"{'='*70}")
            
            # Create attempt record
            attempt = CorrectionAttempt(
                attempt_number=attempt_num,
                original_command=command if attempt_num == 1 else session.attempts[-1].corrected_command,
                corrected_command=current_command,
                errors_before=[]
            )
            
            # Execute/simulate command
            exec_result = self._execute_command(current_command, simulate_only)
            attempt.errors_before = exec_result.get("errors", [])
            
            logger.info(f"📊 Execution result: {len(attempt.errors_before)} errors found")
            
            # Check if successful
            if self._is_successful_execution(exec_result):
                logger.info("✅ Command executed successfully!")
                attempt.success = True
                session.success = True
                session.final_command = current_command
                session.attempts.append(attempt)
                break
            
            # Log errors
            logger.warning(f"❌ Execution failed with {len(attempt.errors_before)} errors:")
            for i, error in enumerate(attempt.errors_before, 1):
                logger.warning(f"  {i}. {error.get('type', 'unknown')}: {error.get('message', 'No message')}")
            
            # Analyze errors and get corrections
            corrections = self.error_analyzer.analyze_errors(exec_result)
            
            if not corrections:
                logger.error("⚠️  No corrections available from error analyzer")
                logger.error(f"Error details: {attempt.errors_before}")
                session.attempts.append(attempt)
                
                # Generate feedback for upstream
                feedback = self._generate_upstream_feedback(
                    session, exec_result, "no_corrections_available"
                )
                session.feedback_generated.append(feedback)
                logger.info(f"📤 Generated feedback for M3: {feedback['type']}")
                break
            
            # Apply best correction
            best_correction = corrections[0]
            corrected_command = best_correction["correction"]["corrected_command"]
            attempt.corrected_command = corrected_command
            attempt.changes_made = best_correction["correction"]["changes"]
            
            logger.info(f"🔧 Applying correction: {best_correction['explanation']}")
            logger.info(f"Changes: {', '.join(attempt.changes_made)}")
            
            # Test corrected command
            if corrected_command != current_command:
                test_result = self._execute_command(corrected_command, simulate_only)
                attempt.errors_after = test_result.get("errors", [])
                
                errors_after = len(attempt.errors_after)
                errors_before = len(attempt.errors_before)
                
                if self._is_successful_execution(test_result):
                    logger.info("✅ Correction successful!")
                    attempt.success = True
                    session.success = True
                    session.final_command = corrected_command
                    session.attempts.append(attempt)
                    break
                elif errors_after < errors_before:
                    improvement = errors_before - errors_after
                    logger.info(f"📈 Partial improvement: {improvement} fewer errors")
                else:
                    logger.warning(f"📉 Correction didn't improve situation ({errors_after} errors remain)")
            else:
                logger.warning("⚠️  Corrected command is identical to current command")
            
            session.attempts.append(attempt)
            current_command = corrected_command
            
            # Check if approaching max attempts
            if attempt_num == self.max_attempts - 1:
                logger.warning(f"⚠️  Approaching max attempts ({attempt_num + 1}/{self.max_attempts})")
                feedback = self._generate_upstream_feedback(
                    session, exec_result, "max_attempts_approaching"
                )
                session.feedback_generated.append(feedback)
                logger.info(f"📤 Generated feedback for M3: {feedback['type']}")
        
        # Finalize session
        session.end_time = datetime.utcnow().isoformat()
        self.sessions.append(session)
        
        # Generate final feedback if not successful
        if not session.success:
            logger.error("❌ Session failed - generating final feedback")
            final_feedback = self._generate_final_feedback(session)
            session.feedback_generated.append(final_feedback)
            logger.info(f"📤 Final feedback generated: {final_feedback.get('recommended_action')}")
        else:
            logger.info("🎉 Session completed successfully")
        
        logger.info(f"📊 Session summary: {len(session.attempts)} attempts, Success: {session.success}")
        logger.info("=" * 70)
        
        return session
    
    def _execute_command(self, command: str, simulate: bool) -> Dict[str, Any]:
        """Execute or simulate command execution with logging"""
        logger.debug(f"Executing command (simulate={simulate}): {command}")
        
        try:
            result = self.execution_simulator.simulate_execution(command)
            logger.debug(f"Execution completed: {result.get('execution', {}).get('exit_code')}")
            return result
        except Exception as e:
            logger.error(f"Execution error: {str(e)}", exc_info=True)
            return {
                "errors": [{"type": "execution_error", "message": str(e), "severity": "critical"}],
                "execution": {"exit_code": 1, "completed": False}
            }
    
    def _is_successful_execution(self, exec_result: Dict[str, Any]) -> bool:
        """Determine if execution was successful with detailed logging"""
        errors = exec_result.get("errors", [])
        critical_errors = [e for e in errors if e.get("severity") == "critical"]
        exit_code = exec_result.get("execution", {}).get("exit_code")
        completed = exec_result.get("execution", {}).get("completed", False)
        
        logger.debug(f"Success check - Errors: {len(errors)}, Critical: {len(critical_errors)}, "
                    f"Exit code: {exit_code}, Completed: {completed}")
        
        success = (
            len(critical_errors) == 0 and
            exit_code == 0 and
            completed
        )
        
        return success
    
    def _generate_upstream_feedback(self, session: CorrectionSession, 
                                  last_result: Dict[str, Any],
                                  reason: str) -> Dict[str, Any]:
        """Generate feedback for upstream agents (M3) with enhanced logging"""
        logger.info(f"Generating upstream feedback: reason={reason}")
        
        feedback = {
            "type": FeedbackType.COMPLETE_REGENERATION.value,
            "session_id": session.session_id,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(),
            "attempts_made": len(session.attempts),
            "persistent_errors": [],
            "recommendations": [],
            "requires_m3_retry": True
        }
        
        # Analyze persistent errors
        all_errors = []
        for attempt in session.attempts:
            all_errors.extend(attempt.errors_before)
        
        error_types = {}
        for error in all_errors:
            error_type = error.get("type", "unknown")
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        persistent_errors = [
            error_type for error_type, count in error_types.items()
            if count >= len(session.attempts)
        ]
        
        feedback["persistent_errors"] = persistent_errors
        logger.debug(f"Persistent errors identified: {persistent_errors}")
        
        # Generate recommendations based on error patterns
        if "permission_denied" in persistent_errors:
            feedback["type"] = FeedbackType.PRIVILEGE_ESCALATION.value
            feedback["recommendations"].append({
                "action": "avoid_root_requiring_scans",
                "suggestion": "Use TCP connect scan (-sT) instead of privileged scan types",
                "priority": "high"
            })
            logger.info("Recommendation: Avoid root-requiring scans")
        
        if "network_unreachable" in persistent_errors:
            feedback["type"] = FeedbackType.TARGET_MODIFICATION.value
            feedback["recommendations"].append({
                "action": "verify_target_accessibility",
                "suggestion": "Check if target is accessible or use different target",
                "priority": "high"
            })
            logger.info("Recommendation: Verify target accessibility")
        
        if "script_not_found" in persistent_errors:
            feedback["type"] = FeedbackType.ALTERNATIVE_APPROACH.value
            feedback["recommendations"].append({
                "action": "use_basic_scripts",
                "suggestion": "Stick to default or safe script categories",
                "priority": "medium"
            })
            logger.info("Recommendation: Use basic scripts")
        
        if len(session.attempts) >= self.max_attempts:
            feedback["type"] = FeedbackType.COMPLEXITY_REDUCTION.value
            feedback["recommendations"].append({
                "action": "simplify_command",
                "suggestion": "Generate simpler command with fewer options",
                "priority": "high"
            })
            logger.info("Recommendation: Simplify command")
        
        return feedback
    
    def _generate_final_feedback(self, session: CorrectionSession) -> Dict[str, Any]:
        """Generate final feedback summary with logging"""
        logger.info("Generating final feedback summary")
        
        feedback = {
            "type": "final_summary",
            "session_id": session.session_id,
            "success": session.success,
            "total_attempts": len(session.attempts),
            "is_autonomous_repair": session.is_autonomous_repair,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if session.success:
            feedback["final_command"] = session.final_command
            feedback["corrections_applied"] = []
            feedback["source_agent"] = "SELF-CORR-AUTO" if session.is_autonomous_repair else "SELF-CORR-ITER"
            
            for attempt in session.attempts:
                if attempt.changes_made:
                    feedback["corrections_applied"].extend(attempt.changes_made)
            
            logger.info(f"Success feedback: {len(feedback['corrections_applied'])} corrections applied")
        else:
            feedback["failure_analysis"] = {
                "persistent_issues": self._analyze_persistent_issues(session),
                "recommended_action": self._recommend_final_action(session)
            }
            feedback["requires_m3_retry"] = True
            logger.warning(f"Failure feedback: {feedback['failure_analysis']['recommended_action']}")
        
        return feedback
    
    def _analyze_persistent_issues(self, session: CorrectionSession) -> List[str]:
        """Analyze issues that couldn't be resolved"""
        issues = []
        
        if session.attempts:
            last_attempt = session.attempts[-1]
            last_errors = last_attempt.errors_after or last_attempt.errors_before
            
            for error in last_errors:
                issues.append(f"{error['type']}: {error.get('message', 'No details')}")
            
            logger.debug(f"Persistent issues: {issues}")
        
        return issues
    
    def _recommend_final_action(self, session: CorrectionSession) -> str:
        """Recommend final action when correction fails"""
        if not session.attempts:
            return "No attempts made - check initial command validity"
        
        error_types = set()
        for attempt in session.attempts:
            for error in attempt.errors_before:
                error_types.add(error.get("type"))
        
        logger.debug(f"Error types for recommendation: {error_types}")
        
        if "permission_denied" in error_types:
            return "Request elevated privileges or use alternative scan methods"
        elif "network_unreachable" in error_types:
            return "Verify network connectivity and target accessibility"
        elif "syntax_error" in error_types:
            return "Regenerate command with correct syntax"
        else:
            return "Consider simplifying requirements or using alternative approach"
    
    def generate_report(self, session: CorrectionSession) -> Dict[str, Any]:
        """Generate comprehensive correction report"""
        report = {
            "session_summary": {
                "session_id": session.session_id,
                "success": session.success,
                "is_autonomous_repair": session.is_autonomous_repair,
                "original_command": session.original_command,
                "final_command": session.final_command,
                "total_attempts": len(session.attempts),
                "source_agent": "SELF-CORR-AUTO" if session.is_autonomous_repair else "SELF-CORR-ITER",
                "duration": self._calculate_duration(session.start_time, session.end_time)
            },
            "attempts_detail": [],
            "feedback_generated": session.feedback_generated,
            "improvements": {
                "errors_fixed": 0,
                "errors_remaining": 0,
                "success_rate": 0.0
            }
        }
        
        for attempt in session.attempts:
            report["attempts_detail"].append({
                "attempt": attempt.attempt_number,
                "command": attempt.corrected_command,
                "changes": attempt.changes_made,
                "repair_type": attempt.repair_type.value if attempt.repair_type else None,
                "errors_before": len(attempt.errors_before),
                "errors_after": len(attempt.errors_after) if attempt.errors_after else None,
                "success": attempt.success,
                "timestamp": attempt.timestamp
            })
            if attempt.success:
                report["improvements"]["errors_fixed"] += len(attempt.errors_before)
            else:
                if attempt.errors_after:
                    report["improvements"]["errors_remaining"] += len(attempt.errors_after)
                else:
                    report["improvements"]["errors_remaining"] += len(attempt.errors_before)

                    