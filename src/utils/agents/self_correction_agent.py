#!/usr/bin/env python3
"""
Self-Correction Agent with Autonomous Repair
==============================================
Implements self-correction loop with autonomous repair for known issues.
"""

import json
import time
import os
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

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
    PERMISSION_FIX = "permission_fix"           # -sS -> -sT
    SYNTAX_FIX = "syntax_fix"                   # Port range correction
    SCRIPT_WHITELIST = "script_whitelist"       # Replace dangerous scripts
    TIMING_ADJUSTMENT = "timing_adjustment"     # Reduce aggressive timing
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
    """Main self-correction agent with autonomous repair capability"""
    
    # Known fixes mapping for autonomous repair
    AUTONOMOUS_FIXES = {
        "permission_denied": {
            "description": "Permission error - switching to TCP Connect scan",
            "repair_type": AutonomousRepairType.PERMISSION_FIX,
            "fixes": [
                {
                    "pattern": r"-sS",  # SYN scan requires root
                    "replacement": "-sT",  # Use TCP Connect scan instead
                    "reason": "TCP Connect scan (-sT) doesn't require root privileges"
                },
                {
                    "pattern": r"-sA",  # ACK scan requires root
                    "replacement": "-sT",
                    "reason": "TCP Connect scan (-sT) is safer alternative"
                }
            ]
        },
        "invalid_port_range": {
            "description": "Invalid port range specification",
            "repair_type": AutonomousRepairType.SYNTAX_FIX,
            "fixes": [
                {
                    "pattern": r"-p\s+(\d+)-(\d+)",  # Match port range
                    "check": lambda match: int(match.group(1)) > int(match.group(2)),
                    "replacement_func": lambda match: f"-p {match.group(2)}-{match.group(1)}",
                    "reason": "Reversed port range - correcting to ascending order"
                }
            ]
        },
        "dangerous_script": {
            "description": "Using potentially dangerous NSE scripts",
            "repair_type": AutonomousRepairType.SCRIPT_WHITELIST,
            "dangerous_scripts": ["exploit", "brute-force", "malware"],
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
            "fixes": [
                {
                    "pattern": r"-T[45]",  # T4 or T5
                    "replacement": "-T3",  # Moderate timing
                    "reason": "Reducing timing from aggressive to moderate"
                }
            ]
        }
    }
    
    def __init__(self, max_attempts: int = 3):
        self.error_analyzer = ErrorAnalyzer()
        self.execution_simulator = ExecutionSimulator()
        self.max_attempts = max_attempts
        self.sessions: List[CorrectionSession] = []
        
    def attempt_autonomous_repair(self, command: str, 
                                 error_type: str,
                                 errors: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Attempt autonomous repair based on known error types.
        
        Args:
            command: The nmap command to repair
            error_type: Type of error detected
            errors: List of error details
            
        Returns:
            Dict with repaired command and metadata, or None if no fix available
        """
        import re
        
        if error_type not in self.AUTONOMOUS_FIXES:
            return None
        
        fix_config = self.AUTONOMOUS_FIXES[error_type]
        repaired_command = command
        changes_applied = []
        
        # Attempt each available fix
        for fix in fix_config.get("fixes", []):
            pattern = fix.get("pattern")
            
            # Check if we have a conditional check
            if "check" in fix:
                match = re.search(pattern, repaired_command)
                if not match or not fix["check"](match):
                    continue
            
            # Apply replacement
            if "replacement_func" in fix:
                repaired_command = re.sub(
                    pattern,
                    lambda m: fix["replacement_func"](m),
                    repaired_command
                )
            else:
                replacement = fix.get("replacement", "")
                if re.search(pattern, repaired_command):
                    repaired_command = re.sub(pattern, replacement, repaired_command)
            
            changes_applied.append(fix.get("reason", "Applied fix"))
        
        # Check for dangerous scripts
        if error_type == "dangerous_script":
            dangerous = fix_config.get("dangerous_scripts", [])
            for script in dangerous:
                if script in repaired_command:
                    repaired_command = re.sub(
                        r"--script\s+[^-\s]+",
                        "--script default",
                        repaired_command
                    )
                    changes_applied.append("Replaced dangerous script with default")
                    break
        
        # Verify command was actually modified
        if repaired_command == command and not changes_applied:
            return None
        
        return {
            "repaired_command": repaired_command,
            "repair_type": fix_config["repair_type"].value,
            "changes": changes_applied,
            "description": fix_config["description"],
            "original_error_type": error_type
        }
    
    def correct_command(self, command: str, intent: str = "", 
                       simulate_only: bool = True,
                       validation_status: str = "Unknown") -> CorrectionSession:
        """
        Main correction loop with autonomous repair capability.
        
        Args:
            command: Nmap command to correct
            intent: Original user intent (for feedback generation)
            simulate_only: If True, simulate execution; if False, real execution
            validation_status: Status from Validation Agent ("Repairable" or "Invalid")
            
        Returns:
            CorrectionSession with all attempts and results
        """
        session = CorrectionSession(
            session_id=f"session_{int(time.time())}",
            original_command=command,
            original_intent=intent
        )
        
        current_command = command
        
        print(f"\n🔬 Starting Self-Correction Session: {session.session_id}")
        print(f"Original Command: {command}")
        print(f"Intent: {intent or 'Not specified'}")
        print(f"Validation Status: {validation_status}")
        print("=" * 60)
        
        # AUTONOMOUS REPAIR ATTEMPT (First priority)
        if validation_status == "Repairable":
            print("\n🤖 Attempting Autonomous Repair...")
            
            # Execute original command to identify errors
            exec_result = self._execute_command(command, simulate_only)
            errors = exec_result.get("errors", [])
            
            if errors:
                # Try to repair based on the first error type
                error_type = errors[0].get("type", "")
                repair_result = self.attempt_autonomous_repair(
                    command, error_type, errors
                )
                
                if repair_result:
                    print(f"✅ Autonomous Repair Available!")
                    print(f"Description: {repair_result['description']}")
                    
                    repaired_cmd = repair_result["repaired_command"]
                    
                    # Test the repaired command
                    test_result = self._execute_command(repaired_cmd, simulate_only)
                    
                    # Create attempt record with errors_before
                    attempt = CorrectionAttempt(
                        attempt_number=1,
                        original_command=command,
                        corrected_command=repaired_cmd,
                        errors_before=errors
                    )
                    
                    # Check if repair was successful
                    if self._is_successful_execution(test_result):
                        print("✅ Repaired command executed successfully!")
                        attempt.success = True
                        session.success = True
                        session.is_autonomous_repair = True
                        session.final_command = repaired_cmd
                        session.attempts.append(attempt)
                        session.end_time = datetime.utcnow().isoformat()
                        self.sessions.append(session)
                        return session
                    else:
                        # Repair improved but didn't fully fix - proceed to full correction
                        print(f"⚠️  Repair partially successful ({len(test_result.get('errors', []))} errors remain)")
                        session.attempts.append(attempt)
                        current_command = repaired_cmd
        
        # ITERATIVE CORRECTION (Standard flow if autonomous repair fails)
        print("\n🔧 Starting Iterative Correction Loop...")
        
        for attempt_num in range(1, self.max_attempts + 1):
            print(f"\n🔍 Attempt {attempt_num}/{self.max_attempts}")
            print(f"Testing: {current_command}")
            
            # Create attempt record with errors_before vide au départ
            attempt = CorrectionAttempt(
                attempt_number=attempt_num,
                original_command=command if attempt_num == 1 else session.attempts[-1].corrected_command,
                corrected_command=current_command,
                errors_before=[]
            )
            
            # Execute/simulate command
            exec_result = self._execute_command(current_command, simulate_only)
            attempt.errors_before = exec_result.get("errors", [])
            
            # Check if successful
            if self._is_successful_execution(exec_result):
                print("✅ Command executed successfully!")
                attempt.success = True
                session.success = True
                session.final_command = current_command
                session.attempts.append(attempt)
                break
            
            # Analyze errors and get corrections
            print(f"❌ Execution failed with {len(attempt.errors_before)} errors")
            corrections = self.error_analyzer.analyze_errors(exec_result)
            
            if not corrections:
                print("⚠️  No corrections available")
                session.attempts.append(attempt)
                
                # Generate feedback for upstream
                feedback = self._generate_upstream_feedback(
                    session, exec_result, "no_corrections_available"
                )
                session.feedback_generated.append(feedback)
                break
            
            # Apply best correction
            best_correction = corrections[0]
            corrected_command = best_correction["correction"]["corrected_command"]
            attempt.corrected_command = corrected_command
            attempt.changes_made = best_correction["correction"]["changes"]
            
            print(f"🔧 Applying correction: {best_correction['explanation']}")
            print(f"Changes: {', '.join(attempt.changes_made)}")
            
            # Test corrected command
            if corrected_command != current_command:
                test_result = self._execute_command(corrected_command, simulate_only)
                attempt.errors_after = test_result.get("errors", [])
                
                if self._is_successful_execution(test_result):
                    print("✅ Correction successful!")
                    attempt.success = True
                    session.success = True
                    session.final_command = corrected_command
                    session.attempts.append(attempt)
                    break
                elif len(test_result.get("errors", [])) < len(attempt.errors_before):
                    print("📈 Partial improvement achieved")
                else:
                    print("📉 Correction didn't improve situation")
            
            session.attempts.append(attempt)
            current_command = corrected_command
            
            # Check if we need different approach
            if attempt_num == self.max_attempts - 1:
                # Generate feedback for more significant changes
                feedback = self._generate_upstream_feedback(
                    session, exec_result, "max_attempts_approaching"
                )
                session.feedback_generated.append(feedback)
        
        # Finalize session
        session.end_time = datetime.utcnow().isoformat()
        self.sessions.append(session)
        
        # Generate final feedback if not successful
        if not session.success:
            final_feedback = self._generate_final_feedback(session)
            session.feedback_generated.append(final_feedback)
        
        return session
    
    def _execute_command(self, command: str, simulate: bool) -> Dict[str, Any]:
        """Execute or simulate command execution"""
        if simulate:
            return self.execution_simulator.simulate_execution(command)
        else:
            return self.execution_simulator.simulate_execution(command)
    
    def _is_successful_execution(self, exec_result: Dict[str, Any]) -> bool:
        """Determine if execution was successful"""
        errors = exec_result.get("errors", [])
        critical_errors = [e for e in errors if e.get("severity") == "critical"]
        
        # Debug: Print what we got
        print(f"\n[DEBUG] exec_result structure: {exec_result}")
        print(f"[DEBUG] errors: {errors}")
        print(f"[DEBUG] critical_errors: {critical_errors}")
        print(f"[DEBUG] execution block: {exec_result.get('execution', {})}")
        print(f"[DEBUG] exit_code: {exec_result.get('execution', {}).get('exit_code')}")
        print(f"[DEBUG] completed: {exec_result.get('execution', {}).get('completed')}")
        
        success = (
            len(critical_errors) == 0 and
            exec_result.get("execution", {}).get("exit_code") == 0 and
            exec_result.get("execution", {}).get("completed", False)
        )
        
        print(f"[DEBUG] Success result: {success}\n")
        return success
    
    def _generate_upstream_feedback(self, session: CorrectionSession, 
                                  last_result: Dict[str, Any],
                                  reason: str) -> Dict[str, Any]:
        """Generate feedback for upstream agents (M3)"""
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
        
        # Generate recommendations
        if "permission_denied" in persistent_errors:
            feedback["type"] = FeedbackType.PRIVILEGE_ESCALATION.value
            feedback["recommendations"].append({
                "action": "avoid_root_requiring_scans",
                "suggestion": "Use TCP connect scan (-sT) instead of SYN scan",
                "priority": "high"
            })
        
        if "network_unreachable" in persistent_errors:
            feedback["type"] = FeedbackType.TARGET_MODIFICATION.value
            feedback["recommendations"].append({
                "action": "verify_target_accessibility",
                "suggestion": "Check if target is accessible or use different target",
                "priority": "high"
            })
        
        if "script_not_found" in persistent_errors:
            feedback["type"] = FeedbackType.ALTERNATIVE_APPROACH.value
            feedback["recommendations"].append({
                "action": "use_basic_scripts",
                "suggestion": "Stick to default or safe script categories",
                "priority": "medium"
            })
        
        if len(session.attempts) >= self.max_attempts:
            feedback["type"] = FeedbackType.COMPLEXITY_REDUCTION.value
            feedback["recommendations"].append({
                "action": "simplify_command",
                "suggestion": "Generate simpler command with fewer options",
                "priority": "high"
            })
        
        return feedback
    
    def _generate_final_feedback(self, session: CorrectionSession) -> Dict[str, Any]:
        """Generate final feedback summary"""
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
        else:
            feedback["failure_analysis"] = {
                "persistent_issues": self._analyze_persistent_issues(session),
                "recommended_action": self._recommend_final_action(session)
            }
            feedback["requires_m3_retry"] = True
        
        return feedback
    
    def _analyze_persistent_issues(self, session: CorrectionSession) -> List[str]:
        """Analyze issues that couldn't be resolved"""
        issues = []
        
        if session.attempts:
            last_attempt = session.attempts[-1]
            last_errors = last_attempt.errors_after or last_attempt.errors_before
            
            for error in last_errors:
                issues.append(f"{error['type']}: {error.get('message', 'No details')}")
        
        return issues
    
    def _recommend_final_action(self, session: CorrectionSession) -> str:
        """Recommend final action when correction fails"""
        if not session.attempts:
            return "No attempts made - check initial command validity"
        
        error_types = set()
        for attempt in session.attempts:
            for error in attempt.errors_before:
                error_types.add(error.get("type"))
        
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
                "errors_after": len(attempt.errors_after) if attempt.errors_after else 0,
                "success": attempt.success
            })
        
        if session.attempts:
            first_errors = len(session.attempts[0].errors_before)
            
            if session.success:
                report["improvements"]["errors_fixed"] = first_errors
                report["improvements"]["success_rate"] = 1.0
            else:
                last_attempt = session.attempts[-1]
                last_errors = len(last_attempt.errors_after or last_attempt.errors_before)
                report["improvements"]["errors_fixed"] = max(0, first_errors - last_errors)
                report["improvements"]["errors_remaining"] = last_errors
                report["improvements"]["success_rate"] = (
                    report["improvements"]["errors_fixed"] / first_errors 
                    if first_errors > 0 else 0.0
                )
        
        return report
    
    def _calculate_duration(self, start: str, end: Optional[str]) -> float:
        """Calculate session duration in seconds"""
        if not end:
            end = datetime.utcnow().isoformat()
        
        start_time = datetime.fromisoformat(start.replace('Z', '+00:00'))
        end_time = datetime.fromisoformat(end.replace('Z', '+00:00'))
        
        return (end_time - start_time).total_seconds()


def demo_self_correction():
    """Demonstrate self-correction agent with autonomous repair"""
    agent = SelfCorrectionAgent(max_attempts=3)
    
    test_cases = [
        {
            "command": "nmap -sS -p 80 scanme.nmap.org",
            "intent": "Perform stealth scan on port 80",
            "validation_status": "Repairable",
            "description": "Permission error - autonomous repair should switch to -sT"
        },
        {
            "command": "nmap -p 80-70 --script default target.com",
            "intent": "Scan ports and run basic scripts",
            "validation_status": "Repairable",
            "description": "Port range reversal - autonomous repair should fix"
        },
        {
            "command": "nmap -T5 -p- -A 192.168.1.1",
            "intent": "Comprehensive scan with aggressive timing",
            "validation_status": "Invalid",
            "description": "Complex issues - should fall back to iterative correction"
        }
    ]
    
    print("🤖 Self-Correction Agent with Autonomous Repair Demo")
    print("=" * 70)
    
    all_reports = []
    
    for i, test in enumerate(test_cases):
        print(f"\n\n{'='*70}")
        print(f"🔹 Test Case {i+1}: {test['description']}")
        print(f"{'='*70}")
        
        session = agent.correct_command(
            command=test["command"],
            intent=test["intent"],
            simulate_only=True,
            validation_status=test["validation_status"]
        )
        
        report = agent.generate_report(session)
        all_reports.append(report)
        
        print(f"\n📊 Correction Summary:")
        print(f"Success: {'✅' if session.success else '❌'}")
        print(f"Autonomous Repair: {'✅' if session.is_autonomous_repair else '❌'}")
        print(f"Attempts: {len(session.attempts)}")
        print(f"Source Agent: {report['session_summary']['source_agent']}")
        
        if session.final_command and session.final_command != test["command"]:
            print(f"\n🔄 Command Evolution:")
            print(f"Original: {test['command']}")
            print(f"Final:    {session.final_command}")
        
        if session.feedback_generated:
            print(f"\n💬 Feedback Generated:")
            for feedback in session.feedback_generated:
                print(f"- {feedback['type']}: {feedback.get('reason', 'N/A')}")
    
    # Save reports
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"self_correction_demo_{timestamp}.json"
    
    with open(f"results/{filename}", 'w') as f:
        json.dump({
            "demo": "Self-Correction Agent with Autonomous Repair",
            "timestamp": datetime.utcnow().isoformat(),
            "test_cases": test_cases,
            "reports": all_reports
        }, f, indent=2)
    
    print(f"\n\n💾 Demo results saved to: results/{filename}")


if __name__ == "__main__":
    demo_self_correction()