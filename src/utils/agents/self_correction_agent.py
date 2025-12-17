#!/usr/bin/env python3
"""
Self-Correction Agent
====================
Implements the core self-correction loop with fix generation and feedback.
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

from error_mapping_logic import ErrorAnalyzer, CorrectionType
from execution_simulator import ExecutionSimulator


class FeedbackType(Enum):
    """Types of feedback to upstream agents"""
    COMPLEXITY_REDUCTION = "complexity_reduction"
    PARAMETER_CHANGE = "parameter_change"
    ALTERNATIVE_APPROACH = "alternative_approach"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TARGET_MODIFICATION = "target_modification"
    COMPLETE_REGENERATION = "complete_regeneration"


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
    feedback_generated: List[Dict[str, Any]] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None


class SelfCorrectionAgent:
    """Main self-correction agent with fix generation and feedback loop"""
    
    def __init__(self, max_attempts: int = 3):
        self.error_analyzer = ErrorAnalyzer()
        self.execution_simulator = ExecutionSimulator()
        self.max_attempts = max_attempts
        self.sessions: List[CorrectionSession] = []
        
    def correct_command(self, command: str, intent: str = "", 
                       simulate_only: bool = True) -> CorrectionSession:
        """
        Main correction loop
        
        Args:
            command: Nmap command to correct
            intent: Original user intent (for feedback generation)
            simulate_only: If True, simulate execution; if False, real execution
            
        Returns:
            CorrectionSession with all attempts and results
        """
        session = CorrectionSession(
            session_id=f"session_{int(time.time())}",
            original_command=command,
            original_intent=intent
        )
        
        current_command = command
        
        print(f"\n🔄 Starting Self-Correction Session: {session.session_id}")
        print(f"Original Command: {command}")
        print(f"Intent: {intent or 'Not specified'}")
        print("=" * 60)
        
        for attempt_num in range(1, self.max_attempts + 1):
            print(f"\n📍 Attempt {attempt_num}/{self.max_attempts}")
            print(f"Testing: {current_command}")
            
            # Create attempt record
            attempt = CorrectionAttempt(
                attempt_number=attempt_num,
                original_command=command if attempt_num == 1 else session.attempts[-1].corrected_command,
                corrected_command=current_command
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
            # Real execution would go here
            # For now, we'll use simulation
            return self.execution_simulator.simulate_execution(command)
    
    def _is_successful_execution(self, exec_result: Dict[str, Any]) -> bool:
        """Determine if execution was successful"""
        # Success criteria:
        # 1. No critical errors
        # 2. Exit code 0
        # 3. Some output produced
        
        errors = exec_result.get("errors", [])
        critical_errors = [e for e in errors if e.get("severity") == "critical"]
        
        return (
            len(critical_errors) == 0 and
            exec_result.get("execution", {}).get("exit_code") == 0 and
            exec_result.get("execution", {}).get("completed", False)
        )
    
    def _generate_upstream_feedback(self, session: CorrectionSession, 
                                  last_result: Dict[str, Any],
                                  reason: str) -> Dict[str, Any]:
        """Generate feedback for upstream agents"""
        feedback = {
            "type": FeedbackType.COMPLETE_REGENERATION.value,
            "session_id": session.session_id,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(),
            "attempts_made": len(session.attempts),
            "persistent_errors": [],
            "recommendations": []
        }
        
        # Analyze persistent errors
        all_errors = []
        for attempt in session.attempts:
            all_errors.extend(attempt.errors_before)
        
        # Find errors that persist across attempts
        error_types = {}
        for error in all_errors:
            error_type = error.get("type", "unknown")
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        persistent_errors = [
            error_type for error_type, count in error_types.items()
            if count >= len(session.attempts)
        ]
        
        feedback["persistent_errors"] = persistent_errors
        
        # Generate specific recommendations
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
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if session.success:
            feedback["final_command"] = session.final_command
            feedback["corrections_applied"] = []
            
            for attempt in session.attempts:
                if attempt.changes_made:
                    feedback["corrections_applied"].extend(attempt.changes_made)
        else:
            feedback["failure_analysis"] = {
                "persistent_issues": self._analyze_persistent_issues(session),
                "recommended_action": self._recommend_final_action(session)
            }
        
        return feedback
    
    def _analyze_persistent_issues(self, session: CorrectionSession) -> List[str]:
        """Analyze issues that couldn't be resolved"""
        issues = []
        
        # Check last attempt errors
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
        
        # Analyze failure patterns
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
                "original_command": session.original_command,
                "final_command": session.final_command,
                "total_attempts": len(session.attempts),
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
        
        # Detail each attempt
        for attempt in session.attempts:
            report["attempts_detail"].append({
                "attempt": attempt.attempt_number,
                "command": attempt.corrected_command,
                "changes": attempt.changes_made,
                "errors_before": len(attempt.errors_before),
                "errors_after": len(attempt.errors_after) if attempt.errors_after else 0,
                "success": attempt.success
            })
        
        # Calculate improvements
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
    """Demonstrate self-correction agent"""
    agent = SelfCorrectionAgent(max_attempts=3)
    
    test_cases = [
        {
            "command": "nmap -sS -p 80 scanme.nmap.org",
            "intent": "Perform stealth scan on port 80",
            "description": "Permission error - should switch to -sT"
        },
        {
            "command": "nmap -p 80-70 --script exploit target.com",
            "intent": "Scan ports and run exploit detection",
            "description": "Multiple errors - port range and dangerous script"
        },
        {
            "command": "nmap -T5 -p- -A unreachable.invalid",
            "intent": "Comprehensive scan of target",
            "description": "DNS and timing issues"
        }
    ]
    
    print("🤖 Self-Correction Agent Demo")
    print("=" * 60)
    
    all_reports = []
    
    for i, test in enumerate(test_cases):
        print(f"\n\n{'='*60}")
        print(f"📋 Test Case {i+1}: {test['description']}")
        print(f"{'='*60}")
        
        # Run correction
        session = agent.correct_command(
            command=test["command"],
            intent=test["intent"],
            simulate_only=True
        )
        
        # Generate report
        report = agent.generate_report(session)
        all_reports.append(report)
        
        # Display summary
        print(f"\n📊 Correction Summary:")
        print(f"Success: {'✅' if session.success else '❌'}")
        print(f"Attempts: {len(session.attempts)}")
        
        if session.final_command and session.final_command != test["command"]:
            print(f"\n🔄 Command Evolution:")
            print(f"Original: {test['command']}")
            print(f"Final:    {session.final_command}")
        
        if session.feedback_generated:
            print(f"\n📨 Feedback Generated:")
            for feedback in session.feedback_generated:
                print(f"- {feedback['type']}: {feedback.get('reason', 'N/A')}")
                for rec in feedback.get('recommendations', []):
                    print(f"  • {rec['suggestion']}")
    
    # Save all reports
    os.makedirs("results", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"self_correction_demo_{timestamp}.json"
    
    with open(f"results/{filename}", 'w') as f:
        json.dump({
            "demo": "Self-Correction Agent",
            "timestamp": datetime.utcnow().isoformat(),
            "test_cases": test_cases,
            "reports": all_reports
        }, f, indent=2)
    
    print(f"\n\n💾 Demo results saved to: results/{filename}")


if __name__ == "__main__":
    demo_self_correction()
