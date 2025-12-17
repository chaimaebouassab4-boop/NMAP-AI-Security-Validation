#!/usr/bin/env python3
"""
Auto-Correction Cycle Demo
==========================
Demonstrates the complete self-correction loop with intentionally flawed commands.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any

# Add parent directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'agents'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'utils'))

from self_correction_agent import SelfCorrectionAgent
from execution_simulator import ExecutionSimulator
from validation_agent import ValidationAgent


class AutoCorrectionDemo:
    """Demonstrates the complete auto-correction cycle"""
    
    def __init__(self):
        self.correction_agent = SelfCorrectionAgent(max_attempts=4)
        self.validation_agent = ValidationAgent()
        self.test_scenarios = self._create_test_scenarios()
        
    def _create_test_scenarios(self) -> List[Dict[str, Any]]:
        """Create intentionally flawed commands for testing"""
        return [
            {
                "id": "PERM_001",
                "name": "Permission Error Fix",
                "description": "SYN scan without root → TCP connect scan",
                "flawed_command": "nmap -sS -p 22,80,443 192.168.1.100",
                "user_intent": "Scan common web and SSH ports on internal server",
                "expected_fix": "Replace -sS with -sT",
                "expected_result": "nmap -sT -p 22,80,443 192.168.1.100"
            },
            {
                "id": "SYNTAX_001",
                "name": "Port Range Syntax Error",
                "description": "Reversed port range → Corrected range",
                "flawed_command": "nmap -sT -p 443-80 example.com",
                "user_intent": "Scan ports between 80 and 443",
                "expected_fix": "Fix port range order",
                "expected_result": "nmap -sT -p 80-443 example.com"
            },
            {
                "id": "SCRIPT_001",
                "name": "Dangerous Script Replacement",
                "description": "Exploit script → Safe alternative",
                "flawed_command": "nmap --script exploit -p 80 target.com",
                "user_intent": "Check for vulnerabilities on web server",
                "expected_fix": "Replace with safe script",
                "expected_result": "nmap --script safe -p 80 target.com"
            },
            {
                "id": "COMPLEX_001",
                "name": "Multiple Issues Fix",
                "description": "Permission + DNS + Timing issues",
                "flawed_command": "nmap -sS -T5 -O unreachable.invalid",
                "user_intent": "Quick scan with OS detection",
                "expected_fix": "Multiple corrections needed",
                "expected_result": "nmap -sT -T3 -n unreachable.invalid"
            },
            {
                "id": "TIMING_001",
                "name": "Aggressive Timing Adjustment",
                "description": "Insane timing → Normal timing",
                "flawed_command": "nmap -T5 -p- 10.0.0.0/16",
                "user_intent": "Scan entire subnet quickly",
                "expected_fix": "Reduce timing and scope",
                "expected_result": "nmap -T3 -p 1-1000 10.0.0.0/16"
            }
        ]
    
    def run_scenario(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Run a single test scenario"""
        print(f"\n{'='*70}")
        print(f"🧪 Scenario: {scenario['name']}")
        print(f"{'='*70}")
        print(f"ID: {scenario['id']}")
        print(f"Description: {scenario['description']}")
        print(f"User Intent: {scenario['user_intent']}")
        print(f"Flawed Command: {scenario['flawed_command']}")
        print(f"Expected Fix: {scenario['expected_fix']}")
        
        # Step 1: Validate the flawed command
        print(f"\n📋 Step 1: Initial Validation")
        validation_result = self.validation_agent.validate_command(scenario['flawed_command'])
        print(f"Risk Score: {validation_result.risk_score}")
        print(f"Risk Level: {validation_result.risk_level.value}")
        
        # Step 2: Run self-correction
        print(f"\n🔄 Step 2: Self-Correction Loop")
        correction_session = self.correction_agent.correct_command(
            command=scenario['flawed_command'],
            intent=scenario['user_intent'],
            simulate_only=True
        )
        
        # Step 3: Validate corrected command
        final_command = correction_session.final_command or scenario['flawed_command']
        print(f"\n📋 Step 3: Final Validation")
        final_validation = self.validation_agent.validate_command(final_command)
        
        # Prepare results
        result = {
            "scenario": scenario,
            "initial_validation": {
                "risk_score": validation_result.risk_score,
                "risk_level": validation_result.risk_level.value,
                "issues": len(validation_result.suggestions)
            },
            "correction_session": {
                "session_id": correction_session.session_id,
                "success": correction_session.success,
                "attempts": len(correction_session.attempts),
                "final_command": final_command,
                "changes_applied": []
            },
            "final_validation": {
                "risk_score": final_validation.risk_score,
                "risk_level": final_validation.risk_level.value,
                "improvement": validation_result.risk_score - final_validation.risk_score
            },
            "success_metrics": {
                "command_fixed": correction_session.success,
                "risk_reduced": final_validation.risk_score < validation_result.risk_score,
                "matches_expected": final_command == scenario.get('expected_result', final_command)
            }
        }
        
        # Collect all changes
        for attempt in correction_session.attempts:
            result["correction_session"]["changes_applied"].extend(attempt.changes_made)
        
        # Display results
        print(f"\n📊 Results:")
        print(f"Original Command: {scenario['flawed_command']}")
        print(f"Final Command:    {final_command}")
        print(f"Success: {'✅' if correction_session.success else '❌'}")
        print(f"Risk Reduction: {result['final_validation']['improvement']} points")
        
        if result["correction_session"]["changes_applied"]:
            print(f"\nChanges Applied:")
            for change in result["correction_session"]["changes_applied"]:
                print(f"  • {change}")
        
        return result
    
    def run_full_demo(self):
        """Run all test scenarios"""
        print("🚀 NMAP-AI Auto-Correction Cycle Demo")
        print("📅 Week 3 Deliverable")
        print(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        
        all_results = []
        summary = {
            "total_scenarios": len(self.test_scenarios),
            "successful_corrections": 0,
            "risk_reductions": 0,
            "perfect_matches": 0,
            "average_attempts": 0
        }
        
        # Run each scenario
        for scenario in self.test_scenarios:
            result = self.run_scenario(scenario)
            all_results.append(result)
            
            # Update summary
            if result["success_metrics"]["command_fixed"]:
                summary["successful_corrections"] += 1
            if result["success_metrics"]["risk_reduced"]:
                summary["risk_reductions"] += 1
            if result["success_metrics"]["matches_expected"]:
                summary["perfect_matches"] += 1
            summary["average_attempts"] += result["correction_session"]["attempts"]
        
        summary["average_attempts"] /= len(self.test_scenarios)
        
        # Display summary
        print(f"\n{'='*70}")
        print("📊 DEMO SUMMARY")
        print("="*70)
        print(f"Total Scenarios: {summary['total_scenarios']}")
        print(f"Successful Corrections: {summary['successful_corrections']} ({summary['successful_corrections']/summary['total_scenarios']*100:.1f}%)")
        print(f"Risk Reductions: {summary['risk_reductions']} ({summary['risk_reductions']/summary['total_scenarios']*100:.1f}%)")
        print(f"Perfect Matches: {summary['perfect_matches']} ({summary['perfect_matches']/summary['total_scenarios']*100:.1f}%)")
        print(f"Average Attempts: {summary['average_attempts']:.1f}")
        
        # Save detailed results
        self._save_results(all_results, summary)
        
        return all_results, summary
    
    def _save_results(self, results: List[Dict[str, Any]], summary: Dict[str, Any]):
        """Save demo results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"auto_correction_demo_{timestamp}.json"
        
        output = {
            "demo": "NMAP-AI Auto-Correction Cycle",
            "version": "Week 3",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": summary,
            "scenarios": results
        }
        
        os.makedirs("results", exist_ok=True)
        filepath = os.path.join("results", filename)
        
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Detailed results saved to: {filepath}")
    
    def demonstrate_single_correction(self):
        """Demonstrate a single correction in detail"""
        print("\n" + "="*70)
        print("🔍 DETAILED SINGLE CORRECTION DEMO")
        print("="*70)
        
        # Use the most complex scenario
        scenario = self.test_scenarios[3]  # COMPLEX_001
        
        print(f"Demonstrating: {scenario['name']}")
        print(f"Flawed Command: {scenario['flawed_command']}")
        print(f"User Intent: {scenario['user_intent']}")
        
        # Create correction agent with verbose output
        agent = SelfCorrectionAgent(max_attempts=4)
        
        # Run correction with detailed tracking
        session = agent.correct_command(
            command=scenario['flawed_command'],
            intent=scenario['user_intent'],
            simulate_only=True
        )
        
        # Display each attempt
        print("\n📝 Correction Attempts:")
        for attempt in session.attempts:
            print(f"\n  Attempt {attempt.attempt_number}:")
            print(f"  Command: {attempt.corrected_command}")
            print(f"  Errors Before: {len(attempt.errors_before)}")
            if attempt.errors_before:
                for error in attempt.errors_before[:2]:  # Show first 2 errors
                    print(f"    - {error.get('type')}: {error.get('message', '')[:50]}...")
            
            if attempt.changes_made:
                print(f"  Changes Made:")
                for change in attempt.changes_made:
                    print(f"    • {change}")
            
            print(f"  Success: {'✅' if attempt.success else '❌'}")
        
        # Display feedback
        if session.feedback_generated:
            print("\n📨 Feedback Generated for Upstream Agents:")
            for feedback in session.feedback_generated:
                print(f"  Type: {feedback['type']}")
                print(f"  Reason: {feedback.get('reason', 'N/A')}")
                if feedback.get('recommendations'):
                    print("  Recommendations:")
                    for rec in feedback['recommendations']:
                        print(f"    - {rec['action']}: {rec['suggestion']}")
        
        # Final result
        print(f"\n🎯 Final Result:")
        print(f"Success: {'✅' if session.success else '❌'}")
        print(f"Original: {scenario['flawed_command']}")
        print(f"Final:    {session.final_command or 'No successful correction'}")
        
        # Generate and display report
        report = agent.generate_report(session)
        print(f"\n📊 Improvement Metrics:")
        print(f"Errors Fixed: {report['improvements']['errors_fixed']}")
        print(f"Success Rate: {report['improvements']['success_rate']:.1%}")


def main():
    """Main entry point"""
    demo = AutoCorrectionDemo()
    
    # Run full demo
    demo.run_full_demo()
    
    # Show detailed single correction
    demo.demonstrate_single_correction()
    
    print("\n✅ Auto-Correction Demo Complete!")


if __name__ == "__main__":
    main()
