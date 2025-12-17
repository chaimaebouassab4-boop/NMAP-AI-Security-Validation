#!/usr/bin/env python3
"""
Error Mapping Logic
==================
Maps execution errors to corrective actions for self-correction.
"""

import json
import re
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass


class CorrectionType(Enum):
    """Types of corrections that can be applied"""
    REPLACE_FLAG = "replace_flag"
    ADD_FLAG = "add_flag"
    REMOVE_FLAG = "remove_flag"
    MODIFY_PARAMETER = "modify_parameter"
    CHANGE_SCAN_TYPE = "change_scan_type"
    ADJUST_TIMING = "adjust_timing"
    FIX_SYNTAX = "fix_syntax"
    SIMPLIFY_COMMAND = "simplify_command"
    ESCALATE_PRIVILEGES = "escalate_privileges"
    ALTERNATIVE_APPROACH = "alternative_approach"


@dataclass
class ErrorMapping:
    """Maps an error pattern to a corrective action"""
    error_type: str
    error_pattern: str
    correction_type: CorrectionType
    correction_action: Dict[str, Any]
    confidence: float
    explanation: str


class ErrorAnalyzer:
    """Analyzes errors and maps them to corrections"""
    
    def __init__(self):
        self.error_mappings = self._initialize_mappings()
        self.correction_history = []
        
    def _initialize_mappings(self) -> List[ErrorMapping]:
        """Initialize error to correction mappings"""
        return [
            # Permission errors
            ErrorMapping(
                error_type="permission_denied",
                error_pattern="requires_root|Operation not permitted",
                correction_type=CorrectionType.REPLACE_FLAG,
                correction_action={
                    "replacements": {
                        "-sS": "-sT",
                        "-sA": "-sT",
                        "-sF": "-sT",
                        "-sX": "-sT",
                        "-sN": "-sT",
                        "-sU": "-sT"
                    },
                    "reason": "Stealth scans require root privileges"
                },
                confidence=0.95,
                explanation="Replace stealth scan with TCP connect scan that doesn't require root"
            ),
            
            ErrorMapping(
                error_type="permission_denied",
                error_pattern="PCAP permission problem",
                correction_type=CorrectionType.REMOVE_FLAG,
                correction_action={
                    "remove": ["-O", "--osscan-guess"],
                    "reason": "OS detection requires raw packet access"
                },
                confidence=0.90,
                explanation="Remove OS detection flags that require elevated privileges"
            ),
            
            # Port specification errors
            ErrorMapping(
                error_type="port_specification",
                error_pattern="Illegal port number|port specifications are illegal",
                correction_type=CorrectionType.FIX_SYNTAX,
                correction_action={
                    "fix_function": "fix_port_syntax",
                    "validation_regex": r'^(\d+(-\d+)?,)*\d+(-\d+)?$'
                },
                confidence=0.85,
                explanation="Fix port specification syntax"
            ),
            
            # DNS errors
            ErrorMapping(
                error_type="dns_resolution",
                error_pattern="Failed to resolve|Could not resolve hostname",
                correction_type=CorrectionType.ADD_FLAG,
                correction_action={
                    "add": "-n",
                    "reason": "Skip DNS resolution for unreachable hosts"
                },
                confidence=0.80,
                explanation="Add -n flag to skip DNS resolution"
            ),
            
            # Script errors
            ErrorMapping(
                error_type="script_not_found",
                error_pattern="Failed to load.*script|script.*does not exist",
                correction_type=CorrectionType.ALTERNATIVE_APPROACH,
                correction_action={
                    "alternatives": {
                        "vuln": ["default", "discovery"],
                        "exploit": ["safe", "version"],
                        "brute": ["auth", "default"]
                    },
                    "fallback": "default"
                },
                confidence=0.75,
                explanation="Replace unavailable script with safe alternative"
            ),
            
            # Timing errors
            ErrorMapping(
                error_type="timeout",
                error_pattern="timed out|timeout",
                correction_type=CorrectionType.ADJUST_TIMING,
                correction_action={
                    "timing_adjustments": {
                        "-T5": "-T4",
                        "-T4": "-T3",
                        "-T3": "-T2"
                    },
                    "add_if_missing": "-T3"
                },
                confidence=0.85,
                explanation="Reduce scan aggressiveness to prevent timeout"
            ),
            
            # Network errors
            ErrorMapping(
                error_type="network_unreachable",
                error_pattern="No route to host|Network is unreachable",
                correction_type=CorrectionType.SIMPLIFY_COMMAND,
                correction_action={
                    "simplification_steps": [
                        "reduce_port_range",
                        "single_target",
                        "basic_scan"
                    ]
                },
                confidence=0.70,
                explanation="Simplify command for unreachable network"
            ),
            
            # Syntax errors
            ErrorMapping(
                error_type="syntax_error",
                error_pattern="unrecognized option|requires an argument",
                correction_type=CorrectionType.FIX_SYNTAX,
                correction_action={
                    "fix_function": "fix_general_syntax"
                },
                confidence=0.80,
                explanation="Fix command syntax errors"
            )
        ]
    
    def analyze_errors(self, execution_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze execution errors and map to corrections
        
        Args:
            execution_result: Result from execution simulator
            
        Returns:
            List of mapped corrections with confidence scores
        """
        corrections = []
        errors = execution_result.get("errors", [])
        command = execution_result.get("command", "")
        
        for error in errors:
            error_type = error.get("type", "")
            error_message = error.get("message", "")
            
            # Find matching error mappings
            for mapping in self.error_mappings:
                if (mapping.error_type == error_type and 
                    re.search(mapping.error_pattern, error_message, re.IGNORECASE)):
                    
                    correction = {
                        "error": error,
                        "mapping": mapping,
                        "correction": self._generate_correction(command, mapping),
                        "confidence": mapping.confidence,
                        "explanation": mapping.explanation
                    }
                    
                    corrections.append(correction)
                    break
        
        # Sort by confidence
        corrections.sort(key=lambda x: x["confidence"], reverse=True)
        
        # Record in history
        self.correction_history.append({
            "timestamp": execution_result.get("timestamp"),
            "command": command,
            "errors": errors,
            "corrections": corrections
        })
        
        return corrections
    
    def _generate_correction(self, command: str, mapping: ErrorMapping) -> Dict[str, Any]:
        """Generate specific correction based on mapping"""
        correction = {
            "type": mapping.correction_type.value,
            "original_command": command,
            "corrected_command": command,
            "changes": []
        }
        
        if mapping.correction_type == CorrectionType.REPLACE_FLAG:
            correction["corrected_command"], changes = self._apply_replacements(
                command, mapping.correction_action["replacements"]
            )
            correction["changes"] = changes
            
        elif mapping.correction_type == CorrectionType.ADD_FLAG:
            flag_to_add = mapping.correction_action["add"]
            if flag_to_add not in command:
                correction["corrected_command"] = command.replace("nmap", f"nmap {flag_to_add}")
                correction["changes"].append(f"Added {flag_to_add}")
                
        elif mapping.correction_type == CorrectionType.REMOVE_FLAG:
            corrected = command
            for flag in mapping.correction_action["remove"]:
                if flag in corrected:
                    corrected = re.sub(rf'\s*{re.escape(flag)}(?:\s+\S+)?', '', corrected)
                    correction["changes"].append(f"Removed {flag}")
            correction["corrected_command"] = corrected.strip()
            
        elif mapping.correction_type == CorrectionType.ADJUST_TIMING:
            corrected, change = self._adjust_timing(
                command, mapping.correction_action["timing_adjustments"]
            )
            correction["corrected_command"] = corrected
            if change:
                correction["changes"].append(change)
                
        elif mapping.correction_type == CorrectionType.FIX_SYNTAX:
            if mapping.correction_action["fix_function"] == "fix_port_syntax":
                corrected, changes = self._fix_port_syntax(command)
                correction["corrected_command"] = corrected
                correction["changes"] = changes
                
        elif mapping.correction_type == CorrectionType.ALTERNATIVE_APPROACH:
            corrected, change = self._apply_alternative(
                command, mapping.correction_action["alternatives"]
            )
            correction["corrected_command"] = corrected
            if change:
                correction["changes"].append(change)
                
        elif mapping.correction_type == CorrectionType.SIMPLIFY_COMMAND:
            corrected, changes = self._simplify_command(command)
            correction["corrected_command"] = corrected
            correction["changes"] = changes
        
        return correction
    
    def _apply_replacements(self, command: str, replacements: Dict[str, str]) -> Tuple[str, List[str]]:
        """Apply flag replacements"""
        corrected = command
        changes = []
        
        for old, new in replacements.items():
            if old in corrected:
                corrected = corrected.replace(old, new)
                changes.append(f"Replaced {old} with {new}")
                break  # Apply only first matching replacement
        
        return corrected, changes
    
    def _adjust_timing(self, command: str, adjustments: Dict[str, str]) -> Tuple[str, Optional[str]]:
        """Adjust timing template"""
        corrected = command
        change = None
        
        for old, new in adjustments.items():
            if old in command:
                corrected = command.replace(old, new)
                change = f"Adjusted timing from {old} to {new}"
                break
        else:
            # Add default timing if none present
            if not re.search(r'-T\d', command):
                add_timing = adjustments.get("add_if_missing", "-T3")
                corrected = command.replace("nmap", f"nmap {add_timing}")
                change = f"Added {add_timing} timing template"
        
        return corrected, change
    
    def _fix_port_syntax(self, command: str) -> Tuple[str, List[str]]:
        """Fix port specification syntax"""
        changes = []
        corrected = command
        
        # Find port specification
        port_match = re.search(r'-p\s+([^\s]+)', command)
        if port_match:
            port_spec = port_match.group(1)
            
            # Common fixes
            fixed_spec = port_spec
            
            # Fix reversed ranges (e.g., 80-70 -> 70-80)
            range_match = re.match(r'(\d+)-(\d+)', port_spec)
            if range_match:
                start, end = int(range_match.group(1)), int(range_match.group(2))
                if start > end:
                    fixed_spec = f"{end}-{start}"
                    changes.append(f"Fixed port range: {port_spec} -> {fixed_spec}")
            
            # Fix invalid separators
            if ';' in fixed_spec:
                fixed_spec = fixed_spec.replace(';', ',')
                changes.append("Replaced ; with , in port specification")
            
            # Replace in command
            if fixed_spec != port_spec:
                corrected = command.replace(f"-p {port_spec}", f"-p {fixed_spec}")
        
        return corrected, changes
    
    def _apply_alternative(self, command: str, alternatives: Dict[str, List[str]]) -> Tuple[str, Optional[str]]:
        """Apply alternative scripts or approaches"""
        corrected = command
        change = None
        
        # Find script specification
        script_match = re.search(r'--script[=\s]+([^\s]+)', command)
        if script_match:
            current_script = script_match.group(1)
            
            # Find alternative
            for problem_script, alt_scripts in alternatives.items():
                if problem_script in current_script:
                    # Use first alternative
                    if alt_scripts:
                        new_script = alt_scripts[0]
                        corrected = command.replace(
                            f"--script {current_script}", 
                            f"--script {new_script}"
                        )
                        change = f"Replaced script {current_script} with {new_script}"
                    break
        
        return corrected, change
    
    def _simplify_command(self, command: str) -> Tuple[str, List[str]]:
        """Simplify command for better success rate"""
        changes = []
        corrected = command
        
        # Step 1: Reduce port range
        if "-p-" in corrected:
            corrected = corrected.replace("-p-", "-p 1-1000")
            changes.append("Reduced port range from all to common ports (1-1000)")
        elif re.search(r'-p\s+\d+-\d+', corrected):
            # Limit to max 100 ports
            port_match = re.search(r'-p\s+(\d+)-(\d+)', corrected)
            if port_match:
                start = int(port_match.group(1))
                end = int(port_match.group(2))
                if end - start > 100:
                    new_end = start + 100
                    corrected = corrected.replace(
                        f"-p {start}-{end}", 
                        f"-p {start}-{new_end}"
                    )
                    changes.append(f"Limited port range to 100 ports")
        
        # Step 2: Remove aggressive options
        aggressive_flags = ["-A", "--version-all", "-sV", "-O"]
        for flag in aggressive_flags:
            if flag in corrected:
                corrected = re.sub(rf'\s*{re.escape(flag)}', '', corrected)
                changes.append(f"Removed aggressive option {flag}")
        
        # Step 3: Ensure reasonable timing
        if "-T5" in corrected:
            corrected = corrected.replace("-T5", "-T3")
            changes.append("Reduced timing from T5 to T3")
        elif "-T4" in corrected:
            corrected = corrected.replace("-T4", "-T3")
            changes.append("Reduced timing from T4 to T3")
        
        return corrected.strip(), changes
    
    def get_best_correction(self, corrections: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Get the best correction from a list based on confidence"""
        if not corrections:
            return None
        
        # Return highest confidence correction
        return corrections[0]
    
    def generate_report(self, execution_result: Dict[str, Any], corrections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive error analysis report"""
        report = {
            "original_command": execution_result.get("command"),
            "execution_status": {
                "exit_code": execution_result["execution"]["exit_code"],
                "duration": execution_result["execution"]["duration"],
                "completed": execution_result["execution"]["completed"]
            },
            "error_summary": {
                "total_errors": len(execution_result.get("errors", [])),
                "error_types": list(set(e["type"] for e in execution_result.get("errors", [])))
            },
            "corrections": {
                "total_corrections": len(corrections),
                "best_correction": None,
                "all_corrections": []
            }
        }
        
        if corrections:
            best = self.get_best_correction(corrections)
            if best:
                report["corrections"]["best_correction"] = {
                    "command": best["correction"]["corrected_command"],
                    "confidence": best["confidence"],
                    "changes": best["correction"]["changes"],
                    "explanation": best["explanation"]
                }
            
            # Include all corrections summary
            for corr in corrections:
                report["corrections"]["all_corrections"].append({
                    "type": corr["mapping"].correction_type.value,
                    "confidence": corr["confidence"],
                    "command": corr["correction"]["corrected_command"]
                })
        
        return report


def demo_error_analysis():
    """Demonstrate error analysis and mapping"""
    analyzer = ErrorAnalyzer()
    
    # Sample execution results with errors
    test_results = [
        {
            "command": "nmap -sS -p 80 scanme.nmap.org",
            "errors": [{
                "type": "permission_denied",
                "message": "TCP SYN scan requires root privileges",
                "severity": "critical"
            }]
        },
        {
            "command": "nmap -p 80-70 example.com",
            "errors": [{
                "type": "port_specification",
                "message": "Your port specifications are illegal",
                "severity": "high"
            }]
        },
        {
            "command": "nmap --script exploit nonexistent.domain",
            "errors": [
                {
                    "type": "dns_resolution",
                    "message": "Failed to resolve 'nonexistent.domain'",
                    "severity": "high"
                },
                {
                    "type": "script_not_found",
                    "message": "NSE: Failed to load exploit script",
                    "severity": "medium"
                }
            ]
        }
    ]
    
    print("🔍 Error Analysis and Mapping Demo")
    print("=" * 60)
    
    all_reports = []
    
    for i, result in enumerate(test_results):
        print(f"\n📋 Test Case {i+1}")
        print(f"Command: {result['command']}")
        print(f"Errors: {len(result['errors'])}")
        
        # Add execution metadata
        result["execution"] = {
            "exit_code": 1,
            "duration": 2.5,
            "completed": True
        }
        result["timestamp"] = "2024-01-01T00:00:00Z"
        
        # Analyze errors
        corrections = analyzer.analyze_errors(result)
        
        # Generate report
        report = analyzer.generate_report(result, corrections)
        all_reports.append(report)
        
        # Display results
        print("\n📊 Analysis Results:")
        print(f"Total Corrections Found: {report['corrections']['total_corrections']}")
        
        if report["corrections"]["best_correction"]:
            best = report["corrections"]["best_correction"]
            print(f"\n✨ Best Correction (Confidence: {best['confidence']:.2%}):")
            print(f"Original: {result['command']}")
            print(f"Corrected: {best['command']}")
            print(f"Changes: {', '.join(best['changes'])}")
            print(f"Explanation: {best['explanation']}")
        
        print("-" * 60)
    
    # Save reports
    with open("results/error_analysis_demo.json", 'w') as f:
        json.dump(all_reports, f, indent=2)
    
    print("\n💾 Analysis reports saved to: results/error_analysis_demo.json")


if __name__ == "__main__":
    demo_error_analysis()
