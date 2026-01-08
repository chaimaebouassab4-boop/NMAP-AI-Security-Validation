import json
from datetime import datetime
from typing import Dict, List, Any

class ValidationScorer:
    """
    Generates structured JSON scoring output with detailed security risk 
    and compliance information for NMAP command validation.
    """
    
    def __init__(self):
        self.version = "2.0"
        self.schema_version = "1.0"
    
    def generate_compliance_info(self, security_result: Dict) -> Dict:
        """
        Generate compliance information based on security assessment.
        
        Args:
            security_result: Security evaluation results
            
        Returns:
            dict: Compliance status and details
        """
        compliance = {
            "status": "compliant" if security_result['allowed'] else "non_compliant",
            "checks_passed": 0,
            "checks_failed": 0,
            "violations": []
        }
        
        # Check forbidden flags
        if security_result['forbidden_flags']['has_violations']:
            compliance['checks_failed'] += 1
            for violation in security_result['forbidden_flags']['violations']:
                compliance['violations'].append({
                    "type": "forbidden_flag",
                    "item": violation['flag'],
                    "reason": violation['reason'],
                    "severity": violation['severity']
                })
        else:
            compliance['checks_passed'] += 1
        
        # Check unsafe targets
        if security_result['target_validation']['has_unsafe']:
            compliance['checks_failed'] += 1
            for unsafe in security_result['target_validation']['unsafe_targets']:
                compliance['violations'].append({
                    "type": "unsafe_target",
                    "item": unsafe['target'],
                    "reason": unsafe['reason'],
                    "severity": unsafe['severity']
                })
        else:
            compliance['checks_passed'] += 1
        
        # Add warnings as advisory
        if security_result['warnings']['has_warnings']:
            compliance['advisories'] = []
            for warning in security_result['warnings']['warnings']:
                compliance['advisories'].append({
                    "type": "warning_flag",
                    "item": warning['flag'],
                    "reason": warning['reason'],
                    "severity": warning['severity']
                })
        
        return compliance
    
    def calculate_scores(self, security_result: Dict) -> Dict:
        """
        Calculate detailed scoring metrics.
        
        Args:
            security_result: Security evaluation results
            
        Returns:
            dict: Detailed scores
        """
        # Base risk score from security rules
        risk_score = security_result['risk_score']
        
        # Calculate safety score (inverse of risk)
        safety_score = 100 - risk_score
        
        # Calculate compliance score
        forbidden_count = len(security_result['forbidden_flags'].get('violations', []))
        unsafe_target_count = len(security_result['target_validation'].get('unsafe_targets', []))
        warning_count = len(security_result['warnings'].get('warnings', []))
        
        total_checks = 3  # forbidden flags, unsafe targets, warnings
        failed_checks = (1 if forbidden_count > 0 else 0) + (1 if unsafe_target_count > 0 else 0)
        
        compliance_score = ((total_checks - failed_checks) / total_checks) * 100
        
        # Calculate confidence score based on validation completeness
        confidence_score = 95.0  # High confidence in validation logic
        
        return {
            "overall_score": safety_score,
            "risk_score": risk_score,
            "safety_score": safety_score,
            "compliance_score": round(compliance_score, 2),
            "confidence_score": confidence_score,
            "breakdown": {
                "command_structure": 100 if security_result['allowed'] else 0,
                "flag_safety": 100 if forbidden_count == 0 else max(0, 100 - (forbidden_count * 40)),
                "target_safety": 100 if unsafe_target_count == 0 else max(0, 100 - (unsafe_target_count * 30)),
                "execution_safety": 100 if warning_count == 0 else max(0, 100 - (warning_count * 10))
            }
        }
    
    def generate_recommendations(self, validation_result: Dict) -> List[Dict]:
        """
        Generate actionable recommendations based on validation results.
        
        Args:
            validation_result: Complete validation result
            
        Returns:
            list: List of recommendations
        """
        recommendations = []
        
        if not validation_result.get('valid'):
            # Command is invalid/blocked
            if validation_result.get('blocked_by_security'):
                security = validation_result.get('security', {})
                
                # Recommendations for forbidden flags
                if security.get('forbidden_flags', {}).get('has_violations'):
                    recommendations.append({
                        "priority": "high",
                        "category": "forbidden_flags",
                        "message": "Remove forbidden flags from command",
                        "action": "Replace or remove the following flags: " + 
                                 ", ".join([v['flag'] for v in security['forbidden_flags']['violations']]),
                        "impact": "critical"
                    })
                
                # Recommendations for unsafe targets
                if security.get('target_validation', {}).get('has_unsafe'):
                    recommendations.append({
                        "priority": "high",
                        "category": "unsafe_targets",
                        "message": "Target restricted IP ranges detected",
                        "action": "Use allowed targets like scanme.nmap.org or external IPs",
                        "impact": "high"
                    })
            else:
                # Syntax or format error
                recommendations.append({
                    "priority": "critical",
                    "category": "syntax",
                    "message": validation_result.get('error', 'Invalid command format'),
                    "action": "Review command syntax and ensure it starts with 'nmap'",
                    "impact": "critical"
                })
        else:
            # Command is valid but may have warnings
            if validation_result.get('warnings'):
                recommendations.append({
                    "priority": "medium",
                    "category": "warnings",
                    "message": "Command uses aggressive scan options",
                    "action": "Review the necessity of aggressive flags and ensure proper authorization",
                    "impact": "medium"
                })
            
            if validation_result.get('risk_level') in ['high', 'critical']:
                recommendations.append({
                    "priority": "high",
                    "category": "risk_mitigation",
                    "message": "High-risk command detected",
                    "action": "Obtain proper authorization and document the scan purpose",
                    "impact": "high"
                })
            else:
                recommendations.append({
                    "priority": "low",
                    "category": "best_practice",
                    "message": "Command appears safe",
                    "action": "Proceed with execution in appropriate environment",
                    "impact": "low"
                })
        
        return recommendations
    
    def create_json_score(self, validation_result: Dict) -> Dict:
        """
        Create comprehensive JSON scoring output.
        
        Args:
            validation_result: Complete validation result from validator
            
        Returns:
            dict: Structured JSON score with all information
        """
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Base structure
        json_score = {
            "metadata": {
                "version": self.version,
                "schema_version": self.schema_version,
                "timestamp": timestamp,
                "validator": "NMAP-AI-Security-Validation"
            },
            "command": {
                "raw": validation_result.get('command', ''),
                "parsed": {
                    "executable": "nmap",
                    "flags": validation_result.get('flags', []),
                    "targets": validation_result.get('targets', [])
                },
                "valid": validation_result.get('valid', False)
            },
            "validation": {
                "status": "passed" if validation_result.get('valid') else "failed",
                "syntax_check": validation_result.get('syntax', 'FAILED'),
                "error": validation_result.get('error') if not validation_result.get('valid') else None
            }
        }
        
        # Add generator information if available
        if 'generator_confidence' in validation_result:
            json_score["generator"] = {
                "source_agent": validation_result.get("source_agent", "unknown"),
                "confidence": validation_result.get("generator_confidence", 0.0),
                "auto_validated": validation_result.get("auto_validated", False)
            }
        
        # Add security analysis if available
        if 'security' in validation_result:
            security = validation_result['security']
            
            # Calculate scores with base values
            scores = self.calculate_scores(security)
            
            # Use the final risk_score (adjusted or not)
            final_risk_score = validation_result.get("risk_score", 0)
            scores['risk_score'] = final_risk_score
            scores['safety_score'] = 100 - final_risk_score
            scores['overall_score'] = 100 - final_risk_score
            
            json_score['scores'] = scores
            
            # Risk assessment
            json_score['risk_assessment'] = {
                "level": validation_result.get('risk_level', 'unknown'),
                "score": final_risk_score,
                "factors": security.get('risk_factors', []),
                "recommendation": validation_result.get('recommendation', '')
            }
            
            # Add adjustment reason if auto validated
            if validation_result.get("auto_validated", False):
                json_score["risk_assessment"]["adjustment_reason"] = (
                    "Risque abaissé automatiquement grâce à une haute confiance du générateur"
                )
            
            # Compliance
            json_score['compliance'] = self.generate_compliance_info(security)
            
            # Detailed findings
            json_score['findings'] = {
                "forbidden_flags": {
                    "found": security['forbidden_flags']['has_violations'],
                    "count": len(security['forbidden_flags'].get('violations', [])),
                    "details": security['forbidden_flags'].get('violations', [])
                },
                "warning_flags": {
                    "found": security['warnings']['has_warnings'],
                    "count": len(security['warnings'].get('warnings', [])),
                    "details": security['warnings'].get('warnings', [])
                },
                "target_validation": {
                    "safe_targets": security['target_validation'].get('safe_targets', []),
                    "unsafe_targets": security['target_validation'].get('unsafe_targets', []),
                    "has_unsafe": security['target_validation']['has_unsafe']
                }
            }
        
        # Recommendations
        json_score['recommendations'] = self.generate_recommendations(validation_result)
        
        # Execution info (if executed)
        if validation_result.get('executed'):
            json_score['execution'] = {
                "performed": True,
                "return_code": validation_result.get('return_code'),
                "success": validation_result.get('return_code') == 0,
                "output_available": bool(validation_result.get('stdout')),
                "errors": validation_result.get('stderr')
            }
        else:
            json_score['execution'] = {
                "performed": False,
                "mode": "validation_only"
            }
        
        return json_score
    
    def export_json(self, validation_result: Dict, filepath: str = None, pretty: bool = True) -> str:
        """
        Export JSON score to string or file.
        
        Args:
            validation_result: Complete validation result
            filepath: Optional file path to save JSON
            pretty: Whether to use pretty printing
            
        Returns:
            str: JSON string
        """
        json_score = self.create_json_score(validation_result)
        
        if pretty:
            json_str = json.dumps(json_score, indent=2, ensure_ascii=False)
        else:
            json_str = json.dumps(json_score, ensure_ascii=False)
        
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(json_str)
            print(f"JSON score exported to: {filepath}")
        
        return json_str


# Example usage and testing
if __name__ == "__main__":
    from validator import validate_nmap_command
    
    scorer = ValidationScorer()
    
    # Test cases
    test_commands = [
        "nmap -sV scanme.nmap.org",
        "nmap --script vuln 192.168.1.1",
        "nmap -A 10.0.0.1",
    ]
    
    print("=" * 80)
    print("JSON SCORING OUTPUT EXAMPLES")
    print("=" * 80)
    
    for cmd in test_commands:
        print(f"\n{'='*80}")
        print(f"Command: {cmd}")
        print('='*80)
        
        # Validate command
        result = validate_nmap_command(cmd, execute_real=False)
        
        # Generate JSON score
        json_score = scorer.create_json_score(result)
        
        # Pretty print
        print(json.dumps(json_score, indent=2))
        print()
    
    # Example: Export to file
    result = validate_nmap_command("nmap -sV scanme.nmap.org")
    scorer.export_json(result, "validation_score.json")