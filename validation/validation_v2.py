# Save this as: validation/validation_v2.py

"""
Validation v2 - Complete NMAP Command Validation System
========================================================
Comprehensive validation system combining syntax checking, security rules,
risk scoring, and structured JSON output.
"""

import json
import sys
from typing import Dict, List, Optional, Any
from datetime import datetime

from validator import validate_nmap_command, get_validation_summary
from json_scorer import ValidationScorer


class ValidationV2:
    """Complete validation system with advanced features."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize Validation v2 system."""
        self.version = "2.0"
        self.scorer = ValidationScorer()
        self.config = config or self._default_config()
        self.validation_history = []
    
    def _default_config(self) -> Dict:
        """Return default configuration."""
        return {
            "apply_security_rules": True,
            "enable_execution": False,
            "execution_timeout": 60,
            "log_validations": True,
            "strict_mode": False,
            "output_format": "json"
        }
    
    def validate_single(
        self, 
        command: str, 
        execute: bool = False,
        return_json: bool = True
    ) -> Dict[str, Any]:
        """Validate a single NMAP command with full scoring."""
        
        # Override execution based on config
        if not self.config.get("enable_execution", False):
            execute = False
        
        # Validate command
        result = validate_nmap_command(
            command,
            execute_real=execute,
            timeout=self.config.get("execution_timeout", 60),
            apply_security_rules=self.config.get("apply_security_rules", True)
        )
        
        # Apply strict mode if enabled
        if self.config.get("strict_mode", False) and result.get("valid"):
            if result.get("warnings") or result.get("risk_level") in ["high", "critical"]:
                result["valid"] = False
                result["strict_mode_blocked"] = True
                result["error"] = "Command blocked by strict mode due to high risk or warnings"
        
        # Generate JSON score if requested
        if return_json:
            json_score = self.scorer.create_json_score(result)
            result["json_score"] = json_score
        
        # Log validation if enabled
        if self.config.get("log_validations", True):
            self._log_validation(result)
        
        return result
    
    def validate_multiple(
        self, 
        commands: List[str],
        execute: bool = False,
        return_json: bool = True
    ) -> Dict[str, Any]:
        """Validate multiple commands and generate summary."""
        results = []
        
        for i, cmd in enumerate(commands):
            result = self.validate_single(cmd, execute=execute, return_json=return_json)
            result["batch_index"] = i
            results.append(result)
        
        # Generate summary
        summary = get_validation_summary(results)
        
        # Add risk statistics
        risk_distribution = {
            "critical": sum(1 for r in results if r.get("risk_level") == "critical"),
            "high": sum(1 for r in results if r.get("risk_level") == "high"),
            "medium": sum(1 for r in results if r.get("risk_level") == "medium"),
            "low": sum(1 for r in results if r.get("risk_level") == "low")
        }
        
        return {
            "metadata": {
                "version": self.version,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "total_commands": len(commands)
            },
            "summary": summary,
            "risk_distribution": risk_distribution,
            "results": results
        }
    
    def _log_validation(self, result: Dict):
        """Log validation to history."""
        self.validation_history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "command": result.get("command"),
            "valid": result.get("valid"),
            "risk_level": result.get("risk_level")
        })
    
    def get_statistics(self) -> Dict:
        """Get statistics from validation history."""
        if not self.validation_history:
            return {"error": "No validations recorded"}
        
        total = len(self.validation_history)
        valid = sum(1 for v in self.validation_history if v["valid"])
        
        return {
            "total_validations": total,
            "valid_count": valid,
            "blocked_count": total - valid,
            "success_rate": f"{(valid/total)*100:.1f}%",
            "risk_levels": {
                "critical": sum(1 for v in self.validation_history if v.get("risk_level") == "critical"),
                "high": sum(1 for v in self.validation_history if v.get("risk_level") == "high"),
                "medium": sum(1 for v in self.validation_history if v.get("risk_level") == "medium"),
                "low": sum(1 for v in self.validation_history if v.get("risk_level") == "low")
            }
        }
