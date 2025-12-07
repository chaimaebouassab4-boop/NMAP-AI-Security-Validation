import re
import subprocess
import shutil
from security_rules import SecurityRules

def validate_nmap_command(cmd: str, execute_real=False, timeout=60, apply_security_rules=True):
    """
    Validates and optionally executes NMAP commands with security checks.
    
    Args:
        cmd: The nmap command string to validate
        execute_real: If True, actually execute the command (default: False)
        timeout: Maximum execution time in seconds (default: 60)
        apply_security_rules: If True, apply advanced security rules (default: True)
    
    Returns:
        dict: Validation results with 'valid', 'syntax', security analysis, and execution info
    """
    
    # Strip whitespace
    cmd = cmd.strip()
    if len(parts) == 0 or parts[0] != "nmap":
        return {"valid": False, "error": "Command must start with 'nmap'."}
    
    # Check if command starts with "nmap"
    if not cmd.startswith("nmap"):
        return {
            "valid": False,
            "error": "Command must start with 'nmap'.",
            "severity": "high"
        }
    
    
    # Check for dangerous characters (command injection prevention)
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
    for char in dangerous_chars:
        if char in cmd:
            return {
                "valid": False,
                "error": f"Dangerous character detected: '{char}'. Possible command injection attempt.",
                "severity": "critical"
            }
    
    # Enhanced pattern: allow IPs, domains, CIDR notation, ports, and common flags
    pattern = r'^nmap[\s]+[\-a-zA-Z0-9\s\.,:/]+$'
    if not re.match(pattern, cmd):
        return {
            "valid": False,
            "error": "Command contains invalid characters or format.",
            "severity": "high"
        }
    
    # Parse flags for additional validation
    parts = cmd.split()
    flags = [p for p in parts[1:] if p.startswith("-")]
    targets = [p for p in parts[1:] if not p.startswith("-")]
    # Validate targets (at least one target required)
    if not targets:
        return {
            "valid": False,
            "error": "No scan target specified.",
            "severity": "medium"
        }
    
    # Validate target format (basic IP/domain validation)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'  # IPv4 with optional CIDR
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    invalid_targets = []
    for target in targets:
        if not (re.match(ip_pattern, target) or re.match(domain_pattern, target)):
            invalid_targets.append(target)
    
    if invalid_targets:
        return {
            "valid": False,
            "error": f"Invalid target format: {', '.join(invalid_targets)}",
            "severity": "medium"
        }
    
    # Build base response
    response = {
        "valid": True,
        "syntax": "OK",
        "command": cmd,
        "flags": flags,
        "targets": targets
    }
    
    # Apply advanced security rules
    if apply_security_rules:
        rules = SecurityRules()
        security_evaluation = rules.evaluate_command(flags, targets)
        
        # Add security evaluation to response
        response["security"] = security_evaluation
        
        # Override valid status if security rules block the command
        if not security_evaluation['allowed']:
            response["valid"] = False
            response["blocked_by_security"] = True
            
            # Collect all security issues
            issues = []
            if security_evaluation['forbidden_flags']['has_violations']:
                for violation in security_evaluation['forbidden_flags']['violations']:
                    issues.append(f"Forbidden flag: {violation['flag']} - {violation['reason']}")
            
            if security_evaluation['target_validation']['has_unsafe']:
                for unsafe in security_evaluation['target_validation']['unsafe_targets']:
                    issues.append(f"Unsafe target: {unsafe['target']} - {unsafe['reason']}")
            
            response["security_issues"] = issues
            response["error"] = "Command blocked by security rules. See 'security_issues' for details."
            response["severity"] = security_evaluation['risk_level']
            
            return response
        
        # Add warnings for high-risk but allowed commands
        if security_evaluation['warnings']['has_warnings']:
            warning_messages = []
            for warning in security_evaluation['warnings']['warnings']:
                warning_messages.append(f"{warning['flag']}: {warning['reason']}")
            response["warnings"] = warning_messages
        
        # Add risk information
        response["risk_score"] = security_evaluation['risk_score']
        response["risk_level"] = security_evaluation['risk_level']
        response["recommendation"] = security_evaluation['recommendation']
    
    # Execute command if requested and allowed
    if execute_real:
        # Check if nmap is installed
        if not shutil.which("nmap"):
            response["execution_error"] = "NMAP is not installed or not in PATH."
            response["executed"] = False
            return response
        
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            response["executed"] = True
            response["return_code"] = result.returncode
            response["stdout"] = result.stdout
            response["stderr"] = result.stderr
            
            if result.returncode != 0:
                response["execution_warning"] = "Command executed but returned non-zero exit code."
                
        except subprocess.TimeoutExpired:
            response["executed"] = False
            response["execution_error"] = f"Command execution timed out after {timeout} seconds."
        except Exception as e:
            response["executed"] = False
            response["execution_error"] = f"Execution failed: {str(e)}"
    else:
        # Mock execution
        response["execution_test"] = f"[MOCK] Would execute: {cmd}"
        response["executed"] = False
    
    return response


def validate_batch_commands(commands: list, execute_real=False, apply_security_rules=True):
    """
    Validate multiple NMAP commands at once.
    
    Args:
        commands: List of command strings
        execute_real: Whether to actually execute commands
        apply_security_rules: Whether to apply security rules
    
    Returns:
        list: Results for each command
    """
    results = []
    for i, cmd in enumerate(commands):
        result = validate_nmap_command(cmd, execute_real=execute_real, apply_security_rules=apply_security_rules)
        result["command_index"] = i
        results.append(result)
    return results


def get_validation_summary(results):
    """
    Generate a summary of batch validation results.
    
    Args:
        results: List of validation results from validate_batch_commands
        
    Returns:
        dict: Summary statistics
    """
    total = len(results)
    valid = sum(1 for r in results if r.get('valid'))
    blocked = sum(1 for r in results if r.get('blocked_by_security'))
    high_risk = sum(1 for r in results if r.get('risk_level') in ['high', 'critical'])
    
    return {
        'total_commands': total,
        'valid_commands': valid,
        'blocked_commands': blocked,
        'high_risk_commands': high_risk,
        'pass_rate': f"{(valid/total)*100:.1f}%" if total > 0 else "0%"
    }


if __name__ == "__main__":
    # Test cases with security rules integration
    test_commands = [
        "nmap -sV scanme.nmap.org",  # Safe test target
        "nmap -p 80,443 example.com",  # External target
        "nmap -A 10.0.0.1",  # Internal IP with aggressive scan
        "nmap; rm -rf /",  # Injection attempt
        "nmap --script vuln 192.168.1.1",  # Forbidden flag + internal IP
        "nmap -sV 192.168.1.0/24",  # Private network scan
        "nmap",  # No target
        "ping 8.8.8.8",  # Wrong command
    ]
    
    print("=" * 80)
    print("NMAP COMMAND VALIDATION WITH SECURITY RULES")
    print("=" * 80)
    
    results = []
    for cmd in test_commands:
        print(f"\n{'='*80}")
        print(f"Testing: {cmd}")
        print('='*80)
        
        result = validate_nmap_command(cmd, execute_real=False, apply_security_rules=True)
        results.append(result)
        
        # Display validation status
        status = "✅ VALID" if result.get('valid') else "❌ BLOCKED"
        print(f"\nStatus: {status}")
        
        if result.get('valid'):
            print(f"Syntax: {result.get('syntax')}")
            print(f"Targets: {result.get('targets')}")
            print(f"Flags: {result.get('flags')}")
            
            # Security information
            if 'security' in result:
                print(f"\n🔒 Security Analysis:")
                print(f"   Risk Score: {result['risk_score']}/100")
                print(f"   Risk Level: {result['risk_level'].upper()}")
                print(f"   Recommendation: {result['recommendation']}")
                
                # Display warnings
                if result.get('warnings'):
                    print(f"\n⚠️  Warnings:")
                    for warning in result['warnings']:
                        print(f"   - {warning}")
        else:
            print(f"\n❌ Error: {result.get('error')}")
            print(f"Severity: {result.get('severity')}")
            
            # Display security issues if blocked by security rules
            if result.get('blocked_by_security') and 'security_issues' in result:
                print(f"\n🚫 Security Issues:")
                for issue in result['security_issues']:
                    print(f"   - {issue}")
                
                if 'security' in result:
                    print(f"\n🔒 Security Details:")
                    print(f"   Risk Score: {result['security']['risk_score']}/100")
                    print(f"   Risk Level: {result['security']['risk_level'].upper()}")
    
    # Print summary
    print(f"\n{'='*80}")
    print("VALIDATION SUMMARY")
    print('='*80)
    summary = get_validation_summary(results)
    print(f"Total Commands: {summary['total_commands']}")
    print(f"Valid Commands: {summary['valid_commands']}")
    print(f"Blocked Commands: {summary['blocked_commands']}")
    print(f"High Risk Commands: {summary['high_risk_commands']}")
    print(f"Pass Rate: {summary['pass_rate']}")
    print('='*80)