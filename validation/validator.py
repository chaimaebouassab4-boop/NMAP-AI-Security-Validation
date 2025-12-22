import re
import shlex
import subprocess
import shutil
from .security_rules import SecurityRules


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

    response = {
        "command": cmd,
        "valid": False,
        "severity": "high"
    }

    # ------------------------------------------------------------------
    # 1️⃣ Basic input validation
    # ------------------------------------------------------------------
    if not cmd or not isinstance(cmd, str):
        response["error"] = "Empty or invalid command."
        return response

    cmd = cmd.strip()

    # ------------------------------------------------------------------
    # 2️⃣ Block obvious command injection attempts
    # ------------------------------------------------------------------
    injection_pattern = r"[;&|`]|(\$\()|(\|\|)|(&&)|(<)|(>)"
    if re.search(injection_pattern, cmd):
        response.update({
            "error": "Possible command injection detected.",
            "severity": "critical"
        })
        return response

    # ------------------------------------------------------------------
    # 3️⃣ Safe parsing (FIXES CRASH)
    # ------------------------------------------------------------------
    try:
        parts = shlex.split(cmd)
    except ValueError as e:
        response["error"] = f"Command parsing failed: {e}"
        return response

    # ------------------------------------------------------------------
    # 4️⃣ Ensure command is EXACTLY nmap
    # ------------------------------------------------------------------
    if not parts or parts[0].lower() != "nmap":
        response["error"] = "Command must start with 'nmap'."
        return response

    # ------------------------------------------------------------------
    # 5️⃣ Separate flags and targets safely
    # ------------------------------------------------------------------
    flags = []
    targets = []

    skip_next = False
    for i, part in enumerate(parts[1:]):
        if skip_next:
            skip_next = False
            continue

        if part.startswith("-"):
            flags.append(part)

            # Flags that take arguments
            if part in {"-p", "--ports", "--script", "--script-args", "-oA", "-oN", "-oX"}:
                skip_next = True
        else:
            targets.append(part)

    if not targets:
        response.update({
            "error": "No scan target specified.",
            "severity": "medium"
        })
        return response

    # ------------------------------------------------------------------
    # 6️⃣ Validate targets (IPv4, CIDR, domain)
    # ------------------------------------------------------------------
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
    domain_pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$'

    invalid_targets = []
    for target in targets:
        if not (re.match(ip_pattern, target) or re.match(domain_pattern, target)):
            invalid_targets.append(target)

    if invalid_targets:
        response.update({
            "error": f"Invalid target format: {', '.join(invalid_targets)}",
            "severity": "medium"
        })
        return response

    # ------------------------------------------------------------------
    # 7️⃣ Base valid response
    # ------------------------------------------------------------------
    response.update({
        "valid": True,
        "syntax": "nmap [flags] <target>",
        "flags": flags,
        "targets": targets,
        "severity": "low"
    })

    # ------------------------------------------------------------------
    # 8️⃣ Apply advanced security rules
    # ------------------------------------------------------------------
    if apply_security_rules:
        rules = SecurityRules()
        security = rules.evaluate_command(flags, targets)
        response["security"] = security

        if not security["allowed"]:
            issues = []

            for v in security["forbidden_flags"].get("violations", []):
                issues.append(f"Forbidden flag {v['flag']}: {v['reason']}")

            for t in security["target_validation"].get("unsafe_targets", []):
                issues.append(f"Unsafe target {t['target']}: {t['reason']}")

            response.update({
                "valid": False,
                "blocked_by_security": True,
                "security_issues": issues,
                "error": "Command blocked by security rules.",
                "severity": security.get("risk_level", "high")
            })
            return response

        if security["warnings"]["has_warnings"]:
            response["warnings"] = [
                f"{w['flag']}: {w['reason']}"
                for w in security["warnings"]["warnings"]
            ]

        response.update({
            "risk_score": security["risk_score"],
            "risk_level": security["risk_level"],
            "recommendation": security["recommendation"]
        })

    # ------------------------------------------------------------------
    # 9️⃣ Execute command (optional)
    # ------------------------------------------------------------------
    if execute_real:
        if not shutil.which("nmap"):
            response.update({
                "executed": False,
                "execution_error": "Nmap is not installed or not in PATH."
            })
            return response

        try:
            proc = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            response.update({
                "executed": True,
                "return_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr
            })

            if proc.returncode != 0:
                response["execution_warning"] = "Non-zero exit code returned."

        except subprocess.TimeoutExpired:
            response.update({
                "executed": False,
                "execution_error": f"Execution timed out after {timeout}s."
            })
        except Exception as e:
            response.update({
                "executed": False,
                "execution_error": str(e)
            })
    else:
        response.update({
            "executed": False,
            "execution_test": f"[MOCK] Would execute: {cmd}"
        })

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
    # Test cases
    test_commands = [
        "nmap -sV scanme.nmap.org",
        "nmap -p 80,443 example.com",
        "nmap -A 10.0.0.1",
        "nmap; rm -rf /",
        "nmap --script vuln 192.168.1.1",
        "nmap -sV 192.168.1.0/24",
        "nmap",
        "ping 8.8.8.8",
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
        
        status = "✅ VALID" if result.get('valid') else "❌ BLOCKED"
        print(f"\nStatus: {status}")
        
        if result.get('valid'):
            print(f"Syntax: {result.get('syntax')}")
            print(f"Targets: {result.get('targets')}")
            print(f"Flags: {result.get('flags')}")
            
            if 'security' in result:
                print(f"\n🔒 Security Analysis:")
                print(f"   Risk Score: {result['risk_score']}/100")
                print(f"   Risk Level: {result['risk_level'].upper()}")
                print(f"   Recommendation: {result['recommendation']}")
                
                if result.get('warnings'):
                    print(f"\n⚠️  Warnings:")
                    for warning in result['warnings']:
                        print(f"   - {warning}")
        else:
            print(f"\n❌ Error: {result.get('error')}")
            print(f"Severity: {result.get('severity')}")
            
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