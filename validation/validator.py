import re
import shlex
import subprocess
import shutil
from datetime import datetime
from dataclasses import dataclass
from typing import Optional

try:
    from .security_rules import SecurityRules
except ImportError:
    # Mock si SecurityRules n'est pas disponible (pour tests)
    class SecurityRules:
        def evaluate_command(self, flags, targets):
            return {
                "allowed": True,
                "risk_score": 10,
                "risk_level": "low",
                "recommendation": "Commande sûre",
                "forbidden_flags": {"violations": []},
                "target_validation": {"unsafe_targets": []},
                "warnings": {"has_warnings": False, "warnings": []}
            }


@dataclass
class CommandCandidate:
    """Représente une commande générée avec son niveau de confiance."""
    command: str
    confidence: Optional[float] = None
    source_agent: Optional[str] = None


def validate_nmap_command(candidate: CommandCandidate, execute_real=False, timeout=60, apply_security_rules=True):
    """
    Validates and optionally executes NMAP commands with security checks.
    
    Args:
        candidate: CommandCandidate object containing command and metadata
        execute_real: If True, actually execute the command (default: False)
        timeout: Maximum execution time in seconds (default: 60)
        apply_security_rules: If True, apply advanced security rules (default: True)
    
    Returns:
        dict: Validation results with 'valid', 'syntax', security analysis, and execution info
    """
    cmd = candidate.command.strip()
    confidence = candidate.confidence or 0.0  # 0.0 par défaut
    source_agent = candidate.source_agent or "unknown"

    # Normalisation au cas où (si quelqu'un envoie sur 10)
    if confidence > 1.0:
        confidence /= 10.0

    response = {
        "command": cmd,
        "valid": False,
        "severity": "high",
        "risk_score": 0,
        "risk_level": "low",
        "issues": [],
        "warnings": [],
        "recommendation": "",
        "timestamp": datetime.now().isoformat(),
        "source_agent": source_agent,
        "generator_confidence": round(confidence, 3),
        "auto_validated": False
    }

    # 1. Basic input validation
    if not cmd or not isinstance(cmd, str):
        response["error"] = "Empty or invalid command."
        return response

    # 2. Block obvious command injection attempts
    injection_pattern = r"[;&|`]|(\$\()|(\|\|)|(&&)|(<)|(>)"
    if re.search(injection_pattern, cmd):
        response.update({
            "error": "Possible command injection detected.",
            "severity": "critical"
        })
        return response

    # 3. Safe parsing
    try:
        parts = shlex.split(cmd)
    except ValueError as e:
        response["error"] = f"Command parsing failed: {str(e)}"
        return response

    # 4. Ensure command is EXACTLY nmap
    if not parts or parts[0].lower() != "nmap":
        response["error"] = "Command must start with 'nmap'."
        return response

    # 5. Separate flags and targets safely
    flags = []
    targets = []
    skip_next = False
    for part in parts[1:]:
        if skip_next:
            skip_next = False
            continue

        if part.startswith("-"):
            flags.append(part)
            # Flags that take arguments
            if part in {"-p", "--ports", "--script", "--script-args", "-oA", "-oN", "-oX"}:
                skip_next = True
            continue
        else:
            targets.append(part)

    if not targets:
        response["error"] = "No scan target specified."
        response["severity"] = "medium"
        return response

    # 6. Validate targets (IPv4, CIDR, domain)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
    domain_pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)((\.[A-Za-z0-9-]{1,63}(?<!-))*(\.[A-Za-z]{2,}))?$'
    invalid_targets = []
    for target in targets:
        if not (re.match(ip_pattern, target) or re.match(domain_pattern, target)):
            invalid_targets.append(target)

    if invalid_targets:
        response["error"] = f"Invalid target format: {', '.join(invalid_targets)}"
        response["severity"] = "medium"
        return response

    # 7. Base valid response
    response.update({
        "valid": True,
        "syntax": "nmap [flags] <target>",
        "flags": flags,
        "targets": targets
    })

    # 8. Apply advanced security rules
    if apply_security_rules:
        rules = SecurityRules()
        security = rules.evaluate_command(flags, targets)
        response["security"] = security

        if not security["allowed"]:
            issues = [f"Forbidden flag {v['flag']}: {v['reason']}" for v in security["forbidden_flags"].get("violations", [])]
            issues += [f"Unsafe target {t['target']}: {t['reason']}" for t in security["target_validation"].get("unsafe_targets", [])]

            response.update({
                "valid": False,
                "blocked_by_security": True,
                "issues": issues,
                "error": "Command blocked by security rules.",
                "severity": security.get("risk_level", "high")
            })
            return response

        if security["warnings"]["has_warnings"]:
            response["warnings"] = [f"{w['flag']}: {w['reason']}" for w in security["warnings"]["warnings"]]

        # Risque calculé normalement par les règles
        base_risk_score = security["risk_score"]

        # === NOUVELLE LOGIQUE : Ajustement selon la confidence ===
        has_critical_issues = (
            security["forbidden_flags"].get("has_violations", False) or
            security["target_validation"].get("has_unsafe", False)
        )

        if confidence > 0.7 and not has_critical_issues:
            # On fait confiance à l'agent générateur
            if confidence > 0.9:
                final_risk_score = 2
            else:
                final_risk_score = 3
            
            response["risk_score"] = final_risk_score
            response["risk_level"] = "low"
            response["recommendation"] = (
                f"Validation automatique : haute confiance ({confidence:.2f}) de l'agent {source_agent}. "
                "Aucun élément interdit détecté. Commande considérée comme très sûre."
            )
            response["auto_validated"] = True
        else:
            # On garde le risque normal
            response["risk_score"] = base_risk_score
            response["risk_level"] = security["risk_level"]
            response["recommendation"] = security["recommendation"]
            response["auto_validated"] = False

        response["risk_score"] = max(0, min(100, response["risk_score"]))

    # 9. Execute command (optional)
    if execute_real:
        if not shutil.which("nmap"):
            response["execution_error"] = "Nmap is not installed or not in PATH."
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
            response["execution_error"] = f"Execution timed out after {timeout}s."
        except Exception as e:
            response["execution_error"] = str(e)
    else:
        response["execution_test"] = f"[MOCK] Would execute: {cmd}"

    return response


def validate_batch_commands(candidates, execute_real=False, apply_security_rules=True):
    """
    Validate multiple commands at once.
    
    Args:
        candidates: List of CommandCandidate objects
        execute_real: If True, execute commands
        apply_security_rules: If True, apply security rules
        
    Returns:
        List of validation results
    """
    results = []
    for candidate in candidates:
        result = validate_nmap_command(
            candidate,
            execute_real=execute_real,
            apply_security_rules=apply_security_rules
        )
        results.append(result)
    return results


def get_validation_summary(results):
    """
    Generate summary statistics from validation results.
    
    Args:
        results: List of validation results
        
    Returns:
        dict: Summary statistics
    """
    total = len(results)
    valid = sum(1 for r in results if r.get('valid', False))
    blocked = sum(1 for r in results if r.get('blocked_by_security', False))
    high_risk = sum(1 for r in results if r.get('risk_level') in ['high', 'critical'])
    
    return {
        "total_commands": total,
        "valid_commands": valid,
        "blocked_commands": blocked,
        "high_risk_commands": high_risk,
        "pass_rate": round((valid / total) * 100, 2) if total > 0 else 0
    }


if __name__ == "__main__":
    # Test cases
    test_candidates = [
        CommandCandidate("nmap -sV scanme.nmap.org", confidence=0.95, source_agent="AI_Agent_v1"),
        CommandCandidate("nmap -p 80,443 example.com", confidence=0.85, source_agent="AI_Agent_v1"),
        CommandCandidate("nmap -A 10.0.0.1", confidence=0.65, source_agent="AI_Agent_v1"),
        CommandCandidate("nmap; rm -rf /", confidence=0.95, source_agent="AI_Agent_v1"),
        CommandCandidate("nmap --script vuln 192.168.1.1", confidence=0.75, source_agent="AI_Agent_v1"),
        CommandCandidate("nmap -sV 192.168.1.0/24", confidence=0.50, source_agent="Manual"),
        CommandCandidate("nmap", confidence=0.90, source_agent="AI_Agent_v1"),
        CommandCandidate("ping 8.8.8.8", confidence=0.95, source_agent="AI_Agent_v1"),
    ]
    
    print("=" * 80)
    print("NMAP COMMAND VALIDATION WITH CONFIDENCE-BASED ADJUSTMENT")
    print("=" * 80)
    
    results = []
    for candidate in test_candidates:
        print(f"\n{'='*80}")
        print(f"Testing: {candidate.command}")
        print(f"Confidence: {candidate.confidence:.2f}, Source: {candidate.source_agent}")
        print('='*80)
        
        result = validate_nmap_command(candidate, execute_real=False, apply_security_rules=True)
        results.append(result)
        
        status = "✅ VALID" if result.get('valid') else "❌ BLOCKED"
        auto_val = " (AUTO-VALIDATED)" if result.get('auto_validated', False) else ""
        print(f"\nStatus: {status}{auto_val}")
        
        if result.get('valid'):
            print(f"Syntax: {result.get('syntax')}")
            print(f"Targets: {result.get('targets')}")
            print(f"Flags: {result.get('flags')}")
            
            if 'security' in result:
                print(f"\n🔒 Security Analysis:")
                print(f"   Risk Score: {result['risk_score']}/100")
                print(f"   Risk Level: {result['risk_level'].upper()}")
                print(f"   Recommendation: {result['recommendation']}")
                print(f"   Generator Confidence: {result['generator_confidence']}")
                print(f"   Source Agent: {result['source_agent']}")
                
                if result.get('warnings'):
                    print(f"\n⚠️ Warnings:")
                    for warning in result['warnings']:
                        print(f"   - {warning}")
        else:
            print(f"\n❌ Error: {result.get('error')}")
            print(f"Severity: {result.get('severity')}")
            
            if result.get('blocked_by_security') and 'issues' in result:
                print(f"\n🚫 Security Issues:")
                for issue in result['issues']:
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