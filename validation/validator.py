import re
import shlex
import subprocess
import shutil
from security_rules import SecurityRules


def validate_nmap_command(cmd: str, execute_real=False, timeout=60, apply_security_rules=True):
    """
    Validates and optionally executes NMAP commands with security checks.
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
    # 3️⃣ Safe parsing (FIXES YOUR CRASH)
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
