import sys
import json
from validator import validate_nmap_command


def print_colored_result(result):
    """Print validation result with nice formatting."""
    print("\n" + "=" * 70)

    # Status
    if result.get("valid"):
        print("✅ STATUS: VALID - Command passed all validations")
    else:
        print("❌ STATUS: BLOCKED - Command failed validation")

    print("=" * 70)
    print(f"\nCommand: {result.get('command', 'N/A')}")

    if result.get("valid"):
        print(f"Syntax: {result.get('syntax', 'N/A')}")
        print(f"Targets: {', '.join(result.get('targets', []))}")
        print(f"Flags: {', '.join(result.get('flags', []))}")

        # Security analysis
        if "security" in result:
            print("\n🔒 SECURITY ANALYSIS")
            print("-" * 70)
            print(f"Risk Score: {result['security'].get('risk_score', 0)}/100")
            print(f"Risk Level: {result['security'].get('risk_level', 'unknown').upper()}")
            print(f"Recommendation: {result['security'].get('recommendation', 'N/A')}")

            if result.get("warnings"):
                print("\n⚠️ WARNINGS:")
                for w in result["warnings"]:
                    print(f"  • {w}")

    else:
        print(f"\n❌ ERROR: {result.get('error', 'Unknown error')}")
        print(f"Severity: {result.get('severity', 'unknown').upper()}")

        if result.get("security_issues"):
            print("\n🚫 SECURITY ISSUES:")
            for issue in result["security_issues"]:
                print(f"  • {issue}")

    print("\n" + "=" * 70)


def print_usage():
    print("=" * 70)
    print("NMAP Command Validator with Security Rules")
    print("=" * 70)
    print("\nUsage:")
    print('  python run_validation.py "nmap <args>" [options]')
    print("\nOptions:")
    print("  --execute           Actually execute the command (use with caution)")
    print("  --no-security       Skip security rules (basic validation only)")
    print("  --json              Output in JSON format")
    print("\nExamples:")
    print('  python run_validation.py "nmap -sV scanme.nmap.org"')
    print('  python run_validation.py "nmap -A 192.168.1.1" --execute')
    print('  python run_validation.py "nmap -p 80 example.com" --json')
    print("=" * 70)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    execute_real = "--execute" in sys.argv
    apply_security = "--no-security" not in sys.argv
    json_output = "--json" in sys.argv

    # Remove option flags
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    cmd = " ".join(args).strip()

    result = validate_nmap_command(
        cmd,
        execute_real=execute_real,
        apply_security_rules=apply_security,
    )

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print_colored_result(result)

    sys.exit(0 if result.get("valid") else 1)
