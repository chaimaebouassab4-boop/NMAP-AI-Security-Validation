from validator import validate_nmap_command
import sys
import json

def print_colored_result(result):
    """Print validation result with nice formatting."""
    print("\n" + "="*70)
    
    # Status
    if result.get('valid'):
        print("✅ STATUS: VALID - Command passed all validations")
    else:
        print("❌ STATUS: BLOCKED - Command failed validation")
    
    print("="*70)
    
    # Command details
    print(f"\nCommand: {result.get('command', 'N/A')}")
    
    if result.get('valid'):
        print(f"Syntax: {result.get('syntax')}")
        print(f"Targets: {', '.join(result.get('targets', []))}")
        print(f"Flags: {', '.join(result.get('flags', []))}")
        
        # Security analysis
        if 'security' in result:
            print(f"\n🔒 SECURITY ANALYSIS")
            print("-"*70)
            print(f"Risk Score: {result['risk_score']}/100")
            print(f"Risk Level: {result['risk_level'].upper()}")
            print(f"Recommendation: {result['recommendation']}")
            
            # Display warnings
            if result.get('warnings'):
                print(f"\n⚠️  WARNINGS:")
                for warning in result['warnings']:
                    print(f"  • {warning}")
            
            # Display safe targets
            if result['security']['target_validation']['safe_targets']:
                print(f"\n✓ Safe Targets:")
                for target in result['security']['target_validation']['safe_targets']:
                    print(f"  • {target['target']} ({target['status']})")
        
        # Execution info
        if result.get('executed'):
            print(f"\n⚙️  EXECUTION RESULT")
            print("-"*70)
            print(f"Return Code: {result.get('return_code')}")
            if result.get('stdout'):
                print(f"\nOutput:\n{result['stdout']}")
        else:
            print(f"\n{result.get('execution_test', 'Not executed')}")
    
    else:
        # Error details
        print(f"\n❌ ERROR: {result.get('error')}")
        print(f"Severity: {result.get('severity', 'unknown').upper()}")
        
        # Security issues
        if result.get('blocked_by_security') and 'security_issues' in result:
            print(f"\n🚫 SECURITY ISSUES:")
            for issue in result['security_issues']:
                print(f"  • {issue}")
            
            if 'security' in result:
                print(f"\nRisk Score: {result['security']['risk_score']}/100")
                print(f"Risk Level: {result['security']['risk_level'].upper()}")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    # Parse arguments
    if len(sys.argv) < 2:
        print("="*70)
        print("NMAP Command Validator with Security Rules")
        print("="*70)
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
        print("="*70)
        sys.exit(1)
    
    # Check for flags
    execute_real = "--execute" in sys.argv
    apply_security = "--no-security" not in sys.argv
    json_output = "--json" in sys.argv
    
    # Remove flags from argv
    args = [arg for arg in sys.argv[1:] if not arg.startswith('--')]
    
    # Build command
    cmd = " ".join(args)
    
    # Validate command
    result = validate_nmap_command(
        cmd, 
        execute_real=execute_real,
        apply_security_rules=apply_security
    )
    
    # Output result
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print_colored_result(result)
        
        # Show JSON tip
        if not result.get('valid'):
            print("\n💡 Tip: Use --json flag for machine-readable output")
    
    # Exit with appropriate code
    sys.exit(0 if result.get('valid') else 1)