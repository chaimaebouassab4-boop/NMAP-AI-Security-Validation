import re

def check_syntax_v1(command_str: str) -> dict:
    """Performs a basic structural and preliminary syntax check on the Nmap command string."""
    
    results = {
        "is_valid": True,
        "error_message": "",
        "details": [],
    }

    # 1. Check for basic Nmap existence (must start with a flag or target)
    if not command_str or not command_str.strip():
        results["is_valid"] = False
        results["error_message"] = "Command is empty or contains only whitespace."
        return results

    # 2. Check for required target (basic check: must contain at least one IP or hostname)
    # This regex is a simple check for common IP/hostname patterns, not a perfect validator.
    target_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\w+\.\w+)'
    if not re.search(target_pattern, command_str):
        results["is_valid"] = False
        results["error_message"] = "No obvious target IP address or hostname found."
        results["details"].append("Required for a valid Nmap scan.")
        
    # 3. Check for obvious dangerous commands (basic security)
    # This will be expanded in Week 2
    forbidden_flags = ['--script=shell', '-e', 'exec', 'system']
    for flag in forbidden_flags:
        if flag in command_str:
            results["is_valid"] = False
            results["error_message"] = f"Forbidden flag or script found: '{flag}'."
            results["details"].append("Flag indicates a potentially malicious or non-scan operation.")
            break
            
    if not results["is_valid"]:
        return results
        
    results["error_message"] = "Syntax check passed (v1)."
    return results

if __name__ == '__main__':
    print("--- Testing Syntax Checker V1 ---")
    
    # Test 1: Valid
    print("\nTest Valid:", check_syntax_v1("-sV 192.168.1.1"))
    
    # Test 2: Missing Target
    print("\nTest Missing Target:", check_syntax_v1("-sS -F"))
    
    # Test 3: Forbidden Flag
    print("\nTest Forbidden Flag:", check_syntax_v1("-sV 127.0.0.1 --script=shell"))