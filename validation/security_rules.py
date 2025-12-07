import ipaddress
import re

class SecurityRules:
    """
    Security rules engine for NMAP command validation.
    Identifies forbidden flags and unsafe target ranges.
    """
    
    # Blacklisted flags that pose security risks
    FORBIDDEN_FLAGS = {
        # Script execution risks
        '--script': 'Script execution not allowed',
        '-sC': 'Default script execution not allowed',
        
        # File operations
        '-oN': 'File output not allowed',
        '-oX': 'XML output not allowed',
        '-oG': 'Grepable output not allowed',
        '-oA': 'All format output not allowed',
        '--stylesheet': 'Stylesheet loading not allowed',
        
        # Dangerous scan types
        '--osscan-guess': 'Aggressive OS detection not allowed',
        '--badsum': 'Invalid checksum scanning not allowed',
        
        # Timing that could cause issues
        '-T5': 'Insane timing template not allowed (may cause network issues)',
    }
    
    # Warning flags (allowed but flagged)
    WARNING_FLAGS = {
        '-A': 'Aggressive scan (OS detection, version detection, script scanning, traceroute)',
        '-sS': 'SYN stealth scan (requires root privileges)',
        '-sU': 'UDP scan (slow and resource intensive)',
        '-O': 'OS detection (requires root privileges)',
        '-T4': 'Aggressive timing (may be detected by IDS/IPS)',
        '--traceroute': 'Traceroute enabled',
        '-sV': 'Service version detection',
        '-p-': 'Scanning all 65535 ports (very slow)',
    }
    
    # Unsafe IP ranges (RFC 1918 private networks, localhost, etc.)
    UNSAFE_RANGES = [
        '127.0.0.0/8',      # Loopback
        '10.0.0.0/8',       # Private network
        '172.16.0.0/12',    # Private network
        '192.168.0.0/16',   # Private network
        '169.254.0.0/16',   # Link-local
        '224.0.0.0/4',      # Multicast
        '240.0.0.0/4',      # Reserved
        '0.0.0.0/8',        # Current network
    ]
    
    # Allowed safe targets for testing
    SAFE_TEST_TARGETS = [
        'scanme.nmap.org',
        'scanme.org',
    ]
    
    def __init__(self, custom_forbidden_flags=None, custom_unsafe_ranges=None):
        """
        Initialize security rules with optional custom configurations.
        
        Args:
            custom_forbidden_flags: Additional flags to forbid (dict)
            custom_unsafe_ranges: Additional IP ranges to block (list)
        """
        self.forbidden_flags = self.FORBIDDEN_FLAGS.copy()
        self.unsafe_ranges = self.UNSAFE_RANGES.copy()
        
        if custom_forbidden_flags:
            self.forbidden_flags.update(custom_forbidden_flags)
        if custom_unsafe_ranges:
            self.unsafe_ranges.extend(custom_unsafe_ranges)
    
    def check_forbidden_flags(self, flags):
        """
        Check if command contains forbidden flags.
        
        Args:
            flags: List of flags from the command
            
        Returns:
            dict: {'violations': [...], 'has_violations': bool}
        """
        violations = []
        
        for flag in flags:
            for forbidden, reason in self.forbidden_flags.items():
                if flag.startswith(forbidden):
                    violations.append({
                        'flag': flag,
                        'reason': reason,
                        'severity': 'critical'
                    })
        
        return {
            'violations': violations,
            'has_violations': len(violations) > 0
        }
    
    def check_warning_flags(self, flags):
        """
        Check for flags that should generate warnings.
        
        Args:
            flags: List of flags from the command
            
        Returns:
            dict: {'warnings': [...], 'has_warnings': bool}
        """
        warnings = []
        
        for flag in flags:
            for warning_flag, reason in self.WARNING_FLAGS.items():
                if flag.startswith(warning_flag):
                    warnings.append({
                        'flag': flag,
                        'reason': reason,
                        'severity': 'warning'
                    })
        
        return {
            'warnings': warnings,
            'has_warnings': len(warnings) > 0
        }
    
    def is_ip_in_unsafe_range(self, ip_str):
        """
        Check if an IP address is in an unsafe range.
        
        Args:
            ip_str: IP address string (can include CIDR notation)
            
        Returns:
            tuple: (is_unsafe, reason)
        """
        try:
            # Handle CIDR notation
            if '/' in ip_str:
                target_network = ipaddress.ip_network(ip_str, strict=False)
            else:
                target_ip = ipaddress.ip_address(ip_str)
                target_network = ipaddress.ip_network(f"{ip_str}/32", strict=False)
            
            # Check against unsafe ranges
            for unsafe_range in self.unsafe_ranges:
                unsafe_network = ipaddress.ip_network(unsafe_range)
                
                # Check if target overlaps with unsafe range
                if target_network.overlaps(unsafe_network):
                    return True, f"Target in restricted range: {unsafe_range}"
            
            return False, None
            
        except ValueError as e:
            return False, None  # Not a valid IP, will be caught by other validation
    
    def is_safe_test_target(self, target):
        """
        Check if target is a known safe testing target.
        
        Args:
            target: Target hostname or IP
            
        Returns:
            bool: True if safe test target
        """
        return target.lower() in [t.lower() for t in self.SAFE_TEST_TARGETS]
    
    def check_targets(self, targets):
        """
        Validate all targets against security rules.
        
        Args:
            targets: List of target IPs/domains
            
        Returns:
            dict: {'unsafe_targets': [...], 'safe_targets': [...], 'has_unsafe': bool}
        """
        unsafe_targets = []
        safe_targets = []
        
        for target in targets:
            # Skip if it's a safe test target
            if self.is_safe_test_target(target):
                safe_targets.append({
                    'target': target,
                    'status': 'safe_test_target'
                })
                continue
            
            # Try to parse as IP
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
            if re.match(ip_pattern, target):
                is_unsafe, reason = self.is_ip_in_unsafe_range(target)
                if is_unsafe:
                    unsafe_targets.append({
                        'target': target,
                        'reason': reason,
                        'severity': 'high'
                    })
                else:
                    safe_targets.append({
                        'target': target,
                        'status': 'allowed'
                    })
            else:
                # Domain name - consider safe unless explicitly blocked
                safe_targets.append({
                    'target': target,
                    'status': 'domain_allowed'
                })
        
        return {
            'unsafe_targets': unsafe_targets,
            'safe_targets': safe_targets,
            'has_unsafe': len(unsafe_targets) > 0
        }
    
    def evaluate_command(self, flags, targets):
        """
        Comprehensive security evaluation of NMAP command.
        
        Args:
            flags: List of command flags
            targets: List of target IPs/domains
            
        Returns:
            dict: Complete security evaluation with risk score
        """
        # Check flags
        forbidden_result = self.check_forbidden_flags(flags)
        warning_result = self.check_warning_flags(flags)
        
        # Check targets
        target_result = self.check_targets(targets)
        
        # Calculate risk score (0-100)
        risk_score = 0
        risk_factors = []
        
        # Forbidden flags = +40 points each
        risk_score += len(forbidden_result['violations']) * 40
        if forbidden_result['has_violations']:
            risk_factors.append('forbidden_flags')
        
        # Warning flags = +10 points each
        risk_score += len(warning_result['warnings']) * 10
        if warning_result['has_warnings']:
            risk_factors.append('warning_flags')
        
        # Unsafe targets = +30 points each
        risk_score += len(target_result['unsafe_targets']) * 30
        if target_result['has_unsafe']:
            risk_factors.append('unsafe_targets')
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = 'critical'
        elif risk_score >= 40:
            risk_level = 'high'
        elif risk_score >= 20:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Determine if command should be allowed
        allow_execution = (
            not forbidden_result['has_violations'] and
            not target_result['has_unsafe']
        )
        
        return {
            'allowed': allow_execution,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'forbidden_flags': forbidden_result,
            'warnings': warning_result,
            'target_validation': target_result,
            'recommendation': self._get_recommendation(risk_level, allow_execution)
        }
    
    def _get_recommendation(self, risk_level, allow_execution):
        """Generate recommendation based on risk assessment."""
        if not allow_execution:
            return "BLOCK: Command contains forbidden elements and should not be executed."
        elif risk_level == 'critical' or risk_level == 'high':
            return "CAUTION: Command has high risk factors. Review carefully before execution."
        elif risk_level == 'medium':
            return "WARNING: Command has some risk factors. Proceed with caution."
        else:
            return "ALLOW: Command appears safe to execute."


# Example usage and testing
if __name__ == "__main__":
    rules = SecurityRules()
    
    # Test cases
    test_cases = [
        {
            'name': 'Safe scan of test target',
            'flags': ['-sV'],
            'targets': ['scanme.nmap.org']
        },
        {
            'name': 'Aggressive scan with warnings',
            'flags': ['-A', '-T4'],
            'targets': ['example.com']
        },
        {
            'name': 'Forbidden script execution',
            'flags': ['--script', 'vuln'],
            'targets': ['target.com']
        },
        {
            'name': 'Scan of internal network',
            'flags': ['-sV'],
            'targets': ['192.168.1.0/24']
        },
        {
            'name': 'Multiple violations',
            'flags': ['-A', '--script', 'default', '-oN', 'output.txt'],
            'targets': ['127.0.0.1']
        },
    ]
    
    print("=" * 70)
    print("SECURITY RULES EVALUATION TEST")
    print("=" * 70)
    
    for test in test_cases:
        print(f"\n📋 Test: {test['name']}")
        print(f"Flags: {test['flags']}")
        print(f"Targets: {test['targets']}")
        
        result = rules.evaluate_command(test['flags'], test['targets'])
        
        print(f"\n{'✅ ALLOWED' if result['allowed'] else '❌ BLOCKED'}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Risk Level: {result['risk_level'].upper()}")
        print(f"Recommendation: {result['recommendation']}")
        
        if result['forbidden_flags']['has_violations']:
            print(f"\n⛔ Forbidden Flags:")
            for v in result['forbidden_flags']['violations']:
                print(f"  - {v['flag']}: {v['reason']}")
        
        if result['warnings']['has_warnings']:
            print(f"\n⚠️  Warning Flags:")
            for w in result['warnings']['warnings']:
                print(f"  - {w['flag']}: {w['reason']}")
        
        if result['target_validation']['has_unsafe']:
            print(f"\n🚫 Unsafe Targets:")
            for t in result['target_validation']['unsafe_targets']:
                print(f"  - {t['target']}: {t['reason']}")
        
        print("-" * 70)