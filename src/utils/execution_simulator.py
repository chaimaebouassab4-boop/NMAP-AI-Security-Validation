#!/usr/bin/env python3
"""
Enhanced Execution Simulator
============================
Performs full execution simulation with detailed error capture and analysis.
"""

import subprocess
import json
import re
import time
import os
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from enum import Enum
import traceback


class ExecutionError(Enum):
    """Types of execution errors"""
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    TIMEOUT = "timeout"
    INVALID_ARGUMENT = "invalid_argument"
    PORT_SPECIFICATION = "port_specification"
    SCRIPT_NOT_FOUND = "script_not_found"
    DNS_RESOLUTION = "dns_resolution"
    RESOURCE_LIMIT = "resource_limit"
    SYNTAX_ERROR = "syntax_error"
    UNKNOWN = "unknown"


class ErrorPattern:
    """Error pattern matching for Nmap output"""
    
    PATTERNS = [
        # Permission errors
        (r"Operation not permitted", ExecutionError.PERMISSION_DENIED, "requires_root"),
        (r"requires root privileges", ExecutionError.PERMISSION_DENIED, "requires_root"),
        (r"PCAP permission problem", ExecutionError.PERMISSION_DENIED, "pcap_permission"),
        (r"socket troubles", ExecutionError.PERMISSION_DENIED, "socket_permission"),
        
        # Network errors
        (r"Failed to resolve", ExecutionError.DNS_RESOLUTION, "dns_failure"),
        (r"Could not resolve hostname", ExecutionError.DNS_RESOLUTION, "hostname_invalid"),
        (r"No route to host", ExecutionError.NETWORK_UNREACHABLE, "no_route"),
        (r"Host seems down", ExecutionError.NETWORK_UNREACHABLE, "host_down"),
        (r"Network is unreachable", ExecutionError.NETWORK_UNREACHABLE, "network_unreachable"),
        
        # Argument errors
        (r"Invalid argument", ExecutionError.INVALID_ARGUMENT, "invalid_arg"),
        (r"Unknown argument", ExecutionError.INVALID_ARGUMENT, "unknown_arg"),
        (r"Illegal port number", ExecutionError.PORT_SPECIFICATION, "illegal_port"),
        (r"Your port specifications are illegal", ExecutionError.PORT_SPECIFICATION, "port_spec_error"),
        
        # Script errors
        (r"NSE: Failed to load.*script", ExecutionError.SCRIPT_NOT_FOUND, "script_load_fail"),
        (r"script .* does not exist", ExecutionError.SCRIPT_NOT_FOUND, "script_missing"),
        (r"Unknown script", ExecutionError.SCRIPT_NOT_FOUND, "unknown_script"),
        
        # Resource errors
        (r"memory allocation problem", ExecutionError.RESOURCE_LIMIT, "memory_limit"),
        (r"Too many open files", ExecutionError.RESOURCE_LIMIT, "file_limit"),
        
        # Syntax errors
        (r"nmap: unrecognized option", ExecutionError.SYNTAX_ERROR, "unrecognized_option"),
        (r"option requires an argument", ExecutionError.SYNTAX_ERROR, "missing_argument"),
    ]


class ExecutionSimulator:
    """Enhanced execution simulator with detailed error capture"""
    
    def __init__(self, docker_image: str = "nmap-ai-sandbox:latest"):
        self.docker_image = docker_image
        self.timeout = 300
        self.error_patterns = ErrorPattern.PATTERNS
        
    def simulate_execution(self, command: str, target_type: str = "container") -> Dict[str, Any]:
        """
        Simulate Nmap execution with comprehensive error capture
        
        Args:
            command: Nmap command to execute
            target_type: Type of target (container, vm, network)
            
        Returns:
            Detailed execution results with error analysis
        """
        start_time = time.time()
        
        # Initialize result structure
        result = {
            "command": command,
            "timestamp": datetime.utcnow().isoformat(),
            "target_type": target_type,
            "execution": {
                "started": True,
                "completed": False,
                "duration": 0,
                "exit_code": None,
                "stdout": "",
                "stderr": ""
            },
            "errors": [],
            "warnings": [],
            "metrics": {
                "packets_sent": 0,
                "packets_received": 0,
                "hosts_up": 0,
                "ports_scanned": 0,
                "services_detected": 0
            },
            "suggestions": []
        }
        
        try:
            # Build Docker command with enhanced monitoring
            docker_cmd = self._build_docker_command(command, target_type)
            
            # Execute with detailed monitoring
            process = subprocess.Popen(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Capture output in real-time
            stdout_lines = []
            stderr_lines = []
            
            # Set timeout
            timeout_time = time.time() + self.timeout
            
            while True:
                # Check timeout
                if time.time() > timeout_time:
                    process.terminate()
                    result["errors"].append({
                        "type": ExecutionError.TIMEOUT.value,
                        "message": f"Execution timed out after {self.timeout}s",
                        "severity": "critical"
                    })
                    break
                
                # Check if process finished
                if process.poll() is not None:
                    break
                
                # Read available output
                stdout_line = process.stdout.readline()
                if stdout_line:
                    stdout_lines.append(stdout_line.strip())
                    self._parse_runtime_output(stdout_line, result)
                
                stderr_line = process.stderr.readline()
                if stderr_line:
                    stderr_lines.append(stderr_line.strip())
                    self._parse_error_output(stderr_line, result)
                
                time.sleep(0.1)
            
            # Get remaining output
            remaining_stdout, remaining_stderr = process.communicate()
            if remaining_stdout:
                stdout_lines.extend(remaining_stdout.strip().split('\n'))
            if remaining_stderr:
                stderr_lines.extend(remaining_stderr.strip().split('\n'))
            
            # Store results
            result["execution"]["stdout"] = '\n'.join(stdout_lines)
            result["execution"]["stderr"] = '\n'.join(stderr_lines)
            result["execution"]["exit_code"] = process.returncode
            result["execution"]["completed"] = True
            result["execution"]["duration"] = time.time() - start_time
            
            # Analyze complete output
            self._analyze_complete_output(result)
            
            # Generate suggestions based on errors
            self._generate_suggestions(result)
            
        except Exception as e:
            result["errors"].append({
                "type": ExecutionError.UNKNOWN.value,
                "message": f"Simulation error: {str(e)}",
                "severity": "critical",
                "traceback": traceback.format_exc()
            })
            result["execution"]["completed"] = False
            result["execution"]["duration"] = time.time() - start_time
        
        return result
    
    def _build_docker_command(self, command: str, target_type: str) -> List[str]:
        """Build Docker command with appropriate settings"""
        docker_cmd = [
            "docker", "run",
            "--rm",
            "--name", f"nmap-sim-{int(time.time())}",
            "--network", "nmap-ai-net",
            "--cpus", "0.5",
            "--memory", "512m",
            "--cap-drop", "ALL"
        ]
        
        # Add capabilities based on command analysis
        if self._needs_root_capability(command):
            docker_cmd.extend(["--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN"])
        
        # Add volume for scripts if needed
        if "--script" in command:
            docker_cmd.extend(["-v", "/usr/share/nmap/scripts:/usr/share/nmap/scripts:ro"])
        
        # Add the image and command
        docker_cmd.extend([self.docker_image, "bash", "-c", command])
        
        return docker_cmd
    
    def _needs_root_capability(self, command: str) -> bool:
        """Check if command needs root capabilities"""
        root_indicators = [
            '-sS', '-sA', '-sW', '-sM', '-sN', '-sF', '-sX',  # Stealth scans
            '-sU',  # UDP scan
            '-sO',  # Protocol scan
            '-O',   # OS detection
            '-PE', '-PP', '-PM'  # ICMP scans
        ]
        return any(indicator in command for indicator in root_indicators)
    
    def _parse_runtime_output(self, line: str, result: Dict[str, Any]):
        """Parse runtime output for metrics"""
        # Parse scan progress
        progress_match = re.search(r'(\d+)% done', line)
        if progress_match:
            result["metrics"]["scan_progress"] = int(progress_match.group(1))
        
        # Parse host discovery
        if "Host is up" in line:
            result["metrics"]["hosts_up"] += 1
        
        # Parse port discovery
        port_match = re.search(r'(\d+)/tcp\s+open', line)
        if port_match:
            result["metrics"]["ports_scanned"] += 1
            
        # Parse service detection
        if "Service Info:" in line:
            result["metrics"]["services_detected"] += 1
    
    def _parse_error_output(self, line: str, result: Dict[str, Any]):
        """Parse error output in real-time"""
        for pattern, error_type, subtype in self.error_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                error_entry = {
                    "type": error_type.value,
                    "subtype": subtype,
                    "message": line.strip(),
                    "severity": self._determine_severity(error_type),
                    "timestamp": datetime.utcnow().isoformat()
                }
                result["errors"].append(error_entry)
                break
        else:
            # Check for warnings
            if any(word in line.lower() for word in ["warning", "warn", "caution"]):
                result["warnings"].append({
                    "message": line.strip(),
                    "timestamp": datetime.utcnow().isoformat()
                })
    
    def _determine_severity(self, error_type: ExecutionError) -> str:
        """Determine error severity"""
        critical_errors = [
            ExecutionError.PERMISSION_DENIED,
            ExecutionError.SYNTAX_ERROR,
            ExecutionError.TIMEOUT
        ]
        
        high_errors = [
            ExecutionError.NETWORK_UNREACHABLE,
            ExecutionError.DNS_RESOLUTION,
            ExecutionError.SCRIPT_NOT_FOUND
        ]
        
        if error_type in critical_errors:
            return "critical"
        elif error_type in high_errors:
            return "high"
        else:
            return "medium"
    
    def _analyze_complete_output(self, result: Dict[str, Any]):
        """Analyze complete output for patterns and issues"""
        full_output = result["execution"]["stdout"] + "\n" + result["execution"]["stderr"]
        
        # Check for successful scan indicators
        if "Nmap done:" in full_output:
            scan_summary = re.search(
                r'Nmap done: (\d+) IP address.*\((\d+) host.*up\).*in ([\d.]+) seconds',
                full_output
            )
            if scan_summary:
                result["metrics"]["total_ips"] = int(scan_summary.group(1))
                result["metrics"]["hosts_up"] = int(scan_summary.group(2))
                result["metrics"]["scan_time"] = float(scan_summary.group(3))
        
        # Check exit code interpretation
        if result["execution"]["exit_code"] != 0:
            self._interpret_exit_code(result["execution"]["exit_code"], result)
    
    def _interpret_exit_code(self, exit_code: int, result: Dict[str, Any]):
        """Interpret Nmap exit codes"""
        exit_code_meanings = {
            1: "General runtime error",
            2: "Parse error (invalid command line)",
            3: "No targets specified",
            255: "Killed by signal"
        }
        
        if exit_code in exit_code_meanings:
            result["errors"].append({
                "type": ExecutionError.UNKNOWN.value,
                "message": f"Exit code {exit_code}: {exit_code_meanings[exit_code]}",
                "severity": "high"
            })
    
    def _generate_suggestions(self, result: Dict[str, Any]):
        """Generate fix suggestions based on errors"""
        for error in result["errors"]:
            error_type = error["type"]
            subtype = error.get("subtype", "")
            
            if error_type == ExecutionError.PERMISSION_DENIED.value:
                if subtype == "requires_root":
                    result["suggestions"].append({
                        "error_ref": error,
                        "fix_type": "alternative_scan",
                        "suggestion": "Use -sT (TCP connect) instead of SYN scan",
                        "alternative_command": self._generate_alternative_command(
                            result["command"], "permission"
                        )
                    })
                
            elif error_type == ExecutionError.DNS_RESOLUTION.value:
                result["suggestions"].append({
                    "error_ref": error,
                    "fix_type": "skip_resolution",
                    "suggestion": "Add -n flag to skip DNS resolution",
                    "alternative_command": result["command"].replace("nmap", "nmap -n")
                })
                
            elif error_type == ExecutionError.PORT_SPECIFICATION.value:
                result["suggestions"].append({
                    "error_ref": error,
                    "fix_type": "fix_port_syntax",
                    "suggestion": "Check port specification syntax (e.g., -p 80,443 or -p 1-1000)",
                    "documentation": "https://nmap.org/book/port-scanning-basics.html"
                })
    
    def _generate_alternative_command(self, command: str, issue_type: str) -> str:
        """Generate alternative command based on issue type"""
        if issue_type == "permission":
            # Replace stealth scans with connect scan
            alternatives = {
                "-sS": "-sT",
                "-sA": "-sT",
                "-sF": "-sT",
                "-sX": "-sT",
                "-sN": "-sT"
            }
            
            alt_command = command
            for old, new in alternatives.items():
                if old in alt_command:
                    alt_command = alt_command.replace(old, new)
                    break
            
            return alt_command
        
        return command


def demo_enhanced_simulation():
    """Demonstrate enhanced execution simulation"""
    simulator = ExecutionSimulator()
    
    test_scenarios = [
        {
            "name": "Permission Error",
            "command": "nmap -sS -p 80 scanme.nmap.org",
            "expected_error": "permission_denied"
        },
        {
            "name": "Invalid Port Specification",
            "command": "nmap -p 80-70 scanme.nmap.org",
            "expected_error": "port_specification"
        },
        {
            "name": "DNS Resolution Failure",
            "command": "nmap nonexistent.invalid.domain",
            "expected_error": "dns_resolution"
        },
        {
            "name": "Script Not Found",
            "command": "nmap --script nonexistent-script scanme.nmap.org",
            "expected_error": "script_not_found"
        },
        {
            "name": "Success Case",
            "command": "nmap -sT -p 80,443 scanme.nmap.org",
            "expected_error": None
        }
    ]
    
    print("🔬 Enhanced Execution Simulator Demo")
    print("=" * 60)
    
    results = []
    
    for scenario in test_scenarios:
        print(f"\n📋 Testing: {scenario['name']}")
        print(f"Command: {scenario['command']}")
        print("-" * 40)
        
        result = simulator.simulate_execution(scenario['command'])
        results.append(result)
        
        # Display summary
        print(f"Exit Code: {result['execution']['exit_code']}")
        print(f"Duration: {result['execution']['duration']:.2f}s")
        
        if result['errors']:
            print(f"Errors Found: {len(result['errors'])}")
            for error in result['errors']:
                print(f"  - {error['type']}: {error['message'][:50]}...")
        
        if result['suggestions']:
            print(f"Suggestions: {len(result['suggestions'])}")
            for suggestion in result['suggestions']:
                print(f"  - {suggestion['suggestion']}")
        
        print(f"Success: {'✅' if not result['errors'] else '❌'}")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"simulation_results_{timestamp}.json"
    
    os.makedirs("results", exist_ok=True)
    with open(f"results/{filename}", 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: results/{filename}")


if __name__ == "__main__":
    demo_enhanced_simulation()
