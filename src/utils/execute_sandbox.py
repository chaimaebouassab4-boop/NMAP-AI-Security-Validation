import subprocess
import json
import shlex

def execute_nmap_command(command_str: str, timeout: int = 60) -> dict:
    """Executes an Nmap command and captures its output and status."""
    
    # 1. Clean and prepare the command for execution
    try:
        # shlex.split handles complex commands with quotes and spaces
        command_list = shlex.split(f"nmap {command_str}")
    except ValueError as e:
        return {
            "success": False,
            "error_type": "Command_Parsing_Error",
            "message": f"Failed to parse command string: {e}",
            "raw_output": "",
        }

    # 2. Execute the command
    try:
        # subprocess.run executes the command
        result = subprocess.run(
            command_list,
            capture_output=True,
            text=True,
            timeout=timeout,  # Enforce runtime timeout
            check=False        # Do not raise exception on non-zero exit code (Nmap uses exit codes for warnings)
        )

        return {
            "success": result.returncode == 0,
            "error_type": "None" if result.returncode == 0 else "Nmap_Runtime_Error",
            "message": "Execution successful." if result.returncode == 0 else f"Nmap exited with code {result.returncode}",
            "raw_output": result.stdout,
            "raw_error": result.stderr,
            "return_code": result.returncode,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error_type": "Timeout_Error",
            "message": f"Command timed out after {timeout} seconds.",
            "raw_output": "",
        }
    except Exception as e:
        return {
            "success": False,
            "error_type": "Internal_Execution_Error",
            "message": str(e),
            "raw_output": "",
        }

if __name__ == '__main__':
    # Example usage for testing (when run inside the Docker sandbox)
    print("--- Testing Execute Sandbox ---")
    
    # Test 1: Successful command
    result_success = execute_nmap_command("-F 127.0.0.1")
    print("\n[SUCCESS TEST] Status:", result_success['success'])
    print(json.dumps(result_success, indent=2))
    
    # Test 2: Invalid Nmap flag
    result_fail = execute_nmap_command("-Z") # -Z is not a valid flag
    print("\n[FAILURE TEST] Status:", result_fail['success'])
    print(json.dumps(result_fail, indent=2))