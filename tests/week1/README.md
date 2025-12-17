# NMAP-AI Week 1 Deliverables

## 📅 Week 1 — Foundations & Basic Validation

This directory contains all deliverables for Week 1 of the NMAP-AI project.

### 🎯 Completed Tasks

#### ✅ Commit 1: Environment Setup
- **Dockerfile**: `docker/Dockerfile` - Ubuntu-based sandbox with Nmap installed
- **Docker Compose**: `docker/docker-compose.yml` - Complete sandbox environment with test target
- **Build Script**: `docker/build.sh` - Easy build process
- **Requirements**: `docker/requirements.txt` - Python dependencies

#### ✅ Commit 2: Execution Script
- **Main Script**: `src/utils/execute_sandbox.py` - Python script for Docker-based Nmap execution
- **Features**:
  - Docker environment checks
  - Automatic capability detection (root requirements)
  - Resource limits (CPU, memory, timeout)
  - JSON output format
  - Result saving

#### ✅ Commit 3: Syntax Checker v1
- **Module**: `src/utils/syntax_checker.py` - Basic Nmap syntax validation
- **Features**:
  - Flag validation
  - Parameter checking
  - Conflict detection
  - Target validation (IP, hostname, CIDR)
  - Error suggestions

#### ✅ PR 1 Draft: Validation v1 Demo
- **Demo Script**: `tests/week1/validation_v1_demo.py` - Integrated validation demo
- **Features**:
  - Syntax checking + sandbox execution
  - Multiple test cases
  - Results saving
  - Summary reporting

### 🚀 Quick Start

```bash
# Run the quick start script
./week1_quickstart.sh

# Or manually:

# 1. Build Docker sandbox
cd docker && ./build.sh

# 2. Test syntax checker
python3 src/utils/syntax_checker.py

# 3. Test sandbox execution
python3 src/utils/execute_sandbox.py "nmap -sT -p 80 scanme.nmap.org"

# 4. Run full demo
python3 tests/week1/validation_v1_demo.py
```

### 📁 File Structure

```
nmap-ai/
├── docker/
│   ├── Dockerfile              # Sandbox container definition
│   ├── docker-compose.yml      # Complete environment setup
│   ├── build.sh               # Build script
│   ├── requirements.txt       # Python dependencies
│   └── scripts/
│       └── sandbox_wrapper.py # Enhanced security wrapper
├── src/
│   ├── agents/
│   │   └── validation_agent.py # Skeleton for full agent
│   └── utils/
│       ├── execute_sandbox.py  # Docker execution wrapper
│       └── syntax_checker.py   # Syntax validation module
├── tests/
│   └── week1/
│       └── validation_v1_demo.py # Integration demo
├── docs/
│   ├── policies/
│   │   └── safety_policy.md    # Safety rules and restrictions
│   └── research/
│       └── nmap_dangerous_flags.md # Flag research document
└── week1_quickstart.sh         # Quick start script
```

### 🧪 Test Commands

The demo includes various test cases:

```bash
# Valid commands
nmap -sT -p 80,443 scanme.nmap.org      # Basic TCP scan
nmap -sS -O 192.168.1.1                 # SYN scan with OS detection
nmap -p 1-100 -T3 --max-rate 50 example.com  # Rate-limited scan

# Invalid syntax examples (caught by validator)
nmap                                     # Missing target
nmap -sT -sS example.com                # Conflicting flags
nmap -xyz 192.168.1.1                   # Invalid flag
nmap 999.999.999.999                    # Invalid IP
```

### 📊 Demo Output Example

```
🚀 NMAP-AI Validation v1 Demo
📅 Week 1 Deliverable
🕐 2024-12-06 14:30:00
============================================================

📝 Running test cases...

============================================================
🔍 Processing: nmap -sT -p 80,443 scanme.nmap.org
============================================================

📋 Step 1: Syntax Validation
   ✅ Syntax is valid

🐳 Step 2: Sandbox Execution
🔓 Adding NET_RAW and NET_ADMIN capabilities
🚀 Executing: nmap -sT -p 80,443 scanme.nmap.org
✅ Execution completed in 2.34s
📊 Exit code: 0

📊 VALIDATION SUMMARY
============================================================
Total commands tested: 8
Valid syntax: 4/8
Commands executed: 3
Successful executions: 3

✅ Week 1 Validation Demo Complete!
```

### 🔒 Security Features

1. **Docker Sandbox**:
   - Resource limits (CPU: 50%, Memory: 512MB)
   - Network isolation
   - Capability restrictions
   - No persistent storage

2. **Syntax Validation**:
   - Flag validation
   - Parameter type checking
   - Conflict detection
   - Target format validation

3. **Safety Measures**:
   - Command timeout (300s)
   - Root privilege detection
   - Execution logging
   - Error handling

### 📝 PR Checklist

- [x] Docker environment setup and tested
- [x] Execution script handles various Nmap commands
- [x] Syntax checker catches common errors
- [x] Integration demo shows end-to-end validation
- [x] Documentation complete
- [x] All scripts are executable
- [x] Test results saved to `results/` directory

### 🎯 Next Week Preview

Week 2 will build on this foundation:
- Enhanced syntax checking with safety rules
- Risk scoring system
- Command modification for safety
- Integration with main validation agent
