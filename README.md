# NMAP-AI-Security-Validation
Repository for the Validation Agent and Self-Correction Agent components of the NMAP-AI project. Includes implementation of the Model Context Protocol (MCP), syntax checking, execution simulation, and error analysis for command refinement.

# NMAP-AI-Validator

Repository for the **Validation Agent** and **Self-Correction Agent** components of the NMAP-AI project. This component implements the Model Context Protocol (MCP), syntax checking, execution simulation, and error analysis for command refinement.

## 🎯 Project Overview

As the **Validation & Security Engineer (Member 4)**, this repository focuses on implementing safety and correction mechanisms to ensure NMAP commands are syntactically correct, secure, and executable before deployment.

### Core Components

- **Validation Agent**: Performs syntax checking, safety validation, and execution simulation
- **Self-Correction Agent**: Analyzes errors and generates corrective feedback for command refinement
- **Docker Sandbox**: Isolated environment for safe command execution testing

---

## 🛡️ Development Timeline

### 📅 Week 1 — Foundations & Basic Validation

Establishing a secure environment for testing and implementing basic checks.

| Step | Task | Deliverable |
|------|------|-------------|
| **1** | **Environment Setup**: Install Nmap and set up Docker sandbox environment for safe command execution | **Commit 1**: Dockerfile/Scripts for Nmap execution sandbox |
| **2** | **Execution Script**: Write Python/shell script to execute mock Nmap commands in Docker and capture output/errors | **Commit 2**: `execute_sandbox.py` or similar script |
| **3** | **Syntax Checker v1**: Implement basic syntax rule checker to catch simple command format errors | **Commit 3**: Initial `syntax_checker.py` module |
| **4** | **Deliverable**: Demonstrate Validation v1 (syntax + execution test) working standalone with mock NMAP command input | **PR 1 Draft**: Draft PR demonstrating sandbox validation |

### 📅 Week 2 — Core Safety Features

Integrating security rules and preparing structured feedback.

| Step | Task | Deliverable |
|------|------|-------------|
| **5** | **Safety Checks**: Implement logic to identify and flag forbidden flags or unsafe target ranges (e.g., internal IPs) | **Commit 4**: `security_rules.py` module with blacklisted flags |
| **6** | **JSON Scoring Output**: Develop structure to return detailed JSON score including security risk and compliance information | **Commit 5**: Refactor validation output to structured JSON |
| **7** | **Deliverable**: Finalize Validation v2 scoring system, ready to accept input and return comprehensive safety score | **PR 2**: Submit PR for advanced validation scoring |

### 📅 Week 3 — Integration & Self-Correction Loop

Implementing the core loop logic for error detection and correction.

| Step | Task | Deliverable |
|------|------|-------------|
| **8** | **Execution Simulation**: Refine sandbox to perform full execution simulation on target VM/Container, capturing detailed runtime errors | **Commit 6**: Enhanced simulation scripts for error capture |
| **9** | **Error Analysis**: Implement Self-correction Agent logic to analyze errors and map them to corrective actions | **Commit 7**: `error_mapping_logic.py` module |
| **10** | **Fix Generation**: Implement logic to generate fixes and send feedback (e.g., request complexity level or parameter changes) | **Commit 8**: Self-Correction Agent core logic |
| **11** | **Deliverable**: Demonstrate auto correction cycle by successfully fixing an intentionally flawed NMAP command | **PR 3**: Submit PR for fully functional Validation and Self-Correction Agents |

### 📅 Week 4 — Polishing, Testing, and Reporting

Ensuring quality, performance, and comprehensive documentation.

| Step | Task | Deliverable |
|------|------|-------------|
| **12** | **Security & Performance Tests**: Conduct extensive security tests (injection attempts) and performance tests on validation speed | **Commit 9**: Test scripts and execution logs |
| **13** | **Success Metrics**: Prepare and analyze success metrics (false positive rate, correction success rate) | **Commit 10**: Final data for report |
| **14** | **Reporting**: Write validation and security section of final report, citing test results and architecture | **PR 4**: Final code review and report section |

---

## 🚀 Getting Started

### Prerequisites

- Docker
- Python 3.8+
- Nmap

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/NMAP-AI-Validator.git
cd NMAP-AI-Validator

# Set up Docker sandbox
docker build -t nmap-sandbox .

# Install Python dependencies
pip install -r requirements.txt
```

### Usage

## 🌐 API Usage

### Start the API
\`\`\`bash
python -m uvicorn api.main:app --reload
\`\`\`

### Access Swagger UI
Open browser: http://localhost:8000/docs

### Example Request
\`\`\`bash
curl -X POST "http://localhost:8000/api/v1/validate" \
  -H "Content-Type: application/json" \
  -d '{"command": "nmap -sV scanme.nmap.org"}'
\`\`\`
---

## 📊 Success Metrics

- **Syntax Detection Rate**: Percentage of invalid syntax caught
- **Security Flag Rate**: Percentage of unsafe commands blocked
- **False Positive Rate**: Commands incorrectly flagged as unsafe
- **Correction Success Rate**: Percentage of errors successfully auto-corrected
- **Validation Speed**: Average time to validate a command

---

## 🤝 Contributing

This repository is part of the NMAP-AI project. For integration with other components:

- **M3 (Command Generation)**: Receives validation feedback
- **M2 (Planning Agent)**: Provides context for validation rules
- **M1 (NLP)**: Supplies original user intent for validation context

---

## 📝 License

[Your License Here]

## 👤 chaimae

**Member 4** - Validation & Security Engineer

---

## 📚 Documentation

For detailed technical documentation, see the `/docs` folder in this repository.
