# 🔄 Week 3: Integration & Self-Correction Loop
### Error Detection • Correction Logic • M3 Integration • Iterative Refinement

---

## 📋 Week Overview

**Goal**: Implement the core self-correction loop that enables automated error detection, analysis, and command refinement through collaboration with M3 (Command Generation Agent).

**Duration**: Week 3 (Days 15-21)  
**Status**: 🟡 In Progress  
**Collaboration**: **M4 (You) + M3 (LLM Engineer)**

---

## 🎯 Learning Objectives

By the end of Week 3, you will have:

✅ Enhanced sandbox execution with detailed error capture  
✅ Implemented intelligent error analysis and mapping  
✅ Created fix generation logic for command refinement  
✅ Established M3-M4 integration pipeline  
✅ Demonstrated working auto-correction cycle  
✅ Validated iterative refinement process

---

## 📁 Week 3 Repository Structure

```
03-self-correction-agent/
│
├── step8-execution-simulation/
│   ├── enhanced_sandbox.py
│   ├── error_capture.py
│   ├── vm_simulation.py
│   └── README.md
│
├── step9-error-analysis/
│   ├── error_mapping_logic.py
│   ├── error_taxonomy.json
│   ├── corrective_actions.py
│   └── README.md
│
├── step10-fix-generation/
│   ├── fix_generator.py
│   ├── m3_feedback_interface.py
│   ├── complexity_adjuster.py
│   └── README.md
│
├── step11-integration-demo/
│   ├── correction_cycle.py
│   ├── test_scenarios.py
│   ├── demo_flawed_commands.json
│   └── README.md
│
├── m3_m4_integration/
│   ├── api_contract.md
│   ├── feedback_schema.json
│   ├── integration_tests.py
│   └── README.md
│
└── README.md (this file)
```

---

## 🚀 Step-by-Step Implementation

### **Step 8: Execution Simulation** 🐳
**Duration**: Days 15-16  
**Commit**: `#6 - Enhanced simulation scripts for error capture`

#### 📝 Objectives
- Refine Docker sandbox for full execution simulation
- Capture detailed runtime errors from target VM/Container
- Log system-level failures and resource issues
- Create comprehensive error reporting

#### 🔨 Implementation Tasks

```python
# enhanced_sandbox.py - Key Features

class EnhancedSandbox:
    """
    Advanced sandbox for NMAP command execution with detailed error capture
    """
    def __init__(self):
        self.error_categories = {
            'SYNTAX_ERROR': [],
            'PERMISSION_DENIED': [],
            'NETWORK_UNREACHABLE': [],
            'DEPENDENCY_MISSING': [],
            'TIMEOUT': [],
            'RESOURCE_LIMIT': []
        }
    
    def execute_with_capture(self, command, target_vm):
        """
        Execute command and capture all error types
        """
        # Docker execution with full logging
        # System-level error capture
        # Resource monitoring
        # Return structured error report
```

#### ✅ Deliverables
- [ ] `enhanced_sandbox.py` - Advanced execution engine
- [ ] `error_capture.py` - Comprehensive error logging
- [ ] `vm_simulation.py` - Target environment simulation
- [ ] Test suite with 10+ error scenarios
- [ ] Error capture documentation

#### 📊 Success Metrics
| Metric | Target | 
|--------|--------|
| Error capture rate | >95% |
| False negatives | <3% |
| Execution time | <2s per command |
| Resource isolation | 100% |

---

### **Step 9: Error Analysis** 🔍
**Duration**: Days 17-18  
**Commit**: `#7 - error_mapping_logic.py module`

#### 📝 Objectives
- Implement Self-correction Agent's error analysis logic
- Map runtime errors to specific corrective actions
- Create error taxonomy and classification system
- Design intelligent error-to-fix mapping

#### 🔨 Implementation Tasks

```python
# error_mapping_logic.py - Core Logic

class ErrorAnalyzer:
    """
    Analyzes execution errors and maps them to corrective actions
    """
    
    ERROR_TAXONOMY = {
        'DEPENDENCY_MISSING': {
            'triggers': ['command not found', 'package not installed'],
            'action': 'install_dependency',
            'severity': 'HIGH'
        },
        'REQUIRES_ROOT': {
            'triggers': ['permission denied', 'requires root'],
            'action': 'add_sudo_or_privilege',
            'severity': 'MEDIUM'
        },
        'INVALID_FLAG': {
            'triggers': ['unknown option', 'invalid flag'],
            'action': 'remove_flag_or_replace',
            'severity': 'HIGH'
        },
        'TARGET_UNREACHABLE': {
            'triggers': ['network unreachable', 'host down'],
            'action': 'verify_target_or_adjust_timeout',
            'severity': 'LOW'
        }
    }
    
    def analyze(self, error_output):
        """
        Analyze error and return corrective action
        """
        # Pattern matching against taxonomy
        # Classify error type
        # Determine severity
        # Return structured feedback for M3
```

#### ✅ Deliverables
- [ ] `error_mapping_logic.py` - Main analysis engine
- [ ] `error_taxonomy.json` - Comprehensive error database
- [ ] `corrective_actions.py` - Action mapping system
- [ ] Unit tests for 20+ error types
- [ ] Error analysis documentation

#### 📊 Key Error Categories

| Error Type | Example | Corrective Action |
|------------|---------|-------------------|
| **Syntax Error** | Invalid flag | Remove/replace flag |
| **Permission Denied** | Requires root | Add privilege escalation |
| **Dependency Missing** | nmap not found | Install package |
| **Network Error** | Host unreachable | Adjust timeout/target |
| **Resource Limit** | Memory exceeded | Reduce scan scope |

---

### **Step 10: Fix Generation** 🛠️
**Duration**: Days 18-19  
**Commit**: `#8 - Self-Correction Agent core logic`

#### 📝 Objectives
- Implement fix generation logic
- Create M3 feedback interface for **iterative refinement**
- Design complexity level adjustment system
- Establish **M3-M4 collaboration protocol**

#### 🔨 Implementation Tasks

```python
# fix_generator.py - Fix Generation Logic

class FixGenerator:
    """
    Generates fixes and sends feedback to M3 for command refinement
    """
    
    def generate_fix(self, error_analysis, original_command):
        """
        Generate fix based on error analysis
        """
        fix_strategy = self._determine_strategy(error_analysis)
        
        if fix_strategy == 'ADJUST_COMPLEXITY':
            return self._request_complexity_change(error_analysis)
        elif fix_strategy == 'MODIFY_PARAMETERS':
            return self._suggest_parameter_change(error_analysis)
        elif fix_strategy == 'REGENERATE':
            return self._request_m3_regeneration(error_analysis)
    
    def send_to_m3(self, feedback):
        """
        Send structured feedback to M3 for iterative refinement
        """
        # API call to M3's Hard Agent (Diffusion-based synthesis)
        # Request complexity adjustment
        # Request parameter modification
        # Return refined command from M3
```

```python
# m3_feedback_interface.py - M3-M4 Integration

class M3FeedbackInterface:
    """
    Interface for M4 → M3 communication (Self-Correction → Command Generation)
    """
    
    def request_refinement(self, feedback_data):
        """
        Send feedback to M3's Generative Agents for iterative refinement
        
        Feedback Structure:
        {
            'command_id': 'uuid',
            'error_type': 'PERMISSION_DENIED',
            'severity': 'MEDIUM',
            'suggested_action': 'add_unprivileged_flag',
            'complexity_adjustment': 'REDUCE',  # For Hard Agent
            'parameter_changes': {
                'scan_type': '-sV' → '-sT',
                'timing': 'add_T3'
            }
        }
        """
        response = requests.post(
            'http://m3-api:8000/refine',
            json=feedback_data
        )
        return response.json()  # Refined command from M3
```

#### 🔗 M3-M4 Collaboration Flow

```
┌─────────────────────────────────────────────────────────────┐
│                   SELF-CORRECTION CYCLE                     │
└─────────────────────────────────────────────────────────────┘

   M3 (Command Generation)          M4 (Validation & Correction)
   ═════════════════════             ═══════════════════════════

1. Generate Command ─────────────────────────────────> Validate
   │                                                        │
   │                                                        ▼
   │                                                   Execute in
   │                                                   Sandbox
   │                                                        │
   │                                                        ▼
   │                                                   Error Found?
   │                                                        │
   │                                                        ▼
   │                                               Analyze Error
   │                                                        │
   │                                                        ▼
   │ <──────────────── Send Feedback ──────────── Generate Fix
   │     (Complexity adjustment,                           │
   │      Parameter changes)                               │
   │                                                        │
   ▼                                                        │
2. Refine Command                                          │
   (Hard Agent: Diffusion-based)                          │
   │                                                        │
   │ ──────────────────────────────────────────────────────▼
   │                                               Validate Again
   │                                                        │
   │ <──────────────────────────────────────────────────────┘
   │                    (Repeat if needed)
   ▼
3. Final Validated Command ─────────────────────> Success! ✓
```

#### ✅ Deliverables
- [ ] `fix_generator.py` - Core fix generation logic
- [ ] `m3_feedback_interface.py` - M3 integration API
- [ ] `complexity_adjuster.py` - Complexity level controller
- [ ] API contract documentation with M3
- [ ] Integration test suite

#### 📋 Feedback Schema for M3

```json
{
  "feedback_version": "1.0",
  "command_id": "cmd_12345",
  "original_command": "nmap -sS -O 192.168.1.1",
  "error_analysis": {
    "error_type": "PERMISSION_DENIED",
    "severity": "MEDIUM",
    "error_message": "You do not have permission for raw socket manipulation",
    "timestamp": "2025-01-15T10:30:00Z"
  },
  "correction_request": {
    "action": "ADJUST_COMPLEXITY",
    "complexity_change": "REDUCE",
    "suggested_modifications": [
      {
        "type": "REMOVE_FLAG",
        "flag": "-O",
        "reason": "OS detection requires root privileges"
      },
      {
        "type": "CHANGE_SCAN_TYPE",
        "from": "-sS",
        "to": "-sT",
        "reason": "TCP connect scan does not require privileges"
      }
    ],
    "alternative_approach": "Use unprivileged scanning techniques"
  },
  "expected_response": {
    "refined_command": "string",
    "refinement_confidence": "float",
    "changes_applied": "array"
  }
}
```

---

### **Step 11: Demonstration & Integration** 🎬
**Duration**: Days 20-21  
**Commit**: `PR #3 - Fully functional Validation and Self-Correction Agents`

#### 📝 Objectives
- Demonstrate complete auto-correction cycle
- Test with intentionally flawed NMAP commands
- Validate M3-M4 integration
- Document success metrics and edge cases

#### 🔨 Implementation Tasks

```python
# correction_cycle.py - Full Cycle Demonstration

class CorrectionCycleDemo:
    """
    Demonstrates the complete auto-correction workflow
    """
    
    def run_demo(self, flawed_command):
        """
        Execute full correction cycle:
        1. Validate command (M4)
        2. Detect errors (M4)
        3. Send feedback to M3
        4. Receive refined command from M3
        5. Validate again
        6. Repeat until success or max iterations
        """
        max_iterations = 3
        current_command = flawed_command
        
        for iteration in range(max_iterations):
            validation_result = self.validator.validate(current_command)
            
            if validation_result.success:
                return {
                    'status': 'SUCCESS',
                    'iterations': iteration + 1,
                    'final_command': current_command
                }
            
            # Generate fix and send to M3
            feedback = self.fix_generator.generate_fix(validation_result)
            refined_command = self.m3_interface.request_refinement(feedback)
            
            current_command = refined_command
        
        return {'status': 'MAX_ITERATIONS_REACHED'}
```

#### 🧪 Test Scenarios

Create test cases for common error patterns:

```python
# test_scenarios.py

FLAWED_COMMANDS = [
    {
        'name': 'Invalid Flag Test',
        'command': 'nmap -invalid-flag 192.168.1.1',
        'expected_error': 'INVALID_FLAG',
        'expected_fix': 'Remove invalid flag',
        'expected_iterations': 1
    },
    {
        'name': 'Permission Denied Test',
        'command': 'nmap -sS -O 192.168.1.1',
        'expected_error': 'PERMISSION_DENIED',
        'expected_fix': 'Change to unprivileged scan',
        'expected_iterations': 1
    },
    {
        'name': 'Multiple Errors Test',
        'command': 'nmap -invalid -sS -O 192.168.1.1',
        'expected_error': 'MULTIPLE',
        'expected_fix': 'Remove invalid flag and adjust privileges',
        'expected_iterations': 2
    },
    {
        'name': 'Complex Refinement Test',
        'command': 'nmap -sS -A -T5 --script=all 192.168.1.0/24',
        'expected_error': 'COMPLEXITY_TOO_HIGH',
        'expected_fix': 'Reduce complexity via M3 Hard Agent',
        'expected_iterations': 2
    }
]
```

#### ✅ Deliverables
- [ ] `correction_cycle.py` - Full cycle implementation
- [ ] `test_scenarios.py` - Comprehensive test suite
- [ ] `demo_flawed_commands.json` - Test command database
- [ ] Video/screen recording of working demo
- [ ] Integration documentation
- [ ] **PR #3** with all Week 3 commits

#### 📊 Success Criteria

| Metric | Target | Status |
|--------|--------|--------|
| **Single Error Correction** | 100% success | ⬜ To Test |
| **Multi-Error Correction** | >90% success | ⬜ To Test |
| **M3 Integration** | <200ms latency | ⬜ To Test |
| **Max Iterations** | ≤3 for 95% cases | ⬜ To Test |
| **False Fix Rate** | <5% | ⬜ To Test |

---

## 🔗 M3-M4 Integration Details

### API Contract

#### **M4 → M3: Refinement Request**

```http
POST http://m3-api:8000/api/v1/refine
Content-Type: application/json

{
  "command_id": "string",
  "original_command": "string",
  "feedback": {
    "error_type": "string",
    "severity": "HIGH|MEDIUM|LOW",
    "correction_request": {
      "complexity_adjustment": "REDUCE|INCREASE|MAINTAIN",
      "parameter_changes": [],
      "suggested_action": "string"
    }
  }
}
```

#### **M3 → M4: Refined Command Response**

```http
200 OK
Content-Type: application/json

{
  "command_id": "string",
  "refined_command": "string",
  "changes_applied": [
    {
      "type": "FLAG_REMOVED",
      "value": "-O",
      "reason": "Requires root privileges"
    }
  ],
  "confidence_score": 0.92,
  "refinement_method": "HARD_AGENT_DIFFUSION"
}
```

### Collaboration Protocol

1. **M4 detects error** in command execution
2. **M4 analyzes error** using error taxonomy
3. **M4 generates feedback** with correction suggestions
4. **M4 sends feedback to M3** via API
5. **M3's Hard Agent** (diffusion-based synthesis) refines command
6. **M3 returns refined command** to M4
7. **M4 validates** refined command
8. **Repeat** if needed (max 3 iterations)

---

## 📚 Week 3 Documentation

### Required Documentation
- [ ] `api_contract.md` - M3-M4 API specification
- [ ] `feedback_schema.json` - Structured feedback format
- [ ] `correction_flow.md` - Complete correction cycle documentation
- [ ] `integration_guide.md` - Setup instructions for M3 integration
- [ ] `error_taxonomy.md` - Complete error classification guide

---

## 🧪 Testing Requirements

### Unit Tests
```bash
# Test error analysis
pytest tests/test_error_analysis.py -v

# Test fix generation
pytest tests/test_fix_generator.py -v

# Test M3 interface (mock)
pytest tests/test_m3_interface.py -v
```

### Integration Tests
```bash
# Test with M3 (requires M3 API running)
pytest tests/test_m3_m4_integration.py -v --m3-url http://localhost:8000

# Test full correction cycle
python step11-integration-demo/correction_cycle.py --demo-mode
```

### Performance Tests
```bash
# Measure correction cycle time
python tests/performance_test.py --iterations 50
```

---

## 🎯 Week 3 Success Checklist

- [ ] **Step 8 Complete**: Enhanced sandbox captures all error types
- [ ] **Step 9 Complete**: Error analysis maps to corrective actions
- [ ] **Step 10 Complete**: Fix generation sends feedback to M3
- [ ] **Step 11 Complete**: Full cycle demonstrated successfully
- [ ] **M3 Integration**: API contract finalized and tested
- [ ] **Tests Pass**: All unit and integration tests green
- [ ] **Documentation**: All required docs completed
- [ ] **PR #3 Submitted**: Code review requested
- [ ] **Demo Prepared**: Video/recording of working system

---

## 🚧 Known Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| **M3 API not ready** | Create mock M3 responses for testing |
| **Complex error patterns** | Start with simple errors, expand gradually |
| **Iteration deadlocks** | Implement max iteration limit (3) |
| **Performance bottlenecks** | Use async calls to M3, cache common fixes |

---

## 📊 Week 3 Metrics Dashboard

```
Correction Cycle Performance
════════════════════════════
Total Tests Run:          0
Successful Corrections:   0
Failed Corrections:       0
Average Iterations:       0.0
Average Time per Cycle:   0.0s
M3 API Uptime:           0%

Error Detection Accuracy
════════════════════════
True Positives:          0
False Positives:         0
False Negatives:         0
Accuracy:                0%
```

---

## 🔄 Iterative Refinement Example

```
Iteration 1:
  Input:  nmap -sS -O 192.168.1.1
  Error:  PERMISSION_DENIED
  Fix:    Request complexity reduction from M3
  Output: nmap -sT 192.168.1.1

Iteration 2:
  Input:  nmap -sT 192.168.1.1
  Error:  None
  Status: ✓ SUCCESS

Final Command: nmap -sT 192.168.1.1
Total Time: 1.2s
```

---

## 🤝 Collaboration Points

### With M3 (LLM Engineer)
- API endpoint design
- Feedback schema validation
- Hard Agent complexity adjustment
- Performance optimization

### With M2 (Planning Agent)
- Scan strategy validation
- Complexity level definitions

### With M5 (Execution Agent)
- Final command handoff
- Execution results feedback

---

## 📞 Support & Communication

- **Slack Channel**: `#m3-m4-integration`
- **Weekly Sync**: Thursdays 2 PM
- **Code Reviews**: Daily stand-up
- **Blocker Resolution**: Immediate Slack ping

---

## 🎓 Learning Resources

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [NMAP Error Messages Guide](https://nmap.org/book/man.html)
- [API Design Patterns](https://cloud.google.com/apis/design/patterns)
- [Iterative Refinement in AI Systems](https://arxiv.org/abs/2301.00234)

---

<div align="center">

**Week 3 Status**: 🟡 In Progress

**Next Review**: End of Day 21

**Target**: PR #3 Submission

</div>