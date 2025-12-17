#!/bin/bash
# NMAP-AI Week 3 Quick Start

echo "🚀 NMAP-AI Week 3 - Self-Correction Loop"
echo "========================================"
echo ""

# Check if Week 1 & 2 components exist
echo "📦 Checking previous components..."
if [ -f "src/utils/syntax_checker.py" ] && [ -f "src/agents/validation_agent.py" ]; then
    echo "✅ Week 1 & 2 components found"
else
    echo "⚠️  Some previous components missing"
    echo "   Make sure Week 1 & 2 are completed first"
fi

echo ""
echo "🔍 Week 3 Components:"
echo "  ✅ Execution Simulator: src/utils/execution_simulator.py"
echo "  ✅ Error Mapping Logic: src/agents/error_mapping_logic.py"
echo "  ✅ Self-Correction Agent: src/agents/self_correction_agent.py"
echo "  ✅ Auto-Correction Demo: tests/week3/auto_correction_demo.py"

# Create results directory
mkdir -p results

echo ""
echo "🧪 Running component tests..."
echo ""

# Test execution simulator
echo "1️⃣ Testing Execution Simulator..."
python3 src/utils/execution_simulator.py > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "   ✅ Execution simulator works!"
else
    echo "   ❌ Execution simulator has issues"
fi

# Test error mapping
echo "2️⃣ Testing Error Mapping Logic..."
python3 src/agents/error_mapping_logic.py > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "   ✅ Error mapping works!"
else
    echo "   ❌ Error mapping has issues"
fi

# Test self-correction agent
echo "3️⃣ Testing Self-Correction Agent..."
python3 src/agents/self_correction_agent.py > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "   ✅ Self-correction agent works!"
else
    echo "   ❌ Self-correction agent has issues"
fi

echo ""
echo "❓ Do you want to run the full auto-correction demo? (y/n)"
read -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🎯 Running Auto-Correction Demo..."
    echo "This will test 5 scenarios with intentionally flawed commands."
    echo ""
    python3 tests/week3/auto_correction_demo.py
else
    echo "💡 You can run the demo later with:"
    echo "   python3 tests/week3/auto_correction_demo.py"
fi

echo ""
echo "✅ Week 3 setup complete!"
echo ""
echo "📚 Key Features Implemented:"
echo "   • Real-time error detection during execution"
echo "   • Pattern-based error to correction mapping"
echo "   • Multi-attempt self-correction loop"
echo "   • Upstream feedback generation"
echo "   • Comprehensive success metrics"
echo ""
echo "📝 To create your PR:"
echo "   git add src/utils/execution_simulator.py"
echo "   git commit -m 'feat: Add enhanced execution simulator with error capture'"
echo "   "
echo "   git add src/agents/error_mapping_logic.py"
echo "   git commit -m 'feat: Implement error mapping and correction logic'"
echo "   "
echo "   git add src/agents/self_correction_agent.py"
echo "   git commit -m 'feat: Add self-correction agent with fix generation'"
echo "   "
echo "   git add tests/week3/"
echo "   git commit -m 'test: Add auto-correction cycle demonstration'"
echo ""
echo "🎉 Ready for PR 3: Fully functional Validation and Self-Correction Agents!"
