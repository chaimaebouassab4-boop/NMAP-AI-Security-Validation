M4 (Validation Agent)
    ↓
    "Repairable" or "Invalid"
    ↓
M5 (Self-Correction Agent)
    ├→ Attempt Autonomous Repair (if "Repairable")
    │  ├→ Success? → Return immediately with source_agent="SELF-CORR-AUTO"
    │  └→ Fail? → Proceed to iterative correction
    │
    └→ Iterative Correction Loop
       ├→ Success? → Return with source_agent="SELF-CORR-ITER"
       └→ Fail? → Generate feedback for M3


       AUTONOMOUS_FIXES = {
    "permission_denied": {
        "description": "Permission error - switching to TCP Connect scan",
        "repair_type": AutonomousRepairType.PERMISSION_FIX,
        "fixes": [
            {
                "pattern": r"-sS",
                "replacement": "-sT",
                "reason": "TCP Connect scan (-sT) doesn't require root privileges"
            }
        ]
    },
    # ... more error types
}

Update M4 (Validation Agent)
When sending to M5, include:
python{
    "command": "nmap -sS -p 80 target.com",
    "intent": "...",
    "validation_status": "Repairable",  # ← IMPORTANT
    "errors": [{"type": "permission_denied", ...}],
    "request_id": "req_12345"
}