import sys
sys.path.insert(0, ".")  # run from project root

from agents.agent_manager import get_manager

manager = get_manager()

# Test each agent directly (no queue, no LLM needed for routing logic)
print("\n--- Routing detection ---")
tasks = [
    "build a Python script to rename files",
    "research the history of quantum computing",
    "write an Instagram caption about coffee",
    "show me YouTube analytics for last week",
]
for task in tasks:
    detected = manager._detect_agent(task)
    print(f"  '{task[:45]}...' → {detected}")

# Test status
print("\n--- Agent status ---")
for name, info in manager.get_status().items():
    print(f"  {name}: {info}")