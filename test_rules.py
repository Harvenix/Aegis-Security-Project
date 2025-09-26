import json

# --- We must include the necessary parts from our watchdog ---

# 1. Load the Rulebook and AI Profile
try:
    with open('rules.json', 'r') as f:
        RULES = json.load(f)
except FileNotFoundError:
    RULES = {}

try:
    with open('profile.json', 'r') as f:
        PROFILE = json.load(f)
except FileNotFoundError:
    print("Warning: profile.json not found. Run profiler.py first.")
    PROFILE = {}

# 2. Include the Analysis Engine function
def analyse_intelligence(intelligence_data):
    """Analysis engine, now with AI-powered impostor detection."""
    alerts = []
    process_name = intelligence_data.get('process_name', '')
    
    # Rule 1 & 2: From the rulebook
    for path in RULES.get("suspicious_paths", []):
        if path.lower() in intelligence_data.get('path', '').lower():
            alerts.append(f"High Alert: Running from suspicious location ({path})")
    if process_name in RULES.get("suspicious_names", {}):
        legit_path = RULES["suspicious_names"][process_name]
        if not intelligence_data.get('path', '').startswith(legit_path):
            alerts.append(f"High Alert: '{process_name}' running from unauthorized location.")

    # Rule 3: AI Profile Impostor Check
    if process_name in PROFILE:
        if intelligence_data.get('signer_status') != 'Signed':
            alerts.append(f"CRITICAL IMPOSTOR ALERT: Trusted program '{process_name}' is not signed!")

    if not alerts:
        return "Status: Clear"
    
    return " | ".join(alerts)

# --- The Simulation ---
print("\n--- Starting AI Impostor Simulation ---")

# Simulate a FAKE, unsigned version of a trusted program (chrome.exe)
fake_impostor_event = {
    "process_name": "chrome.exe",
    "signer_status": "Unsigned", # This should trigger the alert!
    "path": "C:\\Users\\Shivendra\\Downloads\\chrome.exe",
}

print("Simulating a fake, unsigned 'chrome.exe'...")
# This line now uses the correct variable name
analysis_result = analyse_intelligence(fake_impostor_event)

print("\n--- Final Verdict ---")
print(analysis_result)