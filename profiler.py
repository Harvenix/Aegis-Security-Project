import pandas as pd
import json

LOG_FILE = 'aegis_intelligence_log.json'
PROFILE_FILE = 'profile.json'

print("--- Aegis AI Profiler (Corrected Version) ---")

# --- Load the log file ---
try:
    with open(LOG_FILE, 'r') as f:
        log_lines = f.readlines()
    data = [json.loads(line) for line in log_lines]
    df = pd.DataFrame(data)
    print(f"Successfully loaded {len(df)} events for profiling.")
except Exception as e:
    print(f"Error loading log file: {e}")
    exit()

# --- Generate the Profile ---
if not df.empty and 'signer_status' in df.columns:
    # 1. Filter for only trusted, signed programs
    signed_df = df[df['signer_status'] == 'Signed'].copy()
    
    if not signed_df.empty:
        # 2. Find the unique program-signer pairs
        # The column names here are now correct
        profile_df = signed_df[['process_name', 'signer_status']].drop_duplicates().copy()
        
        # 3. Convert the list into a clean dictionary
        profile_dict = pd.Series(profile_df.signer_status.values, index=profile_df.process_name).to_dict()
        
        # 4. Save the profile to a new file
        with open(PROFILE_FILE, 'w') as f:
            json.dump(profile_dict, f, indent=4)
            
        print(f"\nSUCCESS: AI profile created with {len(profile_dict)} trusted programs.")
        print(f"Your system's 'digital fingerprint' has been saved to {PROFILE_FILE}")
    else:
        print("No 'Signed' programs found in the log to create a profile.")
else:
    print("Log file is empty or does not contain 'signer_status' data.")