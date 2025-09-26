import pandas as pd
import sqlite3

DB_FILE = "aegis.db"
print("--- Aegis Data Explorer (Database Edition) ---")

# --- Connect to the database and load data ---
try:
    conn = sqlite3.connect(DB_FILE)
    # Use Pandas to execute a SQL query and load the result into a DataFrame
    df = pd.read_sql_query("SELECT * FROM logs", conn)
    conn.close()
    print(f"Successfully loaded {len(df)} events from the database.")
except Exception as e:
    print(f"Error loading data from database: {e}")
    exit()

# --- Perform the analysis (This part is unchanged) ---
if not df.empty:
    print("\n--- Intelligence Summary ---")
    print("\n[Top 10 Most Common Processes]")
    print(df['process_name'].value_counts().head(10))
    
    if 'signer_status' in df.columns:
        print("\n[Top 5 Most Common Signer Statuses]")
        print(df['signer_status'].value_counts().head(5))