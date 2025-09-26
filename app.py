import psutil
import time
from datetime import datetime
import json
import pefile
from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
import hashlib
import requests
import sqlite3

# --- CONFIGURATION ---
DB_FILE = "aegis.db"
VT_API_KEY = "5f0efbf7914e57cc1747025c54340b108f96c69ce2997b7826930d5df5e2522e"

# --- FLASK SETUP ---
app = Flask(__name__, template_folder='dashboard', static_folder='dashboard')
socketio = SocketIO(app, cors_allowed_origins="*")

# --- LOAD RULES & PROFILE ---
try:
    with open('rules.json', 'r') as f: RULES = json.load(f)
except FileNotFoundError: RULES = {}
try:
    with open('profile.json', 'r') as f: PROFILE = json.load(f)
except FileNotFoundError: PROFILE = {}

# --- DATABASE ---
def init_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, process_name TEXT,
            path TEXT, username TEXT, parent_name TEXT, signer_status TEXT,
            hash_sha256 TEXT UNIQUE, virustotal_score TEXT, analysis TEXT
        )
    ''')
    conn.commit()
    conn.close()

# --- INTELLIGENCE FUNCTIONS ---
def get_file_hash(path):
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""): sha256.update(byte_block)
        return sha256.hexdigest()
    except Exception: return None

def check_virustotal(api_key, file_hash):
    if not api_key or api_key == "YOUR_API_KEY_HERE" or not file_hash: return "VT Not Configured"
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return f"{stats['malicious']} / {stats['harmless'] + stats['suspicious'] + stats['malicious'] + stats['undetected']}"
        else: return "New File"
    except Exception: return "API Error"

def get_process_intelligence(pid, conn):
    try:
        p = psutil.Process(pid)
        path = p.exe()
        signature = "Unsigned"; file_hash = None; vt_report = "Not Checked"
        if p.name() in PROFILE:
            vt_report = "Whitelisted"
            signature = "Signed (Profiled)"
        else:
            file_hash = get_file_hash(path)
            if file_hash:
                cursor = conn.cursor()
                cursor.execute("SELECT virustotal_score FROM logs WHERE hash_sha256 = ?", (file_hash,))
                result = cursor.fetchone()
                if result:
                    vt_report = f"Cached: {result[0]}"
                else:
                    vt_report = check_virustotal(VT_API_KEY, file_hash)
            try:
                pe = pefile.PE(path, fast_load=True)
                if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size > 0:
                    signature = "Signed"
            except Exception: signature = "Could Not Verify"
        return {
            "timestamp": datetime.now().strftime("%Y-m-d %H:%M:%S"), "pid": p.pid,
            "process_name": p.name(), "path": path, "username": p.username(),
            "parent_name": p.parent().name() if p.parent() else "N/A",
            "signer_status": signature, "hash_sha256": file_hash, "virustotal_score": vt_report
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied): return None

def analyse_intelligence(intelligence_data):
    alerts = []
    # (Analysis logic can be expanded here in the future)
    if not alerts: return "Status: Clear"
    return " | ".join(alerts)

# --- BACKGROUND THREAD ---
def watchdog_thread():
    known_pids = {p.pid for p in psutil.process_iter()}
    db_conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    while True:
        current_pids = {p.pid for p in psutil.process_iter()}
        new_pids = current_pids - known_pids
        if new_pids:
            for pid in new_pids:
                intelligence = get_process_intelligence(pid, db_conn)
                if intelligence:
                    intelligence['analysis'] = analyse_intelligence(intelligence)
                    socketio.emit('new_process', intelligence)
                    cursor = db_conn.cursor()
                    cursor.execute( "INSERT OR IGNORE INTO logs (timestamp, process_name, path, username, parent_name, signer_status, hash_sha256, virustotal_score, analysis) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (intelligence['timestamp'], intelligence['process_name'], intelligence['path'],
                         intelligence['username'], intelligence['parent_name'], intelligence['signer_status'],
                         intelligence['hash_sha256'], intelligence['virustotal_score'], intelligence['analysis'])
                    )
                    db_conn.commit()
            known_pids.update(new_pids)
        
        # THIS IS THE CORRECTED LINE
        time.sleep(2)

# --- FLASK SERVER ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print('Client connected to dashboard')

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    init_database()
    print("Starting Aegis Live Server (Optimized Final Version)...")
    thread = threading.Thread(target=watchdog_thread)
    thread.daemon = True
    thread.start()
    socketio.run(app, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)