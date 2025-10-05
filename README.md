# Project Aegis 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**A proactive, AI-driven digital immune system that learns your system's behavior to detect and neutralize novel threats in real-time.**



---

## 🚀 About The Project

Traditional cybersecurity is reactive. It relies on signatures of *known* threats, meaning we are always one step behind the attackers. **Project Aegis** was born from a different philosophy: what if we could build a security system that functions like a biological immune system?

> Instead of just looking for known malware, Aegis creates a dynamic baseline of your system's "healthy" behavior—its normal processes, network connections, and file interactions. It then uses this baseline to spot anomalous patterns symptomatic of a brand-new, never-before-seen attack.

This tool is not just a script; it's a complete platform. It combines a lightweight Python agent (`watchdog.py`) with a powerful Flask backend and a sleek, real-time web dashboard. It’s a modern security tool for the modern threat landscape, designed for analysts, developers, and security enthusiasts who want to see the future of defense.

---

### ✨ Core Features

* **🧠 AI-Powered Anomaly Detection:** At its core, Aegis uses a heuristic and eventually an AI-driven engine to score the "suspicion level" of system events, moving beyond simple rule-based alerts.
* **👁️ Real-time Process Monitoring:** Captures every new process, its parent, its command line arguments, and its digital signature status the moment it executes.
* **🌐 Live Web Dashboard:** A beautiful and intuitive command center built with Flask and Socket.IO that displays system events and security alerts as they happen.
* **🔍 Deep System Intelligence:** Automatically performs hash calculations (SHA256), checks file signatures, and integrates with the **VirusTotal API** to enrich data.
* **🛡️ Heuristic Scoring Engine:** Generates a "Suspicion Score" based on a combination of factors (unsigned files, suspicious parent processes, running from temp folders) for intelligent alerting.
* ** scalable Foundation:** Built with a **SQLite database** backend to professionally log and manage thousands of events for historical analysis and future model training.
* **🔧 Clean & Modular Codebase:** Logically structured to make it incredibly easy for others to contribute new detection modules and features.

---

### 🛠️ Getting Started

Get your local copy of Project Aegis up and running in a few simple steps.

#### Prerequisites

* **Python 3.9+** and **pip** must be installed.
* **Git** for cloning the repository.
* A free **VirusTotal API Key** is required for full functionality.

#### Installation & Launch

1.  **Clone the Repository**
    ```sh
    git clone [https://github.com/YOUR_USERNAME/AegisProject.git](https://github.com/YOUR_USERNAME/AegisProject.git)
    ```
2.  **Navigate to the Directory**
    ```sh
    cd AegisProject
    ```
3.  **Install Dependencies**
    ```sh
    pip install -r requirements.txt
    ```
4.  **Configure API Key**
    * Open the `app.py` file and find the line `VT_API_KEY = "YOUR_API_KEY_HERE"`.
    * Replace `"YOUR_API_KEY_HERE"` with your actual VirusTotal API key.
5.  **Initialize the Database**
    * The database (`aegis.db`) will be created automatically on the first run.
6.  **Launch the Aegis Server!**
    * You must run the server with administrator/sudo privileges to allow it to monitor all system processes.
    * **On Windows:** Open your terminal (CMD or PowerShell) as an Administrator.
    * **On macOS/Linux:** Use the `sudo` command.
    ```sh
    # On macOS/Linux
    sudo python app.py

    # On Windows (in an Admin terminal)
    python app.py
    ```
---

### 📖 How to Use

Once the server is running, the system is active.

1.  **Open the Command Center**
    * Open your web browser and navigate to `http://127.0.0.1:5000`.
    * You will see the live dashboard, which will immediately start displaying new process events from your machine.

2.  **Monitor for Alerts**
    * Use your computer normally. As new programs run, they will appear on the dashboard.
    * The system will automatically analyze each event. Suspicious events will be highlighted with a **"WARNING"** or **"CRITICAL"** status and a non-zero suspicion score.

3.  **Explore the Data**
    * The `explore_data.py` script can be run to get a quick summary of all events logged in the database.
    ```sh
    python explore_data.py
    ```

---

### 🗺️ Project Roadmap

This is the foundational version of Project Aegis. The vision is much larger. See the [open issues](https://github.com/YOUR_USERNAME/AegisProject/issues) for a full list of proposed features.

* ✅ **Phase 1: Professional Foundation**
    * Integrate SQLite Database.
* ⚙️ **Phase 2: Advanced Intelligence Agent**
    * Live Network Monitoring & IP Geolocation.
    * File System & Windows Registry Monitoring.
    * Process Tree Analysis.
* ấp **Phase 3: The Interactive Command Center**
    * Historical Database Search & Filtering.
    * Interactive World Map for network connections.
    * Data Visualization Dashboards (charts, graphs).
* ấp **Phase 4: The True AI Brain**
    * Train a real ML model to classify threats.
    * Implement statistical anomaly detection (Z-score, Isolation Forests).
    * Automated rule generation based on discovered threats.

---

### 🙏 Acknowledgments

This tool wouldn't be possible without the incredible work of the following projects:
* [Flask](https://flask.palletsprojects.com/) & [Socket.IO](https://python-socketio.readthedocs.io/)
* [psutil](https://github.com/giampaolo/psutil)
* [pefile](https://github.com/erocarrera/pefile)
* [VirusTotal API](https://developers.virustotal.com/reference)

---

### 📜 License

Distributed under the MIT License. See the `LICENSE` file for more information.

---

### ✍️ Author

**Harvenix** - *Initial Work & Development* - [Harvenix](https://github.com/Harvenix)
