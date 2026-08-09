# Task 3: AI Prompt Web App

## 🎯 Overview
A robust and production-aware Flask application designed to interact with AI models. The app supports dual-mode functionality: it automatically detects an API key and switches to real integration, or falls back to a deterministic **Mock Mode** for seamless testing and demonstration.

---

## 🛠️ Technical Stack
* **Backend:** Python (Flask 3.x)
* **Database:** SQLite (Used for audit logging and persistence)
* **Frontend:** Responsive HTML5/CSS3 (Centered layout, clean interface)
* **Data Handling:** CSV generation for history auditing

---

## 🚀 Getting Started

### 1. Prerequisites
Ensure you are in the project directory:
```bash
cd task-3-ai-prompt-app
2. Installation
Install the required dependencies:

Bash
pip install --break-system-packages -r requirements.txt
3. Run the Application
Start the server:

Bash
python3 app.py
4. Usage
Open your browser and navigate to: http://localhost:5000

📋 Features
Dual-Provider Modes: Automatically handles real API calls if AI_API_KEY is provided; otherwise, it activates the Mock Mode to ensure zero downtime.

Smart History Tracking: Every prompt, template used, and response is logged into an SQLite database.

Audit & Export: View full interaction history and download the entire audit log as a CSV file with one click.

Input Validation: Built-in safeguards against empty or malicious oversized inputs.

Modern UI: Clean, centered, and responsive design for better user experience.

💡 Notes
This application follows PEP 668 guidelines for environment management.

The project is structured for easy scalability to support future AI providers.
