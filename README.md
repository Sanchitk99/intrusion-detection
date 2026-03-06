# Intrusion Detection System (IDS) Dashboard

A real-time Intrusion Detection System with an interactive web dashboard that monitors system behavior, analyzes network activity, and detects anomalies using machine learning.

---

## Overview

This project implements a live monitoring intrusion detection system designed to detect suspicious or malicious activity in real time. It combines system telemetry, traffic analytics, and a trained machine learning model to classify activity as normal or potentially malicious.

The dashboard provides a visual interface for monitoring system health, risk levels, traffic patterns, and detection confidence, allowing users to quickly identify anomalies without manually analyzing logs.

---

## Key Features

- Real-time intrusion detection
- Machine learning–based threat classification
- Risk level assessment (Low / Medium / High)
- Detection confidence scoring
- Live system health metrics
- Traffic monitoring and anomaly visualization
- Active connection tracking
- Attack simulation for testing
- Historical monitoring panel
- CSV upload for batch attack prediction
- Modern dark-themed dashboard UI

---

## System Architecture

The system consists of three main components:

### 1. Data Processing Layer
Handles input data preparation using:
- Feature encoders
- Data scaling
- Preprocessing pipeline

### 2. Detection Engine
Machine learning model that:
- Analyzes traffic/system features
- Predicts attack probability
- Outputs risk level + confidence score

### 3. Web Dashboard
Flask-based interface that displays:
- Live status
- System metrics
- Traffic charts
- Detection results

---

## Project Structure
```text
intrusion-detection/
│
├── templates/            # HTML dashboard templates
├── scripts/              # Local CSV export scripts for end users
├── data/                 # Dataset directory
├── __pycache__/          # Python cache files
│
├── app.py                # Main Flask dashboard server
├── agent.py              # Detection engine logic
├── train.py              # Model training script
│
├── model.pkl             # Trained ML model
├── scaler.pkl            # Feature scaler
├── encoders.pkl          # Feature encoders
├── attack_encoder.pkl    # Attack label encoder
│
├── .gitignore
├── .gitattributes
└── README.md
```
---

## Installation

Clone the repository:
```bash 
git clone https://github.com/Sanchitk99/intrusion-detection.git
cd intrusion-detection
```
Install dependencies:
```bash
pip install -r requirements.txt
```
Run the application:
```bash
python app.py
```
Open in browser:
```bash
http://127.0.0.1:5000
```
---

## Usage

1. Launch the server
2. Open the dashboard in your browser
3. Monitor live metrics
4. Observe risk classification updates
5. Use "Simulate Fake Attack" to test detection behavior
6. Toggle "History Panel" to review past predictions
7. Upload a CSV in "CSV Batch Analysis" to classify each row

---

## Export Activity CSV From PC

You can export a CSV from a Windows PC and upload it to the dashboard.

Run from project root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\export_activity.ps1
```

Or double-click:

```text
scripts\run_export_activity.bat
```

The file is saved to your `Downloads` folder as:

`ids-pc-activity-YYYYMMDD-HHMMSS.csv`

Then upload it in dashboard:

`CSV Batch Analysis` -> choose file -> `Analyze CSV`

---

## Deploy Online (CSV Upload For Everyone)

Yes, you can deploy online so users can upload CSV files.

### Option A: Render (recommended)

1. Push this repository to GitHub
2. Create a new Web Service in Render and select the repo
3. Render will use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
4. Deploy and share the public URL

Deployment files already included:

- `Procfile`
- `render.yaml`

Note: in cloud deployment, "live" traffic metrics represent the server machine, while CSV analysis works for user-uploaded files.

---

## Machine Learning Model

The detection engine uses a trained classification model stored in:

model.pkl

Supporting preprocessing files:

scaler.pkl  
encoders.pkl  
attack_encoder.pkl

Prediction pipeline:

Input Data → Encoding → Scaling → Prediction → Risk Classification

---

## Training the Model

To retrain using your dataset:

python train.py

This regenerates:

- model.pkl
- scaler.pkl
- encoders.pkl
- attack_encoder.pkl

---

## Testing the Detection System

The dashboard includes a built-in attack simulation feature that allows you to:

- Verify model response
- Demonstrate functionality
- Test alerts
- Validate UI behavior

---

## Use Cases

- Cybersecurity learning projects
- IDS research experiments
- Machine learning demonstrations
- Security visualization tools
- Academic submissions
- Portfolio projects

---

## Security Notice

This project is intended for educational, experimental, and demonstration purposes only.

It is not designed to replace production-grade intrusion detection systems used in enterprise environments.

---

## Contributing

Contributions are welcome.

Steps:
1. Fork repository
2. Create feature branch
3. Commit changes
4. Submit pull request

---
