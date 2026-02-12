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
