# IPS Security Monitoring Application

This project is a Python Flask-based web application that simulates a modern intrusion prevention system (IPS) dashboard for security monitoring.

## Features

- Intrusion detection dashboard with live-style metrics
- Security event simulation and alert creation
- Incident queue with open/closed response states
- Signature-rule management
- Policy enforcement controls
- Sensor health monitoring

## Run locally

1. Create a virtual environment (optional)
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Launch the app:
   ```bash
   python app.py
   ```
4. Open `http://localhost:5000` in a browser.

## Notes

This is an educational IPS prototype designed to mimic the core operational workflow of commercial IPS systems such as Trend Micro Deep Security or TippingPoint-style management consoles.
