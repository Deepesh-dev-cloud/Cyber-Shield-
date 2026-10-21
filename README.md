# CyberShield — Cybersecurity Monitoring Web Application

CyberShield is a Flask-based cybersecurity project that combines behavioral login tracking, security statistics, URL and QR code analysis, and cybersecurity news in a single web application.

## Features

- **User Authentication:** Provides registration and login functionality.
- **Behavioral Login Tracking:** Records login-related behavioral measurements, including typing speed and key intervals.
- **Security Dashboard:** Displays login activity, risk scores, and behavioral statistics.
- **Link and QR Code Analyzer:** Accepts URLs and QR codes for rule-based security analysis.
- **Cybersecurity News:** Retrieves cybersecurity articles from available RSS feeds.
- **SQLite Database:** Stores user and login-attempt information.

## Technology Stack

- Python
- Flask
- SQLite
- HTML and CSS
- JavaScript, where used
- OpenCV and NumPy for QR-related processing, where configured
- RSS feed parsing for cybersecurity news

## Project Structure

```text
CyberShield/
├── app/
│   ├── auth/
│   ├── database/
│   ├── link_analyzer/
│   ├── news/
│   ├── security/
│   ├── static/
│   └── templates/
├── instance/
├── tests/
├── run.py
├── README.md
└── requirements.txt
```

## Installation and Setup

1. Install Python on your computer.
2. Clone or download this repository.
3. Open a terminal in the project directory.
4. Create and activate a virtual environment.
5. Install the project's dependencies.
6. Start the Flask application.

Example commands for Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000` in your browser.

## Project Purpose

The purpose of CyberShield is to demonstrate how multiple cybersecurity-related functions can be integrated into one web application. It is an educational project intended for learning and demonstration, not a replacement for professional security monitoring tools.

## Limitations

Behavioral measurements and risk scores are indicative and should not be treated as definitive proof of unauthorized access. URL analysis may produce false positives or false negatives. News availability depends on external RSS sources.

## Future Enhancements

- Improve behavioral anomaly detection.
- Add more robust URL reputation checks.
- Improve dashboard visualizations.
- Add automated security alerts.
- Expand testing and deployment support.

## Disclaimer

CyberShield is developed for educational and authorized testing purposes. Do not use it to collect or analyze data without appropriate permission.
