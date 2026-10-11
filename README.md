# SecureKey — Python Cybersecurity Mini Project

Features:
- Password strength estimate with improvement tips
- Secure random password generator (`secrets`)
- Basic suspicious-URL heuristic checker
- Flask backend and responsive HTML/CSS/JavaScript frontend

## Run locally
1. Install Python 3.10 or newer.
2. Open a terminal in this folder.
3. Optional but recommended: create and activate a virtual environment.
4. Install dependencies:
   `pip install -r requirements.txt`
5. Start the site:
   `python app.py`
6. Open `http://127.0.0.1:5000` in your browser.

## Important limitations
- Password strength is a teaching-oriented heuristic, not a formal entropy estimator.
- Passwords are sent to the local Flask server for checking in this demo; do not use real account passwords. For a production version, move checking entirely client-side or avoid transmitting/storing secrets.
- The URL checker does not contact reputation services and cannot confirm that a URL is safe. It only flags simple patterns.
- Before public deployment, turn off Flask debug mode, add rate limiting/CSRF protections as appropriate, and review security/privacy practices.
