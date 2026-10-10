from flask import Flask, render_template, request, jsonify
import secrets
import string
import re
from urllib.parse import urlparse

app = Flask(__name__)

COMMON_PASSWORDS = {
    "password", "password123", "12345678", "qwerty123",
    "admin123", "letmein", "welcome123"
}

SUSPICIOUS_TERMS = {
    "login", "verify", "account", "secure", "update", "password",
    "banking", "wallet", "signin", "confirm", "gift", "free"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"
}

def assess_password(password):
    if not password:
        return {
            "score": 0, "label": "Not checked", "color": "muted",
            "tips": ["Enter a password to check it."]
        }

    score = 0
    tips = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        tips.append("Use at least 12 characters.")
    else:
        tips.append("Make it longer — aim for at least 12 characters.")

    checks = [
        (any(c.islower() for c in password), "Add lowercase letters."),
        (any(c.isupper() for c in password), "Add uppercase letters."),
        (any(c.isdigit() for c in password), "Add numbers."),
        (any(c in string.punctuation for c in password), "Add special characters.")
    ]
    for passed, tip in checks:
        if passed:
            score += 1
        else:
            tips.append(tip)

    if password.lower() in COMMON_PASSWORDS:
        score = 0
        tips.insert(0, "This is a commonly used password. Choose a unique one.")
    if re.search(r"(.)\1{3,}", password):
        score = max(0, score - 1)
        tips.append("Avoid repeating the same character many times.")
    if re.search(r"1234|abcd|qwerty", password.lower()):
        score = max(0, score - 1)
        tips.append("Avoid predictable sequences.")

    if score >= 5:
        label, color = "Strong", "good"
    elif score >= 3:
        label, color = "Moderate", "warn"
    else:
        label, color = "Weak", "bad"

    if not tips:
        tips.append("Good mix. Make sure this password is unique to one account.")
    return {"score": min(score, 6), "label": label, "color": color, "tips": tips}

def generate_password(length, use_upper, use_lower, use_digits, use_symbols):
    pools = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+?")
    if not pools:
        raise ValueError("Select at least one character type.")
    if length < len(pools):
        raise ValueError("Length must be at least the number of selected character types.")

    # Ensure each selected type appears at least once, then fill and shuffle securely.
    chars = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    chars.extend(secrets.choice(all_chars) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

def check_url(raw_url):
    raw_url = raw_url.strip()
    if not raw_url:
        return {"label": "No URL entered", "color": "muted",
                "reasons": ["Paste a URL to run a quick check."]}

    candidate = raw_url if "://" in raw_url else "https://" + raw_url
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower().strip(".")

    if not host or "." not in host or any(ch.isspace() for ch in raw_url):
        return {"label": "Invalid URL", "color": "bad",
                "reasons": ["The URL format looks invalid. Check the address and try again."]}

    reasons = []
    if parsed.scheme.lower() != "https":
        reasons.append("The URL does not use HTTPS.")
    if "@" in parsed.netloc:
        reasons.append("The address contains '@', which can obscure the real destination.")
    if host in SHORTENERS:
        reasons.append("This is a URL-shortening service, so the final destination is hidden.")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        reasons.append("The host is an IP address rather than a typical domain name.")
    if host.startswith("xn--") or ".xn--" in host:
        reasons.append("The domain uses punycode, which can sometimes be used in lookalike domains.")
    if host.count("-") >= 3:
        reasons.append("The domain contains many hyphens.")
    if len(host) > 50:
        reasons.append("The domain name is unusually long.")
    if sum(term in raw_url.lower() for term in SUSPICIOUS_TERMS) >= 2:
        reasons.append("The URL contains several words often used in deceptive messages.")
    if len(parsed.username or "") > 0:
        reasons.append("The address includes user-info before the host, which is unusual.")

    if reasons:
        label, color = "Suspicious signals found", "warn"
    else:
        label, color = "No obvious signals found", "good"
        reasons.append("This simple check found no obvious warning signs.")

    reasons.append("This is a heuristic only; it does not query threat-intelligence databases and cannot prove a link is safe.")
    return {"label": label, "color": color, "reasons": reasons, "host": host}

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/api/password")
def password_api():
    data = request.get_json(silent=True) or {}
    return jsonify(assess_password(str(data.get("password", ""))))

@app.post("/api/generate")
def generate_api():
    data = request.get_json(silent=True) or {}
    try:
        length = int(data.get("length", 16))
        if length < 8 or length > 64:
            raise ValueError("Choose a password length between 8 and 64.")
        password = generate_password(
            length,
            bool(data.get("upper", True)),
            bool(data.get("lower", True)),
            bool(data.get("digits", True)),
            bool(data.get("symbols", True))
        )
        return jsonify({"password": password, "strength": assess_password(password)})
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

@app.post("/api/url")
def url_api():
    data = request.get_json(silent=True) or {}
    return jsonify(check_url(str(data.get("url", ""))))

if __name__ == "__main__":
    app.run(debug=True)
