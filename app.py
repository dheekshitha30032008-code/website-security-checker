from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from urllib.parse import urlparse
import requests
import socket
import ipaddress

app = Flask(__name__)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///security_scans.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# -----------------------------
# Database Model
# -----------------------------

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    score = db.Column(db.Integer, nullable=False)

    https = db.Column(db.Boolean, nullable=False)
    hsts = db.Column(db.Boolean, nullable=False)
    csp = db.Column(db.Boolean, nullable=False)
    x_frame_options = db.Column(db.Boolean, nullable=False)
    x_content_type_options = db.Column(db.Boolean, nullable=False)

    scanned_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# -----------------------------
# URL Safety Check
# -----------------------------

def is_safe_url(url):

    try:
        parsed = urlparse(url)

        # Allow only HTTP and HTTPS
        if parsed.scheme not in ["http", "https"]:
            return False

        if not parsed.hostname:
            return False

        hostname = parsed.hostname.lower()

        # Block localhost
        if hostname in [
            "localhost",
            "localhost.localdomain"
        ]:
            return False

        # Resolve hostname
        ip_addresses = socket.getaddrinfo(
            hostname,
            None
        )

        # Block private/internal addresses
        for address in ip_addresses:

            ip = ipaddress.ip_address(
                address[4][0]
            )

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                return False

        return True

    except Exception:
        return False


# -----------------------------
# Website Security Checker
# -----------------------------

def check_website(url):

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "https://" + url

    # Security validation
    if not is_safe_url(url):
        raise ValueError(
            "Unsafe or invalid URL."
        )

    # Request website
    response = requests.get(
        url,
        timeout=8,
        allow_redirects=False,
        headers={
            "User-Agent":
            "Website-Security-Checker/1.0"
        }
    )

    headers = response.headers

    # Security checks
    security_headers = {

        "HTTPS":
            url.startswith("https://"),

        "HSTS":
            "Strict-Transport-Security"
            in headers,

        "Content Security Policy":
            "Content-Security-Policy"
            in headers,

        "X-Frame-Options":
            "X-Frame-Options"
            in headers,

        "X-Content-Type-Options":
            "X-Content-Type-Options"
            in headers
    }

    # Calculate score
    score = sum(
        security_headers.values()
    )

    return (
        url,
        security_headers,
        score
    )


# -----------------------------
# Home Page
# -----------------------------

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# -----------------------------
# Website Check
# -----------------------------

@app.route(
    "/check",
    methods=["POST"]
)
def check():

    url = request.form.get(
        "url",
        ""
    ).strip()

    try:

        checked_url, security_headers, score = \
            check_website(url)

        # Save scan to database
        scan = Scan(

            url=checked_url,

            score=score,

            https=security_headers[
                "HTTPS"
            ],

            hsts=security_headers[
                "HSTS"
            ],

            csp=security_headers[
                "Content Security Policy"
            ],

            x_frame_options=security_headers[
                "X-Frame-Options"
            ],

            x_content_type_options=security_headers[
                "X-Content-Type-Options"
            ]
        )

        db.session.add(scan)
        db.session.commit()

        return render_template(

            "result.html",

            url=checked_url,

            security_headers=security_headers,

            score=score
        )

    except (
        requests.RequestException,
        ValueError
    ):

        return render_template(
            "error.html"
        )


# -----------------------------
# REST API
# -----------------------------

@app.route(
    "/api/check",
    methods=["POST"]
)
def api_check():

    data = request.get_json(
        silent=True
    )

    if not data or "url" not in data:

        return jsonify({

            "success": False,

            "error":
                "Please provide a URL."

        }), 400

    url = data["url"].strip()

    try:

        checked_url, security_headers, score = \
            check_website(url)

        # Store API scan
        scan = Scan(

            url=checked_url,

            score=score,

            https=security_headers[
                "HTTPS"
            ],

            hsts=security_headers[
                "HSTS"
            ],

            csp=security_headers[
                "Content Security Policy"
            ],

            x_frame_options=security_headers[
                "X-Frame-Options"
            ],

            x_content_type_options=security_headers[
                "X-Content-Type-Options"
            ]
        )

        db.session.add(scan)
        db.session.commit()

        return jsonify({

            "success": True,

            "url": checked_url,

            "score": score,

            "maximum_score": 5,

            "security_headers":
                security_headers,

            "scan_id": scan.id,

            "scanned_at":
                scan.scanned_at.isoformat()

        })

    except (
        requests.RequestException,
        ValueError
    ):

        return jsonify({

            "success": False,

            "error":
                "Unable to safely check this website."

        }), 400


# -----------------------------
# Security Dashboard
# -----------------------------

@app.route("/dashboard")
def dashboard():

    scans = Scan.query.order_by(
        Scan.scanned_at.desc()
    ).all()

    total_scans = len(scans)

    excellent_scans = sum(
        1
        for scan in scans
        if scan.score == 5
    )

    if total_scans:

        average_score = round(
            sum(
                scan.score
                for scan in scans
            ) / total_scans,
            1
        )

    else:

        average_score = 0

    return render_template(

        "dashboard.html",

        scans=scans,

        total_scans=total_scans,

        excellent_scans=
            excellent_scans,

        average_score=
            average_score
    )


# -----------------------------
# API Documentation
# -----------------------------

@app.route("/api-docs")
def api_docs():

    return render_template(
        "api_docs.html"
    )


# -----------------------------
# Create Database
# -----------------------------

with app.app_context():

    db.create_all()


# -----------------------------
# Run Application
# -----------------------------

if __name__ == "__main__":

    app.run()
