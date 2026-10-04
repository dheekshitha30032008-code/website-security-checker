from flask import Flask, render_template, request
import requests

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    url = request.form["url"]

    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=5)

        headers = response.headers

        security_headers = {
            "HTTPS": url.startswith("https"),
            "HSTS": "Strict-Transport-Security" in headers,
            "Content Security Policy": "Content-Security-Policy" in headers,
            "X-Frame-Options": "X-Frame-Options" in headers,
            "X-Content-Type-Options": "X-Content-Type-Options" in headers
        }

        score = sum(security_headers.values())

        return render_template(
            "result.html",
            url=url,
            security_headers=security_headers,
            score=score
        )

    except requests.RequestException:
        return render_template("error.html")


if __name__ == "__main__":
    app.run()