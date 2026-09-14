from flask import Flask, render_template, request
import requests
import socket
import ssl
import ipaddress
import time
from urllib.parse import urlparse

app = Flask(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "Content Security Policy",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions Policy",
}


def is_public_hostname(hostname):
    """Reject localhost/private/link-local targets to reduce SSRF risk."""
    if not hostname:
        return False

    hostname = hostname.lower().rstrip(".")
    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }
    if hostname in blocked_names or hostname.endswith(".local"):
        return False

    try:
        addresses = socket.getaddrinfo(hostname, None)
        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                return False
    except socket.gaierror:
        return False

    return True


def normalize_domain(value):
    value = value.strip()
    if not value:
        raise ValueError("Please enter a domain.")

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("That does not look like a valid domain.")

    if any(char.isspace() for char in hostname):
        raise ValueError("The domain contains spaces.")

    return hostname, f"https://{hostname}", f"http://{hostname}"


def check_ssl(hostname, timeout=5):
    result = {
        "available": False,
        "valid": False,
        "issuer": "Unavailable",
        "subject": "Unavailable",
        "expires": "Unavailable",
        "days_left": None,
        "error": None,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                result["available"] = True
                result["valid"] = True

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))

                result["subject"] = subject.get("commonName", hostname)
                result["issuer"] = issuer.get("organizationName") or issuer.get(
                    "commonName", "Unavailable"
                )

                expires = cert.get("notAfter")
                if expires:
                    from datetime import datetime, timezone
                    expiry_dt = datetime.strptime(
                        expires, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    result["expires"] = expiry_dt.strftime("%d %b %Y")
                    result["days_left"] = max(
                        0, (expiry_dt - datetime.now(timezone.utc)).days
                    )

    except ssl.SSLCertVerificationError as exc:
        result["available"] = True
        result["error"] = "Certificate verification failed."
    except Exception as exc:
        result["error"] = str(exc)

    return result


def scan_website(domain, https_url, http_url):
    result = {
        "domain": domain,
        "reachable": False,
        "status_code": None,
        "https": False,
        "http_redirects_to_https": False,
        "response_time_ms": None,
        "server": None,
        "content_type": None,
        "headers": [],
        "header_count": 0,
        "cookies": [],
        "cookie_count": 0,
        "dns": {"resolved": False, "ip": None, "error": None},
        "ssl": None,
        "score": 0,
        "risk": "UNKNOWN",
        "recommendations": [],
        "error": None,
    }

    # DNS
    try:
        result["dns"]["ip"] = socket.gethostbyname(domain)
        result["dns"]["resolved"] = True
    except socket.gaierror:
        result["dns"]["error"] = "Domain could not be resolved."
        result["error"] = "The domain could not be resolved."
        return result

    if not is_public_hostname(domain):
        result["error"] = (
            "For safety, this scanner only checks publicly reachable domains."
        )
        return result

    session = requests.Session()
    session.headers.update({
        "User-Agent": "PersonalCybersecurityDashboard/2.0"
    })

    # HTTPS request
    start = time.perf_counter()
    try:
        response = session.get(
            https_url,
            timeout=8,
            allow_redirects=True,
        )
        elapsed = (time.perf_counter() - start) * 1000

        result["reachable"] = True
        result["status_code"] = response.status_code
        result["https"] = response.url.lower().startswith("https://")
        result["response_time_ms"] = round(elapsed)
        result["server"] = response.headers.get("Server")
        result["content_type"] = response.headers.get("Content-Type")

        for header, label in SECURITY_HEADERS.items():
            value = response.headers.get(header)
            result["headers"].append({
                "name": label,
                "header": header,
                "present": bool(value),
                "value": value or "",
            })
            if value:
                result["header_count"] += 1

        raw_cookie_headers = response.raw.headers.getlist("Set-Cookie")
        for cookie in raw_cookie_headers:
            lower = cookie.lower()
            result["cookies"].append({
                "secure": "secure" in lower,
                "httponly": "httponly" in lower,
                "samesite": "samesite=" in lower,
            })
        result["cookie_count"] = len(result["cookies"])

    except requests.RequestException as exc:
        result["error"] = f"HTTPS request failed: {exc}"
        return result

    # HTTP -> HTTPS redirect check
    try:
        http_response = session.get(
            http_url,
            timeout=8,
            allow_redirects=False,
        )
        location = http_response.headers.get("Location", "")
        if http_response.status_code in (301, 302, 303, 307, 308):
            result["http_redirects_to_https"] = location.lower().startswith("https://")
    except requests.RequestException:
        pass

    # TLS certificate
    result["ssl"] = check_ssl(domain)

    # Score
    score = 0

    # HTTPS availability/configuration
    if result["https"]:
        score += 20

    # Redirect HTTP to HTTPS
    if result["http_redirects_to_https"]:
        score += 10

    # Security headers: 5 points each
    score += result["header_count"] * 5

    # SSL certificate
    if result["ssl"]["valid"]:
        score += 20

    # Cookie configuration
    if result["cookie_count"] == 0:
        score += 10
    else:
        secure_cookies = sum(1 for c in result["cookies"] if c["secure"])
        httponly_cookies = sum(1 for c in result["cookies"] if c["httponly"])
        samesite_cookies = sum(1 for c in result["cookies"] if c["samesite"])

        score += round((secure_cookies / result["cookie_count"]) * 3)
        score += round((httponly_cookies / result["cookie_count"]) * 3)
        score += round((samesite_cookies / result["cookie_count"]) * 4)

    result["score"] = min(score, 100)

    if result["score"] >= 80:
        result["risk"] = "LOW"
    elif result["score"] >= 60:
        result["risk"] = "MODERATE"
    elif result["score"] >= 40:
        result["risk"] = "HIGH"
    else:
        result["risk"] = "CRITICAL"

    # Recommendations
    missing = [
        item["name"] for item in result["headers"] if not item["present"]
    ]
    if not result["https"]:
        result["recommendations"].append("Enable HTTPS and use a valid TLS certificate.")
    if not result["http_redirects_to_https"]:
        result["recommendations"].append("Redirect HTTP traffic to HTTPS.")
    if missing:
        result["recommendations"].append(
            "Review missing security headers: " + ", ".join(missing) + "."
        )
    if result["ssl"]["error"]:
        result["recommendations"].append(
            "Review the TLS certificate configuration and certificate chain."
        )

    if result["cookie_count"]:
        insecure = [
            i + 1 for i, cookie in enumerate(result["cookies"])
            if not (cookie["secure"] and cookie["httponly"] and cookie["samesite"])
        ]
        if insecure:
            result["recommendations"].append(
                "Review cookie flags: Secure, HttpOnly, and SameSite should be set where appropriate."
            )

    if not result["recommendations"]:
        result["recommendations"].append(
            "No obvious configuration issues were detected by these basic checks."
        )

    return result


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    error = None
    submitted_domain = ""

    if request.method == "POST":
        submitted_domain = request.form.get("domain", "").strip()

        try:
            domain, https_url, http_url = normalize_domain(submitted_domain)
            result = scan_website(domain, https_url, http_url)
            if result.get("error") and not result.get("reachable"):
                error = result["error"]
        except ValueError as exc:
            error = str(exc)

    return render_template(
        "index.html",
        result=result,
        error=error,
        submitted_domain=submitted_domain,
    )


if __name__ == "__main__":
    app.run(debug=True)
