# Personal Cybersecurity Dashboard — Version 2

A Flask-based, non-invasive website security configuration scanner.

## Features

- Public-domain reachability check
- HTTP status code
- HTTPS detection
- HTTP → HTTPS redirect check
- Six common security-header checks
- TLS certificate validity and expiry information
- Basic cookie flag analysis
- DNS IPv4 resolution
- Response time and basic server/content-type information
- 0–100 security score
- Risk classification
- Security recommendations
- Basic SSRF protection against localhost/private/link-local targets
- Responsive cybersecurity-themed dashboard UI

## Run

Create/activate a virtual environment if you use one, then:

```bash
pip install -r requirements.txt
python app.py
```

Open:

`http://127.0.0.1:5000`

## Important

This is a basic configuration scanner, not a penetration tester or vulnerability scanner.
A high score does not prove that a website is secure.

Only scan domains you are authorized to assess.
