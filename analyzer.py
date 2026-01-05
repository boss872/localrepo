import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import json

requests.packages.urllib3.disable_warnings()

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml"
}


def analyze_url(target_url):
    report = {
        "target": target_url,
        "summary": {
            "total_findings": 0,
            "risk_level": "Low"
        },
        "findings": [],
        "security_controls_detected": []
    }

    parsed = urlparse(target_url)

    # -------------------------------
    # A02: Cryptographic Failures
    # -------------------------------
    if parsed.scheme != "https":
        report["findings"].append({
            "owasp": "A02: Cryptographic Failures",
            "severity": "High",
            "issue": "HTTPS not enforced",
            "impact": "Traffic may be intercepted",
            "recommendation": "Enforce HTTPS with valid TLS certificates"
        })

    # -------------------------------
    # Connection Handling
    # -------------------------------
    try:
        response = requests.get(
            target_url,
            headers=BROWSER_HEADERS,
            timeout=15,
            verify=False
        )
    except requests.exceptions.Timeout:
        report["security_controls_detected"].append({
            "control": "Bot Mitigation / WAF",
            "confidence": "High",
            "evidence": "Connection timed out during automated request",
            "description": "Target likely blocks automated scanners"
        })
        return finalize_report(report)

    except requests.exceptions.ConnectionError:
        report["security_controls_detected"].append({
            "control": "Network Access Restriction",
            "confidence": "Medium",
            "evidence": "Connection refused",
            "description": "Direct scanning not permitted"
        })
        return finalize_report(report)

    # -------------------------------
    # WAF Detection (Headers)
    # -------------------------------
    waf_signatures = ["cloudflare", "akamai", "imperva", "incapsula", "fastly"]
    server_header = response.headers.get("Server", "").lower()

    for waf in waf_signatures:
        if waf in server_header:
            report["security_controls_detected"].append({
                "control": "Web Application Firewall",
                "confidence": "High",
                "evidence": f"Server header indicates {waf}",
                "description": "Enterprise-grade traffic filtering enabled"
            })

    headers = response.headers

    # -------------------------------
    # A05: Security Misconfiguration
    # -------------------------------
    security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]

    missing = [h for h in security_headers if h not in headers]

    if missing:
        report["findings"].append({
            "owasp": "A05: Security Misconfiguration",
            "severity": "Medium",
            "issue": "Missing security headers",
            "details": missing,
            "impact": "Higher exposure to client-side attacks",
            "recommendation": "Configure standard HTTP security headers"
        })

    # -------------------------------
    # A07: Authentication Failures
    # -------------------------------
    for cookie in response.cookies:
        if not cookie.secure:
            report["findings"].append({
                "owasp": "A07: Identification & Authentication Failures",
                "severity": "Medium",
                "issue": f"Insecure cookie detected: {cookie.name}",
                "impact": "Session hijacking risk",
                "recommendation": "Set Secure and HttpOnly flags"
            })

    # -------------------------------
    # A06: Vulnerable Components
    # -------------------------------
    soup = BeautifulSoup(response.text, "html.parser")
    scripts = soup.find_all("script", src=True)

    external_scripts = [
        s["src"] for s in scripts if s["src"].startswith("http")
    ]

    if external_scripts:
        report["findings"].append({
            "owasp": "A06: Vulnerable and Outdated Components",
            "severity": "Low",
            "issue": "External JavaScript dependencies detected",
            "details": external_scripts,
            "impact": "Potential supply-chain risk",
            "recommendation": "Audit third-party libraries"
        })

    return finalize_report(report)


def finalize_report(report):
    severity_weight = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    score = sum(severity_weight[f["severity"]] for f in report["findings"])

    report["summary"]["total_findings"] = len(report["findings"])

    if score >= 7:
        report["summary"]["risk_level"] = "High"
    elif score >= 3:
        report["summary"]["risk_level"] = "Medium"

    return report


# ===============================
# PyScripter Run Entry
# ===============================
if __name__ == "__main__":
    print("=== Web Security Risk Analyzer ===")
    print("Passive • OWASP-aligned • Ethical\n")
    print("designed and programmed by --")
    print("               --Kartik")

    target = input("Enter website URL: ").strip()
    result = analyze_url(target)

    print("\n=== ANALYSIS REPORT ===\n")
    print(json.dumps(result, indent=4))
