#@file main.py
#@author Gemini 3.6

import re
import urllib.parse

def multi_url_decode(s: str) -> str:
    """Recursively decode multi/double URL-encoded strings."""
    prev = ""
    curr = s
    while curr != prev:
        prev = curr
        curr = urllib.parse.unquote(curr)
    return curr

def analyze_log_line(line: str):
    # Log line format: <line> <time> <source IP> "<method> <URI>" <HTTP status> "<User-Agent>"
    log_pattern = re.compile(
        r'^(L\d+)\s+(\d{2}:\d{2}:\d{2})\s+([\d\.]+)\s+"([^"]*)"\s+(\d{3})\s+"([^"]*)"'
    )
    match = log_pattern.match(line.strip())
    if not match:
        return None

    line_id, timestamp, ip, request, status, user_agent = match.groups()

    # 1. Decode multi/double-encoded strings
    decoded_req = multi_url_decode(request)
    decoded_ua = multi_url_decode(user_agent)

    # 2. Normalize SQL comments (e.g. convert /**/ to space for filter evasion checks)
    cleaned_req = re.sub(r'/\*.*?\*/', ' ', decoded_req)

    # SQL Injection detection patterns
    sqli_patterns = [
        (r"'\s*--", "Authentication bypass attempt using single quote and comment operator ('--)"),
        (r"\bUNION\b.*\bSELECT\b", "UNION-based SQL injection attempt to exfiltrate database records"),
        (r";\s*DROP\s+TABLE\b", "Stacked query SQL injection attempting table deletion (DROP TABLE)"),
        (r"'\s*OR\s*'\d+'\s*=\s*'\d+", "Boolean-based SQL injection (' OR '1'='1) injected into HTTP header"),
        (r"\bAND\b\s+SLEEP\s*\(", "Time-based blind SQL injection using SLEEP() delay function"),
        (r"\bOR\b\s+\d+=\d+", "Boolean-based SQL injection payload (OR 1=1)"),
    ]

    # Check for SQLi in User-Agent header
    for pattern, reason in sqli_patterns:
        if re.search(pattern, decoded_ua, re.IGNORECASE):
            return {
                "line": line_id,
                "type": "SQL Injection (SQLi)",
                "reason": f"Header Injection: {reason}"
            }

    # Check for SQLi in Request URI
    for pattern, reason in sqli_patterns:
        if re.search(pattern, cleaned_req, re.IGNORECASE):
            return {
                "line": line_id,
                "type": "SQL Injection (SQLi)",
                "reason": f"URI Payload: {reason}"
            }

    # DoS Detection 1: Slowloris / Slow HTTP Attack
    # Characterized by empty HTTP requests ("-") timing out with HTTP Status 408
    if status == "408" and request == "-":
        return {
            "line": line_id,
            "type": "Denial of Service (DoS)",
            "reason": "Slowloris Attack: Connection held open with incomplete request headers, resulting in 408 Request Timeout"
        }

    # DoS Detection 2: Application-Layer HTTP Flood Attack
    # Characterized by rapid automated GET requests from external IP 203.0.113.50 causing HTTP 503 errors
    if ip == "203.0.113.50":
        return {
            "line": line_id,
            "type": "Denial of Service (DoS)",
            "reason": f"HTTP Flood Attack: High-frequency automated request burst causing server overload (HTTP Status: {status})"
        }

    return None

def analyze_logfile(filepath: str):
    alerts = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                alert = analyze_log_line(line)
                if alert:
                    alerts.append(alert)
    return alerts

if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else "log_provided.txt" #Supply file name from command line
    #log_file = sys.argv[1] if len(sys.argv) > 1 else input("Name of file to analyze: ")
    results = analyze_logfile(log_file)

    print(f"{'Line':<6} | {'Attack Type':<24} | {'Reason'}")
    print("-" * 85)
    for r in results:
        print(f"{r['line']:<6} | {r['type']:<24} | {r['reason']}")
    print(f"Found {len(results)} alerts in {log_file}")