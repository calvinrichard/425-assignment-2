#@file main_v2.py
#@author Gemini 3.6
#Edited by Calvin Richard

import re
import urllib.parse
from datetime import datetime
from collections import defaultdict

def multi_url_decode(s: str) -> str:
    """Recursively decode multi/double URL-encoded strings."""
    prev = ""
    curr = s
    while curr != prev:
        prev = curr
        curr = urllib.parse.unquote(curr)
    return curr


def parse_log_line(line: str):
    log_pattern = re.compile(
        r'^(L\d+)\s+(\d{2}:\d{2}:\d{2})\s+([\d\.]+)\s+"([^"]*)"\s+(\d{3})\s+"([^"]*)"'
    )
    match = log_pattern.match(line.strip())
    if not match:
        return None

    line_id, time_str, ip, request, status, user_agent = match.groups()
    timestamp = datetime.strptime(time_str, "%H:%M:%S")

    return {
        "line_id": line_id,
        "time_str": time_str,
        "timestamp": timestamp,
        "ip": ip,
        "request": request,
        "status": status,
        "user_agent": user_agent,
        "raw": line.strip()
    }


def detect_sqli(entry: dict):
    decoded_req = multi_url_decode(entry["request"])
    decoded_ua = multi_url_decode(entry["user_agent"])
    cleaned_req = re.sub(r'/\*.*?\*/', ' ', decoded_req)

    sqli_patterns = [
        (r"'\s*--", "Authentication bypass attempt using single quote and comment operator ('--)"),
        (r"\bUNION\b.*\bSELECT\b", "UNION-based SQL injection attempt to exfiltrate database records"),
        (r";\s*DROP\s+TABLE\b", "Stacked query SQL injection attempting table deletion (DROP TABLE)"),
        (r"'\s*OR\s*'\d+'\s*=\s*'\d+", "Boolean-based SQL injection (' OR '1'='1) injected into HTTP header"),
        (r"\bAND\b\s+SLEEP\s*\(", "Time-based blind SQL injection using SLEEP() delay function"),
        (r"\bOR\b\s+\d+=\d+", "Boolean-based SQL injection payload (OR 1=1)"),
    ]

    for pattern, reason in sqli_patterns:
        if re.search(pattern, decoded_ua, re.IGNORECASE):
            return f"Header Injection: {reason}"

    for pattern, reason in sqli_patterns:
        if re.search(pattern, cleaned_req, re.IGNORECASE):
            return f"URI Payload: {reason}"

    return None


def analyze_log_file(filepath: str, rate_threshold: int = 3, window_seconds: int = 5):
    # Pass 1: Read and parse all valid lines
    parsed_entries = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                parsed = parse_log_line(line)
                if parsed:
                    parsed_entries.append(parsed)

    # Group entries by IP address for rate analysis
    requests_by_ip = defaultdict(list)
    for entry in parsed_entries:
        requests_by_ip[entry['ip']].append(entry)

    # Pass 2: Identify IP burst clusters (HTTP Flood detection)
    flood_line_ids = set()
    for ip, entries in requests_by_ip.items():
        for e1 in entries:
            # Skip incomplete Slowloris requests from flood rate counting
            if e1['request'] == '-':
                continue

            # Count requests from the same IP within the time window
            cluster = [
                e2 for e2 in entries
                if e2['request'] != '-' and abs((e2['timestamp'] - e1['timestamp']).total_seconds()) <= window_seconds
            ]

            if len(cluster) >= rate_threshold:
                flood_line_ids.add(e1['line_id'])

    # Pass 3: Evaluate each line and generate alerts
    alerts = []
    for entry in parsed_entries:
        line_id = entry['line_id']
        sqli_reason = detect_sqli(entry)

        if sqli_reason:
            alerts.append({
                "line": line_id,
                "type": "SQL Injection (SQLi)",
                "reason": sqli_reason
            })
        elif entry['status'] == '408' and entry['request'] == '-':
            alerts.append({
                "line": line_id,
                "type": "Denial of Service (DoS)",
                "reason": "Slowloris Attack: Connection held open with incomplete request headers resulting in HTTP 408 Timeout"
            })
        elif line_id in flood_line_ids:
            alerts.append({
                "line": line_id,
                "type": "Denial of Service (DoS)",
                "reason": f"HTTP Flood Attack: Exceeded rate limit threshold ({rate_threshold}+ requests within {window_seconds}s window)"
            })

    return alerts


if __name__ == "__main__":
    import sys

    filename = sys.argv[1] if len(sys.argv) > 1 else "log_provided.txt" #Original generation
    #If this were to be used anywhere else
    #filename = sys.argv[1] if len(sys.argv) > 1 else input("Name of file to analyze: ")
    results = analyze_log_file(filename, rate_threshold=3, window_seconds=5)

    print(f"{'Line':<6} | {'Attack Type':<24} | {'Reason'}")
    print("-" * 85)
    for r in results:
        print(f"{r['line']:<6} | {r['type']:<24} | {r['reason']}")
    print(f"Found {len(results)} alerts in {filename}")