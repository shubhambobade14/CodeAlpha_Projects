"""Parse Suricata EVE JSON lines without executing or modifying network traffic."""
import json
from pathlib import Path

def parse_line(line):
    try:
        event = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(event, dict) or event.get("event_type") != "alert":
        return None
    alert = event.get("alert") or {}
    if not isinstance(alert, dict):
        return None
    return {
        "timestamp": str(event.get("timestamp", "")),
        "src_ip": str(event.get("src_ip", "unknown")),
        "src_port": event.get("src_port", ""),
        "dest_ip": str(event.get("dest_ip", "unknown")),
        "dest_port": event.get("dest_port", ""),
        "proto": str(event.get("proto", "unknown")),
        "signature": str(alert.get("signature", "unknown")),
        "signature_id": alert.get("signature_id", ""),
        "severity": alert.get("severity", ""),
        "category": str(alert.get("category", "")),
    }

def load_alerts(path, max_lines=100000):
    result = []
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        for idx, line in enumerate(handle):
            if idx >= max_lines:
                break
            item = parse_line(line)
            if item is not None:
                result.append(item)
    return result
