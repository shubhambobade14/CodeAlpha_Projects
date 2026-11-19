"""Read EVE alert events periodically; does not block traffic."""
import argparse
import json
import time
from pathlib import Path
from alert_parser import parse_line

def follow(path, interval=1):
    file_path = Path(path)
    print(f"Monitoring {file_path} (Ctrl+C to stop)")
    position = 0
    identity = None
    while True:
        try:
            stat = file_path.stat()
            current_identity = (stat.st_dev, stat.st_ino)
            if identity != current_identity or stat.st_size < position:
                position = 0
                identity = current_identity
            with file_path.open(encoding="utf-8", errors="replace") as handle:
                handle.seek(position)
                for line in handle:
                    event = parse_line(line)
                    if event:
                        print(json.dumps(event, ensure_ascii=False), flush=True)
                position = handle.tell()
        except FileNotFoundError:
            pass
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="/var/log/suricata/eve.json")
    args = parser.parse_args()
    try:
        follow(args.file)
    except KeyboardInterrupt:
        print("Stopped")
