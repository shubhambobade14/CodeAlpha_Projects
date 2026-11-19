import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from alert_parser import parse_line, load_alerts


def test_valid_alert():
    line = '{"event_type":"alert","src_ip":"192.0.2.5","dest_ip":"198.51.100.9","proto":"TCP","alert":{"signature":"Test","severity":2}}'
    item = parse_line(line)
    assert item["src_ip"] == "192.0.2.5"
    assert item["signature"] == "Test"

def test_ignore_non_alert():
    assert parse_line('{"event_type":"flow"}') is None

def test_ignore_invalid_json():
    assert parse_line('not json') is None

def test_load_sample():
    sample = Path(__file__).resolve().parents[1] / "sample_data" / "sample_eve.json"
    assert len(load_alerts(sample)) == 4
