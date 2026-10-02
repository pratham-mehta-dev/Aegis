#!/usr/bin/env python3
"""Interactive / automated testing tool to simulate live Suricata sensor traffic.

Usage:
    python scripts/simulate_sensor_traffic.py --url http://localhost:4001 --token <SURICATA_INGEST_TOKEN>
    python scripts/simulate_sensor_traffic.py --trigger-autoblock --ip 10.77.0.42
"""

import argparse
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def send_eve_alert(api_url, token, src_ip, signature, severity=1):
    payload = {
        "event_type": "alert",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime()),
        "src_ip": src_ip,
        "src_port": 54321,
        "dest_ip": "10.77.0.1",
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "http",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2000001,
            "rev": 1,
            "signature": signature,
            "category": "Attempted Administrator Privilege Gain",
            "severity": severity,
        },
    }

    req = Request(
        f"{api_url.rstrip('/')}/api/ids/suricata/eve",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return True, data
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return False, f"HTTP {e.code}: {body}"
    except (URLError, TimeoutError, OSError) as e:
        return False, f"Connection error: {e}"


def check_blocks(api_url, token):
    req = Request(
        f"{api_url.rstrip('/')}/api/ids/suricata/blocks",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    try:
        with urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Simulate live Suricata alerts against Aegis.")
    parser.add_argument("--url", default="http://localhost:4001", help="Aegis API URL (default: http://localhost:4001)")
    parser.add_argument("--token", default="test-suricata-token", help="Suricata sensor ingestion token")
    parser.add_argument("--ip", default="10.77.0.15", help="Source IP to simulate (default: 10.77.0.15)")
    parser.add_argument("--trigger-autoblock", action="store_true", help="Send 3 High alerts to test automatic lab client block")

    args = parser.parse_args()

    print(f"[*] Target API: {args.url}")
    print(f"[*] Simulating source IP: {args.ip}")

    if args.trigger_autoblock:
        print("\n[+] Triggering 3 High-Severity Alerts to test auto-block...")
        for i in range(1, 4):
            sig = f"ET EXPLOIT Simulated Critical Exploit Attempt #{i}"
            ok, res = send_eve_alert(args.url, args.token, args.ip, sig, severity=1)
            print(f"    - Alert {i}/3 sent: status={'OK' if ok else 'FAILED'} -> {res}")
            time.sleep(0.5)

        print("\n[+] Checking active sensor blocklist from Aegis...")
        blocks = check_blocks(args.url, args.token)
        print(f"    - Blocked list: {blocks.get('blocked', [])}")
        if args.ip in blocks.get("blocked", []):
            print(f"\n[SUCCESS] Lab IP {args.ip} successfully triggered persistent auto-block!")
        else:
            print(f"\n[INFO] {args.ip} is not currently in the blocklist.")
    else:
        print("\n[+] Sending single test alert...")
        ok, res = send_eve_alert(args.url, args.token, args.ip, "ET SCAN Nmap Scripting Engine Probe", severity=2)
        print(f"    - Result: {'OK' if ok else 'FAILED'} -> {res}")


if __name__ == "__main__":
    main()
