#!/usr/bin/env python3
"""Synchronize Aegis-approved lab client blocks into the gateway nft set."""

import ipaddress
import json
import logging
import os
import signal
import subprocess
import time
from urllib.request import Request, urlopen


API_URL = os.environ.get("AEGIS_API_URL", "http://192.168.56.1:4001").rstrip("/")
LAB_NETWORK = ipaddress.ip_network(os.environ.get("AEGIS_LAB_SUBNET", "10.77.0.0/24"))
GATEWAY_IP = ipaddress.ip_address(os.environ.get("AEGIS_LAB_GATEWAY_IP", "10.77.0.1"))
NFT_BINARY = os.environ.get("NFT_BINARY", "/usr/sbin/nft")
POLL_SECONDS = 10
REQUEST_TIMEOUT = 5
NFT_TABLE = "aegis_filter"
NFT_SET = "blocked_clients"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("aegis-block-sync")
running = True


def stop(_signum, _frame):
    global running
    running = False


def sanitize_blocklist(entries):
    allowed = set()
    for entry in entries:
        if not isinstance(entry, str):
            logger.warning("Ignoring invalid blocklist IP")
            continue
        try:
            address = ipaddress.ip_address(entry)
        except ValueError:
            logger.warning("Ignoring invalid blocklist IP")
            continue
        if (
            isinstance(address, ipaddress.IPv4Address)
            and address in LAB_NETWORK
            and address != GATEWAY_IP
            and address != LAB_NETWORK.network_address
            and address != LAB_NETWORK.broadcast_address
        ):
            allowed.add(str(address))
    return sorted(allowed)


def fetch_blocklist(token):
    request = Request(
        f"{API_URL}/api/ids/suricata/blocks",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        payload = json.loads(response.read().decode("utf-8"))
    entries = payload.get("blocked")
    if not isinstance(entries, list):
        raise ValueError("Aegis returned an invalid blocklist")
    return sanitize_blocklist(entries)


def apply_blocklist(addresses):
    lines = [f"flush set inet {NFT_TABLE} {NFT_SET}"]
    if addresses:
        elements = ", ".join(addresses)
        lines.append(f"add element inet {NFT_TABLE} {NFT_SET} {{ {elements} }}")
    subprocess.run(
        [NFT_BINARY, "-f", "-"],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
        timeout=REQUEST_TIMEOUT,
        check=True,
    )


def run():
    token = os.environ.get("SURICATA_INGEST_TOKEN", "")
    if not token:
        raise SystemExit("SURICATA_INGEST_TOKEN is required")

    current = None
    while running:
        try:
            desired = fetch_blocklist(token)
            if desired != current:
                logger.info("Aegis blocklist changed: %s active lab block(s)", len(desired))
            apply_blocklist(desired)
            current = desired
        except (OSError, TimeoutError, ValueError, subprocess.SubprocessError) as exc:
            logger.warning("Blocklist sync failed; keeping current firewall set: %s", exc)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    run()