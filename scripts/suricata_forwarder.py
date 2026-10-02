#!/usr/bin/env python3
"""Forward Suricata EVE alert events to the Aegis API."""

import json
import logging
import os
import signal
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


API_URL = os.environ.get("AEGIS_API_URL", "http://192.168.1.3:4001").rstrip("/")
EVE_PATH = Path(os.environ.get("SURICATA_EVE_PATH", "/var/log/suricata/eve.json"))
STATE_PATH = Path(os.environ.get("SURICATA_FORWARDER_STATE", "/var/lib/aegis-suricata-forwarder/cursor.json"))
POLL_SECONDS = 0.5
REQUEST_TIMEOUT = 10
MAX_RETRY_SECONDS = 60

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("aegis-suricata-forwarder")
running = True


def stop(_signum, _frame):
    global running
    running = False


def load_cursor():
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read cursor; starting at end of current EVE file: %s", exc)
        return None


def save_cursor(inode, offset):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_path = tempfile.mkstemp(dir=STATE_PATH.parent, prefix="cursor-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temporary_file:
            json.dump({"inode": inode, "offset": offset}, temporary_file)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, STATE_PATH)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def post_alert(event, token):
    request = Request(
        f"{API_URL}/api/ids/suricata/eve",
        data=json.dumps(event, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        result = json.loads(response.read().decode("utf-8"))
        if response.status != 200 or result.get("inserted") != 1:
            raise RuntimeError(f"Aegis rejected event: HTTP {response.status}, {result}")


def forward_alert(event, token):
    retry_seconds = 1
    while running:
        try:
            post_alert(event, token)
            alert = event.get("alert", {})
            logger.info(
                "Forwarded alert %s from %s",
                alert.get("signature", "Suricata alert"),
                event.get("src_ip", "unknown source"),
            )
            return True
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, RuntimeError) as exc:
            logger.warning("Aegis unavailable; retrying in %s seconds: %s", retry_seconds, exc)
            time.sleep(retry_seconds)
            retry_seconds = min(retry_seconds * 2, MAX_RETRY_SECONDS)
    return False


def run():
    token = os.environ.get("SURICATA_INGEST_TOKEN", "")
    if not token:
        raise SystemExit("SURICATA_INGEST_TOKEN is required")

    cursor = load_cursor()
    while running:
        try:
            with EVE_PATH.open("rb") as eve_file:
                file_stat = os.fstat(eve_file.fileno())
                inode = file_stat.st_ino
                if cursor and cursor.get("inode") == inode and 0 <= cursor.get("offset", -1) <= file_stat.st_size:
                    eve_file.seek(cursor["offset"])
                elif cursor is None:
                    eve_file.seek(0, os.SEEK_END)
                else:
                    eve_file.seek(0)

                save_cursor(inode, eve_file.tell())
                cursor = {"inode": inode, "offset": eve_file.tell()}

                while running:
                    current_path_stat = EVE_PATH.stat()
                    if current_path_stat.st_ino != inode and eve_file.tell() >= os.fstat(eve_file.fileno()).st_size:
                        break

                    current_size = os.fstat(eve_file.fileno()).st_size
                    if current_size < eve_file.tell():
                        eve_file.seek(0)
                        save_cursor(inode, 0)

                    line = eve_file.readline()
                    if not line:
                        time.sleep(POLL_SECONDS)
                        continue

                    next_offset = eve_file.tell()
                    try:
                        event = json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        logger.warning("Skipping malformed EVE JSON at byte %s", next_offset)
                    else:
                        if event.get("event_type") == "alert" and isinstance(event.get("alert"), dict):
                            if not forward_alert(event, token):
                                break

                    save_cursor(inode, next_offset)
                    cursor = {"inode": inode, "offset": next_offset}
        except FileNotFoundError:
            logger.warning("Waiting for EVE log: %s", EVE_PATH)
            time.sleep(POLL_SECONDS)
        except (OSError, TypeError) as exc:
            logger.error("EVE reader error: %s", exc)
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    run()