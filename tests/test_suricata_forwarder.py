import importlib.util
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "suricata_forwarder.py"
SPEC = importlib.util.spec_from_file_location("suricata_forwarder", SCRIPT)
forwarder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(forwarder)


class ForwarderHandler(BaseHTTPRequestHandler):
    request_path = None
    request_auth = None
    request_body = None

    def do_POST(self):
        type(self).request_path = self.path
        type(self).request_auth = self.headers.get("Authorization")
        length = int(self.headers.get("Content-Length", "0"))
        type(self).request_body = json.loads(self.rfile.read(length))
        body = json.dumps({"ok": True, "inserted": 1}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class SuricataForwarderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ForwarderHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        forwarder.API_URL = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_posts_alert_to_authenticated_ingestion_route(self):
        event = {
            "event_type": "alert",
            "src_ip": "192.0.2.10",
            "alert": {"signature": "Local test", "severity": 3},
        }

        forwarder.post_alert(event, "test-sensor-token")

        self.assertEqual(ForwarderHandler.request_path, "/api/ids/suricata/eve")
        self.assertEqual(ForwarderHandler.request_auth, "Bearer test-sensor-token")
        self.assertEqual(ForwarderHandler.request_body, event)


if __name__ == "__main__":
    unittest.main()