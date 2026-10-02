import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "aegis_block_sync.py"
SPEC = importlib.util.spec_from_file_location("aegis_block_sync", SCRIPT)
block_sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(block_sync)


class AegisBlockSyncTests(unittest.TestCase):
    def test_blocklist_is_limited_to_lab_hosts(self):
        self.assertEqual(
            block_sync.sanitize_blocklist(
                [
                    "10.77.0.2",
                    "10.77.0.1",
                    "10.77.0.0",
                    "10.77.0.255",
                    "192.168.56.1",
                    "::1",
                    "not-an-ip",
                    None,
                ]
            ),
            ["10.77.0.2"],
        )

    @patch.object(block_sync.subprocess, "run")
    def test_updates_nft_set_in_one_transaction(self, run):
        block_sync.apply_blocklist(["10.77.0.2", "10.77.0.3"])

        run.assert_called_once_with(
            [block_sync.NFT_BINARY, "-f", "-"],
            input=(
                "flush set inet aegis_filter blocked_clients\n"
                "add element inet aegis_filter blocked_clients { 10.77.0.2, 10.77.0.3 }\n"
            ),
            text=True,
            capture_output=True,
            timeout=block_sync.REQUEST_TIMEOUT,
            check=True,
        )

    @patch.object(block_sync.subprocess, "run")
    def test_clears_nft_set_when_no_blocks_remain(self, run):
        block_sync.apply_blocklist([])

        self.assertEqual(
            run.call_args.kwargs["input"],
            "flush set inet aegis_filter blocked_clients\n",
        )


if __name__ == "__main__":
    unittest.main()