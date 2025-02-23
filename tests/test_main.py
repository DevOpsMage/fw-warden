import unittest
import datetime
import pytz
import geoip2.errors
from unittest.mock import patch, mock_open, ANY, MagicMock
from main import parse_log_line, get_country, run_firewall_warden

class TestMain(unittest.TestCase):

    ### A simple parse_log_line test example
    def test_parse_log_line_valid_accept(self):
        log_line = (
            "102 6 tap102i0-IN 22/Feb/2025:12:43:26 -0600 policy ACCEPT:"
            " IN=fwbr102i0 OUT=fwbr102i0 SRC=35.180.127.237 DST=75.37.49.10"
        )
        expected_timestamp = datetime.datetime(2025, 2, 22, 18, 43, 26, tzinfo=pytz.utc)
        result = parse_log_line(log_line)
        self.assertEqual(
            result,
            ("102", "35.180.127.237", expected_timestamp, "ACCEPT:")
        )

    @patch("main.geoip2.database.Reader")  # Prevent real DB load
    @patch("main.os.path.exists", return_value=True)
    @patch("main.os.stat")
    @patch("main.os.path.getsize", return_value=1024)
    @patch("main.subprocess.check_output", return_value='[{"ip":"45.142.193.117","count":5}]')
    @patch("main.ProxmoxAPI")
    def test_run_firewall_warden_temp_and_permanent_blocks(
        self,
        mock_proxmox_api,
        mock_subprocess,
        mock_getsize,
        mock_stat,
        mock_exists,
        mock_geoip_reader
    ):
        """
        Mocks all external calls to test run_firewall_warden logic:
         - state file read & write
         - tracking file read & write
         - log file read
         - geoip database
         - proxmox api
         - jq command
        """
        # Mock the Proxmox calls
        mock_proxmox = mock_proxmox_api.return_value
        mock_proxmox.nodes.return_value.qemu.return_value.firewall.rules.post.return_value = 123
        mock_proxmox.nodes.return_value.qemu.return_value.firewall.rules.delete.return_value = None

        # Mock the geoip database
        mock_reader_instance = mock_geoip_reader.return_value
        mock_reader_instance.country.return_value.country.iso_code = "RU"  # Disallowed country

        # Mock stat
        mock_stat.return_value.st_ino = 5678

        # Prepare content for 5 file opens:
        #  1) State file read
        state_read = '{"drops":{},"blocked":{},"log_file_inode":null,"log_file_position":0}'
        #  2) Tracking file read
        tracking_read = '[]'
        #  3) Log file read
        log_content = (
            "100 6 tap100i0-IN 22/Feb/2025:12:43:32 -0600 policy DROP: SRC=45.142.193.117 DST=75.37.49.10\n"
            "100 6 tap100i0-IN 22/Feb/2025:12:44:00 -0600 policy DROP: SRC=45.142.193.117 DST=75.37.49.10\n"
        )
        #  4) State file write (doesn't need real data, we won't read)
        #  5) Tracking file write (same here)

        # We'll create a separate mock_open for each read
        # and a simple MagicMock for the 2 writes.
        m1 = mock_open(read_data=state_read)     # state file (read)
        m2 = mock_open(read_data=tracking_read)  # tracking file (read)
        m3 = mock_open(read_data=log_content)    # log file (read)
        m4 = MagicMock()  # state file (write)
        m5 = MagicMock()  # tracking file (write)
        open_side_effects = [m1.return_value, m2.return_value, m3.return_value, m4, m5]

        def _mock_file_side_effect(*args, **kwargs):
            return open_side_effects.pop(0)

        with patch("builtins.open", side_effect=_mock_file_side_effect):
            with patch("main.datetime.datetime") as mock_datetime:
                mock_now = datetime.datetime(2025, 3, 1, 10, 0, 0, tzinfo=pytz.utc)
                mock_datetime.now.return_value = mock_now
                run_firewall_warden()

        # Confirm that we posted a firewall rule for the disallowed country IP
        mock_proxmox.nodes.assert_any_call(ANY).qemu(ANY).firewall.rules.post(
            enable=1,
            type="in",
            action="DROP",
            source="45.142.193.117",
            comment=ANY
        )

if __name__ == "__main__":
    unittest.main()
