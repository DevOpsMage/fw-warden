import unittest
import datetime
import pytz
import geoip2.errors
from unittest.mock import patch, mock_open, ANY, MagicMock
from main import parse_log_line, get_country, run_firewall_warden

class TestMain(unittest.TestCase):

    ### Test the parse_log_line function
    def test_parse_log_line_valid_accept(self):
        log_line = "102 6 tap102i0-IN 22/Feb/2025:12:43:26 -0600 policy ACCEPT: IN=fwbr102i0 OUT=fwbr102i0 PHYSIN=fwln102i0 PHYSOUT=tap102i0 MAC=bc:24:11:ce:4e:11:28:74:f5:3a:22:71:08:00 SRC=35.180.127.237 DST=75.37.49.10 LEN=68 TOS=0x00 PREC=0x00 TTL=229 ID=52132 DF PROTO=ICMP TYPE=8 CODE=0 ID=8 SEQ=24870"
        expected_timestamp = datetime.datetime(2025, 2, 22, 18, 43, 26, tzinfo=pytz.utc)  # Convert to UTC
        result = parse_log_line(log_line)
        self.assertEqual(result, ("102", "35.180.127.237", expected_timestamp, "ACCEPT:"))

    @patch('main.geoip2.database.Reader')
    @patch('main.os.stat')
    @patch('main.os.path.getsize', return_value=1024)
    @patch('builtins.open', new_callable=mock_open, read_data='log content')
    @patch('main.ProxmoxAPI')
    @patch('main.subprocess.check_output', return_value='[{"ip": "45.142.193.117", "count": 5}]')
    def test_run_firewall_warden_temp_and_permanent_blocks(self, mock_subprocess, mock_proxmox_api, mock_file, mock_getsize, mock_stat, mock_geoip_reader):
        mock_proxmox = mock_proxmox_api.return_value
        mock_proxmox.nodes.return_value.qemu.return_value.firewall.rules.post.return_value = 1
        mock_proxmox.nodes.return_value.qemu.return_value.firewall.rules.delete.return_value = None
        mock_stat.return_value.st_ino = 1001

        mock_geoip_reader.return_value.country.return_value.country.iso_code = 'RU'
        with patch('main.datetime.datetime') as mock_datetime:
            mock_now = datetime.datetime(2025, 3, 1, 10, 0, 0, tzinfo=pytz.utc)
            mock_datetime.now.return_value = mock_now
            run_firewall_warden()

        mock_proxmox.nodes.assert_any_call(ANY).qemu(ANY).firewall.rules.post(
            enable=1,
            type='in',
            action='DROP',
            source='45.142.193.117',
            comment=ANY
        )

if __name__ == '__main__':
    unittest.main()
