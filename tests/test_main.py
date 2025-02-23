import unittest
import datetime
import pytz
import geoip2.errors
from unittest.mock import patch, mock_open, ANY, MagicMock
from main import parse_log_line, get_country, run_firewall_warden

class TestMain(unittest.TestCase):

    ### Test the parse_log_line function
    def test_parse_log_line_valid_accept(self):
        log_line = "102 7 tap102i0-IN 22/Feb/2025:12:43:26 -0600 ACCEPT: IN=fwbr102i0 OUT=fwbr102i0 PHYSIN=fwln102i0 PHYSOUT=tap102i0 MAC=bc:24:11:ce:4e:11:28:74:f5:3a:22:71:08:00 SRC=35.180.127.237 DST=75.37.49.10 LEN=68 TOS=0x00 PREC=0x00 TTL=229 ID=52132 DF PROTO=ICMP TYPE=8 CODE=0 ID=8 SEQ=24870"
        expected_timestamp = datetime.datetime(2025, 2, 22, 18, 43, 26, tzinfo=pytz.utc)  # Convert to UTC
        result = parse_log_line(log_line)
        self.assertEqual(result, ("102", "35.180.127.237", expected_timestamp, "ACCEPT:"))

    def test_parse_log_line_valid_drop(self):
        log_line = "102 6 tap102i0-IN 22/Feb/2025:12:43:32 -0600 policy DROP: IN=fwbr102i0 OUT=fwbr102i0 PHYSIN=fwln102i0 PHYSOUT=tap102i0 MAC=bc:24:11:ce:4e:11:28:74:f5:3a:22:71:08:00 SRC=45.142.193.117 DST=75.37.49.10 LEN=40 TOS=0x00 PREC=0x00 TTL=236 ID=3448 PROTO=TCP SPT=49743 DPT=8443 SEQ=1839537289 ACK=0 WINDOW=1024 SYN"
        expected_timestamp = datetime.datetime(2025, 2, 22, 18, 43, 32, tzinfo=pytz.utc)  # Convert to UTC
        result = parse_log_line(log_line)
        self.assertEqual(result, ("102", "45.142.193.117", expected_timestamp, "DROP:"))

    def test_parse_log_line_invalid(self):
        log_line = "Some invalid log line"
        result = parse_log_line(log_line)
        self.assertIsNone(result)

    ### Test the get_country function
    @unittest.mock.patch('main.geoip2.database.Reader', autospec=True)
    def test_get_country_found(self, mock_reader):
        mock_response = unittest.mock.MagicMock()
        mock_response.country.iso_code = "US"
        mock_reader.return_value.country.return_value = mock_response

        result = get_country("71.136.111.11")
        self.assertEqual(result, "US")

    @unittest.mock.patch('main.geoip2.database.Reader', autospec=True)
    def test_get_country_not_found(self, mock_reader):
        mock_reader.return_value.country.side_effect = geoip2.errors.AddressNotFoundError

        result = get_country("192.168.1.1")  # Validate private IP returns None
        self.assertIsNone(result)

    ### Test the main function    
    @patch('main.ProxmoxAPI')
    @patch('main.geoip2.database.Reader')
    @patch('main.os.path.getsize', return_value=1024)
    @patch('builtins.open', new_callable=mock_open, read_data='log content')
    def test_run_firewall_warden_temp_and_permanent_blocks(self, mock_file, mock_geoip_reader, mock_proxmox_api):
        # Create a mock ProxmoxAPI instance
        mock_proxmox = mock_proxmox_api.return_value 
        # Mock time to control block expiry
        mock_now = datetime.datetime(2025, 3, 1, 10, 0, 0, tzinfo=pytz.utc)
        with patch('main.datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = mock_now

            # Mock GeoIP to return a disallowed country
            mock_geoip_reader.country.return_value.country.iso_code = 'RU'  # Disallowed country

            # Simulate log lines with multiple drops from the same IP
            mock_log_lines = [
                "100 6 tap100i0-IN 22/Feb/2025:12:43:32 -0600 policy DROP: IN=fwbr100i0 OUT=fwbr100i0 PHYSIN=fwln100i0 PHYSOUT=tap100i0 MAC=bc:24:11:ce:4e:11:28:74:f5:3a:22:71:08:00 SRC=45.142.193.117 DST=75.37.49.10 LEN=40 TOS=0x00 PREC=0x00 TTL=236 ID=3448 PROTO=TCP SPT=49743 DPT=8443 SEQ=1839537289 ACK=0 WINDOW=1024 SYN",
                "100 6 tap100i0-IN 22/Feb/2025:12:43:33 -0600 policy DROP: IN=fwbr100i0 OUT=fwbr100i0 PHYSIN=fwln100i0 PHYSOUT=tap100i0 MAC=bc:24:11:ce:4e:11:28:74:f5:3a:22:71:08:00 SRC=45.142.193.117 DST=75.37.49.10 LEN=40 TOS=0x00 PREC=0x00 TTL=236 ID=3448 PROTO=TCP SPT=49743 DPT=8443 SEQ=1839537289 ACK=0 WINDOW=1024 SYN",
                "100 6 tap100i0-IN 22/Feb/2025:12:43:34 -0600 policy DROP: IN=fwbr100i0 OUT=fwbr100i0 PHYSIN=fwln100i0 PHYSOUT=tap100i0 MAC=bc:24:11:ce:4e:11:28:74:f5:3a:22:71:08:00 SRC=45.142.193.117 DST=75.37.49.10 LEN=40 TOS=0x00 PREC=0x00 TTL=236 ID=3448 PROTO=TCP SPT=49743 DPT=8443 SEQ=1839537289 ACK=0 WINDOW=1024 SYN",
                #... more drops to trigger temp block
                "100 6 tap100i0-IN 22/Feb/2025:12:44:00 -0600 policy DROP: IN=fwbr100i0 OUT=fwbr100i0 PHYSIN=fwln100i0 PHYSOUT=tap100i0 MAC=bc:24:11:ce:4e:11:28:74:f5:3a:22:71:08:00 SRC=45.142.193.117 DST=75.37.49.10 LEN=40 TOS=0x00 PREC=0x00 TTL=236 ID=3448 PROTO=TCP SPT=49743 DPT=8443 SEQ=1839537289 ACK=0 WINDOW=1024 SYN",
                "100 6 tap100i0-IN 22/Feb/2025:12:44:01 -0600 policy DROP: IN=fwbr100i0 OUT=fwbr100i0 PHYSIN=fwln100i0 PHYSOUT=tap100i0 MAC=bc:24:11:ce:4e:11:28:74:f5:3a:22:71:08:00 SRC=45.142.193.117 DST=75.37.49.10 LEN=40 TOS=0x00 PREC=0x00 TTL=236 ID=3448 PROTO=TCP SPT=49743 DPT=8443 SEQ=1839537289 ACK=0 WINDOW=1024 SYN",
            ]
            mock_file.return_value.__iter__.return_value = mock_log_lines

            # Call the run_firewall_warden function
            run_firewall_warden()

            # Assertions
            mock_proxmox.nodes.assert_any_call(ANY).qemu(ANY).firewall.rules.post(
                enable=1,
                type='in',
                action='DROP',
                source='45.142.193.117',
                comment=ANY  # Check for temp block comment
            )

            # Advance time to trigger expiry and call run_firewall_warden again
            mock_datetime.now.return_value = mock_now + datetime.timedelta(hours=2)
            run_firewall_warden()

            # Assert that the temp block was removed
            mock_proxmox.nodes.assert_any_call(ANY).qemu(ANY).firewall.rules.delete(ANY)

            # Simulate more drops to trigger permanent block
            run_firewall_warden()  # Call main again to process more drops and trigger permanent block

            # Assert that a permanent block was added
            mock_proxmox.nodes.assert_any_call(ANY).qemu(ANY).firewall.rules.post(
                enable=1,
                type='in',
                action='DROP',
                source='45.142.193.117',
                comment=ANY  # Check for permanent block comment
            )

            # Advance time - permanent block should not be removed
            mock_datetime.now.return_value = mock_now + datetime.timedelta(days=1)
            run_firewall_warden()
            # Add assertion to check that delete is not called for permanent block
            mock_proxmox.nodes.assert_not_called_with(ANY).qemu(ANY).firewall.rules.delete(ANY)



if __name__ == '__main__':
    unittest.main()