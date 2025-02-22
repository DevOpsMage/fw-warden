import os
import json
import datetime
import pytz
import ipaddress
import uuid
import subprocess
from collections import deque
from proxmoxer import ProxmoxAPI
from dotenv import load_dotenv
import geoip2.database

# Load environment variables from .env
load_dotenv()

# Configuration constants loaded from environment or defaults
LOG_FILE = os.getenv('LOG_FILE', '/var/log/pve-firewall.log')
STATE_FILE = os.getenv('STATE_FILE', './firewall_state.json')
TRACKING_FILE = os.getenv('TRACKING_FILE', './tracking.json')
NODE = os.getenv('NODE', 'pve01')
PROXMOX_HOST = os.getenv('PROXMOX_HOST')
PROXMOX_USER = os.getenv('PROXMOX_USER')
PROXMOX_PASSWORD = os.getenv('PROXMOX_PASSWORD')
VERIFY_SSL = os.getenv('PROXMOX_VERIFY_SSL', 'False').lower() in ('true', '1', 'yes')
COUNTRY_CONF = os.getenv('COUNTRY_CONF', './country_conf')
GEOIP_DB = os.getenv('GEOIP_DB', '/usr/share/GeoIP/GeoLite2-Country.mmdb')

# Load allowed countries from country_conf
try:
    with open(COUNTRY_CONF, 'r') as f:
        allowed_countries = {line.strip().upper() for line in f if line.strip()}
except FileNotFoundError:
    print(f"Warning: {COUNTRY_CONF} not found. No countries allowed.")
    allowed_countries = set()

# Load GeoIP database if available
try:
    geoip_reader = geoip2.database.Reader(GEOIP_DB)
except FileNotFoundError:
    print(f"Error: GeoIP database not found at {GEOIP_DB}")
    geoip_reader = None

# Initialize Proxmox API connection
PROXMOX = ProxmoxAPI(
    PROXMOX_HOST,
    user=PROXMOX_USER,
    password=PROXMOX_PASSWORD,
    verify_ssl=VERIFY_SSL
)

def parse_log_line(line):
    """
    Parse a log line from the firewall log.
    Returns a tuple (vmid, src_ip, timestamp, action) if valid, else None.
    """
    parts = line.split()
    if len(parts) < 10 or parts[5] != "policy":
        return None
    vmid = parts[0]
    if not vmid.isdigit():
        return None
    action = parts[6]  # "DROP:" or "ACCEPT:"
    if action not in ["DROP:", "ACCEPT:"]:
        return None
    timestamp_str = parts[3] + " " + parts[4]
    try:
        timestamp = datetime.datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        timestamp = timestamp.astimezone(pytz.utc)
    except ValueError:
        return None
    for part in parts[7:]:
        if part.startswith("SRC="):
            src_ip = part[4:]
            break
    else:
        return None
    # Sanitize src_ip
    try:
        ipaddress.ip_address(src_ip)
    except ValueError:
        return None
    return vmid, src_ip, timestamp, action

def get_country(ip):
    """Get country code for an IP using GeoIP database."""
    if geoip_reader is None:
        return None
    try:
        response = geoip_reader.country(ip)
        return response.country.iso_code
    except geoip2.errors.AddressNotFoundError:
        return None

def main():
    # Load state from file if exists
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            state = json.load(f)
            for key in state.get('drops', {}):
                state['drops'][key] = deque(
                    [datetime.datetime.fromisoformat(ts) for ts in state['drops'][key]],
                    maxlen=5
                )
            for key in state.get('blocked', {}):
                blocked = state['blocked'][key]
                if blocked['expiration']:
                    blocked['expiration'] = datetime.datetime.fromisoformat(blocked['expiration'])
                blocked.setdefault('permanent', False)
    else:
        state = {
            'drops': {},
            'blocked': {},
            'log_file_inode': None,
            'log_file_position': 0
        }

    # Load tracking events
    if os.path.exists(TRACKING_FILE):
        with open(TRACKING_FILE, 'r') as f:
            try:
                tracking_events = json.load(f)
            except json.JSONDecodeError:
                tracking_events = []
    else:
        tracking_events = []

    # Get block counts for each IP using jq
    try:
        result = subprocess.check_output([
            "jq",
            'group_by(.src_ip) | map({ip: .[0].src_ip, count: length})',
            TRACKING_FILE
        ], universal_newlines=True)
        block_data = json.loads(result)
        block_counts = {item['ip']: item['count'] for item in block_data}
    except Exception as e:
        print(f"Error running jq query: {e}")
        block_counts = {}

    # Determine log file position
    current_inode = os.stat(LOG_FILE).st_ino
    position = state['log_file_position'] if state['log_file_inode'] == current_inode else 0

    with open(LOG_FILE, 'r') as f:
        if position > 0:
            f.seek(position)
        while True:
            line = f.readline()
            if not line:
                break
            parsed = parse_log_line(line)
            if parsed:
                vmid, src_ip, timestamp, action = parsed
                key = f"{vmid}:{src_ip}"

                # Geolocation check
                country = get_country(src_ip)
                if country and country not in allowed_countries:
                    if key not in state['blocked'] or not state['blocked'][key]['permanent']:
                        unique_id = str(uuid.uuid4())
                        rule = {
                            'enable': 1,
                            'type': 'in',
                            'action': 'DROP',
                            'source': src_ip,
                            'comment': f"Permanent geo-block at {datetime.datetime.now(pytz.utc).isoformat()} - ID: {unique_id}"
                        }
                        try:
                            response = PROXMOX.nodes(NODE).qemu(vmid).firewall.rules.post(**rule)
                            state['blocked'][key] = {
                                'rule_index': response,
                                'expiration': None,
                                'unique_id': unique_id,
                                'permanent': True
                            }
                            tracking_events.append({
                                'timestamp': datetime.datetime.now(pytz.utc).isoformat(),
                                'vmid': vmid,
                                'src_ip': src_ip,
                                'unique_id': unique_id,
                                'rule_index': response,
                                'expiration': 'permanent',
                                'reason': 'disallowed country'
                            })
                        except Exception as e:
                            print(f"Failed to block IP {src_ip} for VM {vmid}: {e}")
                elif action == "DROP:" and not state['blocked'].get(key, {}).get('permanent', False):
                    if key not in state['drops']:
                        state['drops'][key] = deque(maxlen=5)
                    state['drops'][key].append(timestamp)
                    if len(state['drops'][key]) == 5:
                        time_diff = (state['drops'][key][-1] - state['drops'][key][0]).total_seconds() / 60.0
                        if time_diff <= 5:
                            unique_id = str(uuid.uuid4())
                            rule = {
                                'enable': 1,
                                'type': 'in',
                                'action': 'DROP',
                                'source': src_ip,
                                'comment': f"Temp block at {datetime.datetime.now(pytz.utc).isoformat()} - ID: {unique_id}"
                            }
                            try:
                                response = PROXMOX.nodes(NODE).qemu(vmid).firewall.rules.post(**rule)
                                previous_blocks = block_counts.get(src_ip, 0)
                                if previous_blocks >= 7:
                                    expiration = None  # Permanent block
                                elif previous_blocks >= 5:
                                    expiration = datetime.datetime.now(pytz.utc) + datetime.timedelta(days=7)
                                else:
                                    expiration = datetime.datetime.now(pytz.utc) + datetime.timedelta(hours=1)
                                state['blocked'][key] = {
                                    'rule_index': response,
                                    'expiration': expiration,
                                    'unique_id': unique_id,
                                    'permanent': expiration is None
                                }
                                tracking_events.append({
                                    'timestamp': datetime.datetime.now(pytz.utc).isoformat(),
                                    'vmid': vmid,
                                    'src_ip': src_ip,
                                    'unique_id': unique_id,
                                    'rule_index': response,
                                    'expiration': expiration.isoformat() if expiration else 'permanent',
                                    'reason': "multiple drops",
                                    'previous_blocks': previous_blocks
                                })
                            except Exception as e:
                                print(f"Failed to temp block IP {src_ip} for VM {vmid}: {e}")
            position = f.tell()

    # Remove expired temporary blocks
    now = datetime.datetime.now(pytz.utc)
    for key, blocked in list(state['blocked'].items()):
        if not blocked['permanent'] and blocked['expiration'] and blocked['expiration'] < now:
            try:
                PROXMOX.nodes(NODE).qemu(key.split(':')[0]).firewall.rules.delete(blocked['rule_index'])
                del state['blocked'][key]
                if key in state['drops']:
                    del state['drops'][key]
            except Exception as e:
                print(f"Failed to remove rule {blocked['rule_index']} for {key}: {e}")

    # Save state
    state_to_save = {
        'log_file_inode': current_inode,
        'log_file_position': position,
        'drops': {k: [ts.isoformat() for ts in d] for k, d in state['drops'].items()},
        'blocked': {
            k: {
                'rule_index': v['rule_index'],
                'expiration': v['expiration'].isoformat() if v['expiration'] else None,
                'unique_id': v['unique_id'],
                'permanent': v['permanent']
            } for k, v in state['blocked'].items()
        }
    }
    with open(STATE_FILE, 'w') as f:
        json.dump(state_to_save, f)

    # Save tracking events
    with open(TRACKING_FILE, 'w') as f:
        json.dump(tracking_events, f)

if __name__ == "__main__":
    main()