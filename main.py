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

# Load environment variables from the .env file
load_dotenv()

# Configuration constants loaded from the environment or default values
LOG_FILE = os.getenv('LOG_FILE', '/var/log/pve-firewall.log')
STATE_FILE = os.getenv('STATE_FILE', './firewall_state.json')
TRACKING_FILE = os.getenv('TRACKING_FILE', './tracking.json')
NODE = os.getenv('NODE', 'pve01')
PROXMOX_HOST = os.getenv('PROXMOX_HOST')
PROXMOX_USER = os.getenv('PROXMOX_USER')
PROXMOX_PASSWORD = os.getenv('PROXMOX_PASSWORD')
VERIFY_SSL = os.getenv('PROXMOX_VERIFY_SSL', 'False').lower() in ('true', '1', 'yes')

# Load excluded networks from exclude.conf
EXCLUDE_CONF = os.getenv('EXCLUDE_CONF', './exclude.conf')

try:
    with open(EXCLUDE_CONF, 'r') as f:
        excluded_networks = [ipaddress.ip_network(line.strip()) for line in f if line.strip()]
except FileNotFoundError:
    print(f"Warning: {EXCLUDE_CONF} not found. No networks will be excluded.")
    excluded_networks = []
except Exception as e:
    print(f"Error reading {EXCLUDE_CONF}: {e}")
    excluded_networks = []

# Initialize the Proxmox API connection
PROXMOX = ProxmoxAPI(
    PROXMOX_HOST,
    user=PROXMOX_USER,
    password=PROXMOX_PASSWORD,
    verify_ssl=VERIFY_SSL
)

def parse_log_line(line):
    """
    Parse a log line from the firewall log.
    Returns a tuple (vmid, src_ip, timestamp) if the line matches the expected format,
    or None if it does not.
    """
    parts = line.split()
    if len(parts) < 10 or parts[5] != "policy" or parts[6] != "DROP:":
        return None
    vmid = parts[0]
    if not vmid.isdigit():
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
    # Sanitize src_ip to ensure it's a valid IP address
    try:
        ipaddress.ip_address(src_ip)
    except ValueError:
        return None
    return vmid, src_ip, timestamp

def main():
    # Load the current state from file if it exists; otherwise, initialize state
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            state = json.load(f)
            # Convert drop timestamps back to datetime objects
            for key in state.get('drops', {}):
                state['drops'][key] = deque(
                    [datetime.datetime.fromisoformat(ts) for ts in state['drops'][key]],
                    maxlen=5
                )
            # Handle blocked entries
            for key in state.get('blocked', {}):
                blocked_entry = state['blocked'][key]
                if blocked_entry['expiration'] is not None:
                    blocked_entry['expiration'] = datetime.datetime.fromisoformat(blocked_entry['expiration'])
                # else, it's already None
                if 'unique_id' not in blocked_entry:
                    blocked_entry['unique_id'] = str(uuid.uuid4())
    else:
        state = {
            'drops': {},
            'blocked': {},
            'log_file_inode': None,
            'log_file_position': 0
        }

    # Load tracking data for auditing blocked events
    if os.path.exists(TRACKING_FILE):
        with open(TRACKING_FILE, 'r') as tf:
            try:
                tracking_events = json.load(tf)
            except json.JSONDecodeError:
                tracking_events = []
    else:
        tracking_events = []

    # Get block counts for each IP
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

    # Determine where to start reading the log file based on inode
    current_inode = os.stat(LOG_FILE).st_ino
    if state['log_file_inode'] == current_inode:
        position = state['log_file_position']
    else:
        position = 0

    # Open and process the log file from the last known position
    with open(LOG_FILE, 'r') as f:
        if position > 0:
            f.seek(position)
        while True:
            line = f.readline()
            if not line:
                break
            parsed = parse_log_line(line)
            if parsed:
                vmid, src_ip, timestamp = parsed
                key = f"{vmid}:{src_ip}"
                if key not in state['drops']:
                    state['drops'][key] = deque(maxlen=5)
                state['drops'][key].append(timestamp)
                # If 5 drops within 5 minutes, trigger blocking
                if len(state['drops'][key]) == 5:
                    time_diff = (state['drops'][key][-1] - state['drops'][key][0]).total_seconds() / 60.0
                    if time_diff <= 5:
                        src_ip_obj = ipaddress.ip_address(src_ip)
                        # Skip IPs in excluded networks
                        if any(src_ip_obj in net for net in excluded_networks):
                            continue
                        now = datetime.datetime.now(pytz.utc)
                        # Add rule if not blocked or block has expired (if expiration is not None)
                        if key not in state['blocked'] or (state['blocked'][key]['expiration'] is not None and state['blocked'][key]['expiration'] < now):
                            unique_id = str(uuid.uuid4())
                            rule = {
                                'enable': 1,
                                'type': 'in',
                                'action': 'DROP',
                                'source': src_ip,
                                'log': 'nolog',
                                'comment': f"Blocked by automation at {now.isoformat()} - ID: {unique_id}"
                            }
                            try:
                                response = PROXMOX.nodes(NODE).qemu(vmid).firewall.rules.post(**rule)
                                rule_index = response
                                previous_blocks = block_counts.get(src_ip, 0)
                                if previous_blocks >= 7:
                                    expiration = None  # Permanent block
                                elif previous_blocks >= 5:
                                    expiration = now + datetime.timedelta(days=7)
                                else:
                                    expiration = now + datetime.timedelta(hours=1)
                                state['blocked'][key] = {
                                    'rule_index': rule_index,
                                    'expiration': expiration,
                                    'unique_id': unique_id
                                }
                                tracking_event = {
                                    "timestamp": now.isoformat(),
                                    "vmid": vmid,
                                    "src_ip": src_ip,
                                    "unique_id": unique_id,
                                    "rule_index": rule_index,
                                    "expiration": expiration.isoformat() if expiration else "permanent",
                                    "previous_blocks": previous_blocks
                                }
                                tracking_events.append(tracking_event)
                            except Exception as e:
                                print(f"Failed to add rule for VM {vmid}, IP {src_ip}: {e}")
            position = f.tell()

    now = datetime.datetime.now(pytz.utc)
    # Remove expired block rules (only if expiration is not None)
    for key in list(state['blocked']):
        blocked_entry = state['blocked'][key]
        if blocked_entry['expiration'] is not None and blocked_entry['expiration'] < now:
            vmid, src_ip = key.split(':', 1)
            unique_id = blocked_entry['unique_id']
            try:
                rules = PROXMOX.nodes(NODE).qemu(vmid).firewall.rules.get()
                for rule in rules:
                    if rule.get('comment', '').endswith(f"ID: {unique_id}"):
                        PROXMOX.nodes(NODE).qemu(vmid).firewall.rules(rule['pos']).delete()
                        break
                del state['blocked'][key]
            except Exception as e:
                print(f"Failed to remove rule for VM {vmid}, IP {src_ip}: {e}")

    # Save state to file
    state_to_save = {
        'log_file_inode': current_inode,
        'log_file_position': position,
        'drops': {key: [ts.isoformat() for ts in deq] for key, deq in state['drops'].items()},
        'blocked': {
            key: {
                'rule_index': val['rule_index'],
                'expiration': val['expiration'].isoformat() if val['expiration'] is not None else None,
                'unique_id': val['unique_id']
            } for key, val in state['blocked'].items()
        }
    }
    with open(STATE_FILE, 'w') as f:
        json.dump(state_to_save, f)

    # Save tracking events
    with open(TRACKING_FILE, 'w') as tf:
        json.dump(tracking_events, tf, indent=4)

if __name__ == "__main__":
    main()