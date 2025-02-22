# PVEFW-Warden

PVEFW-Warden is an automated firewall blocker for Proxmox designed to detect and block IP addresses that repeatedly attempt to access your server. It tracks these IP addresses and prevents them from filling up your logs. After repeated attempts, it can permanently block offending IPs.

## Features

- Detects and blocks repeated access attempts.
- Tracks blocked IP addresses.
- Prevents logs from being filled with repeated attempts.
- Permanently blocks IPs after repeated attempts and a timeout.

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/yourusername/fw-warden.git
    cd fw-warden
    ```

2. **Install dependencies:**

    ```sh
    pip install -r requirements.txt
    ```

3. **Set up environment variables:**
    Create a `.env` file in the project root directory with the following content:

    ```properties
    # Path to the firewall log file
    LOG_FILE=/var/log/pve-firewall.log

    # Path to the JSON file that stores the firewall state
    STATE_FILE=firewall_state.json

    # Path to the JSON file used for auditing and tracking blocked IP events
    TRACKING_FILE=tracking.json

    # Proxmox node identifier
    NODE=pve01

    # Proxmox API configuration
    PROXMOX_HOST=192.168.0.100
    PROXMOX_USER=root@pam
    PROXMOX_PASSWORD=password

    # SSL verification for the Proxmox API: set to 'True' to enable, 'False' to disable
    PROXMOX_VERIFY_SSL=False

    # List of IP networks that should be excluded from blocking
    EXCLUDE_CONF=exclude.conf
    ```

4. **Configure excluded networks:**
    Create an `exclude.conf` file in the project root directory with the IP networks you want to exclude from blocking:

    ```properties
    192.168.1.0/24
    ```

5. **Run the application:**

    ```sh
    python main.py
    ```

## Configuration

- **LOG_FILE:** Path to the firewall log file.
- **STATE_FILE:** Path to the JSON file that stores the firewall state.
- **TRACKING_FILE:** Path to the JSON file used for auditing and tracking blocked IP events.
- **NODE:** Proxmox node identifier.
- **PROXMOX_HOST:** Proxmox API host.
- **PROXMOX_USER:** Proxmox API user.
- **PROXMOX_PASSWORD:** Proxmox API password.
- **PROXMOX_VERIFY_SSL:** SSL verification for the Proxmox API.
- **EXCLUDE_CONF:** Path to the file containing IP networks to exclude from blocking.

## Future Plans

The next version will focus on geolocation blocking, even if the IP initially had an allow.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
