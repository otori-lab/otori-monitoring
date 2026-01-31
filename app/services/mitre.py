"""
MITRE ATT&CK Mapper.
Mappe les activités observées vers le framework MITRE ATT&CK.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MitreTechnique:
    """Une technique MITRE ATT&CK."""

    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    description: str
    url: str

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "description": self.description,
            "url": self.url,
        }


@dataclass
class MitreMapping:
    """Résultat du mapping MITRE."""

    techniques: list[MitreTechnique] = field(default_factory=list)
    tactics_coverage: dict[str, int] = field(default_factory=dict)
    attack_phase: str = "unknown"
    kill_chain_progress: float = 0.0

    def to_dict(self) -> dict:
        return {
            "techniques": [t.to_dict() for t in self.techniques],
            "tactics_coverage": self.tactics_coverage,
            "attack_phase": self.attack_phase,
            "kill_chain_progress": round(self.kill_chain_progress, 2),
        }


# Base de données des techniques MITRE ATT&CK (subset pertinent pour honeypots)
MITRE_TECHNIQUES = {
    # ═══════════════════════════════════════════════════════════════════════════
    # RECONNAISSANCE (TA0043)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1595": MitreTechnique(
        "T1595", "Active Scanning", "Reconnaissance", "TA0043",
        "Adversary scans victim infrastructure",
        "https://attack.mitre.org/techniques/T1595"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # INITIAL ACCESS (TA0001)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1078": MitreTechnique(
        "T1078", "Valid Accounts", "Initial Access", "TA0001",
        "Use of valid credentials for initial access",
        "https://attack.mitre.org/techniques/T1078"
    ),
    "T1110": MitreTechnique(
        "T1110", "Brute Force", "Credential Access", "TA0006",
        "Attempting to gain access via password guessing",
        "https://attack.mitre.org/techniques/T1110"
    ),
    "T1110.001": MitreTechnique(
        "T1110.001", "Password Guessing", "Credential Access", "TA0006",
        "Brute force using common passwords",
        "https://attack.mitre.org/techniques/T1110/001"
    ),
    "T1110.002": MitreTechnique(
        "T1110.002", "Password Cracking", "Credential Access", "TA0006",
        "Offline password hash cracking",
        "https://attack.mitre.org/techniques/T1110/002"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # EXECUTION (TA0002)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1059": MitreTechnique(
        "T1059", "Command and Scripting Interpreter", "Execution", "TA0002",
        "Use of command-line interfaces",
        "https://attack.mitre.org/techniques/T1059"
    ),
    "T1059.004": MitreTechnique(
        "T1059.004", "Unix Shell", "Execution", "TA0002",
        "Use of Unix shell for command execution",
        "https://attack.mitre.org/techniques/T1059/004"
    ),
    "T1059.006": MitreTechnique(
        "T1059.006", "Python", "Execution", "TA0002",
        "Use of Python for execution",
        "https://attack.mitre.org/techniques/T1059/006"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # PERSISTENCE (TA0003)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1053": MitreTechnique(
        "T1053", "Scheduled Task/Job", "Persistence", "TA0003",
        "Use of task scheduling for persistence",
        "https://attack.mitre.org/techniques/T1053"
    ),
    "T1053.003": MitreTechnique(
        "T1053.003", "Cron", "Persistence", "TA0003",
        "Use of cron for persistence",
        "https://attack.mitre.org/techniques/T1053/003"
    ),
    "T1136": MitreTechnique(
        "T1136", "Create Account", "Persistence", "TA0003",
        "Creating new accounts for persistence",
        "https://attack.mitre.org/techniques/T1136"
    ),
    "T1136.001": MitreTechnique(
        "T1136.001", "Local Account", "Persistence", "TA0003",
        "Creating local accounts",
        "https://attack.mitre.org/techniques/T1136/001"
    ),
    "T1098": MitreTechnique(
        "T1098", "Account Manipulation", "Persistence", "TA0003",
        "Modifying account properties",
        "https://attack.mitre.org/techniques/T1098"
    ),
    "T1098.004": MitreTechnique(
        "T1098.004", "SSH Authorized Keys", "Persistence", "TA0003",
        "Adding SSH keys for persistence",
        "https://attack.mitre.org/techniques/T1098/004"
    ),
    "T1037": MitreTechnique(
        "T1037", "Boot or Logon Initialization Scripts", "Persistence", "TA0003",
        "Using init scripts for persistence",
        "https://attack.mitre.org/techniques/T1037"
    ),
    "T1037.004": MitreTechnique(
        "T1037.004", "RC Scripts", "Persistence", "TA0003",
        "Modifying rc.local for persistence",
        "https://attack.mitre.org/techniques/T1037/004"
    ),
    "T1543.002": MitreTechnique(
        "T1543.002", "Systemd Service", "Persistence", "TA0003",
        "Creating systemd services",
        "https://attack.mitre.org/techniques/T1543/002"
    ),
    "T1546.004": MitreTechnique(
        "T1546.004", "Unix Shell Configuration Modification", "Persistence", "TA0003",
        "Modifying shell configs (.bashrc, .profile)",
        "https://attack.mitre.org/techniques/T1546/004"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # PRIVILEGE ESCALATION (TA0004)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1548": MitreTechnique(
        "T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "TA0004",
        "Exploiting elevation mechanisms",
        "https://attack.mitre.org/techniques/T1548"
    ),
    "T1548.001": MitreTechnique(
        "T1548.001", "Setuid and Setgid", "Privilege Escalation", "TA0004",
        "Abusing SUID/SGID binaries",
        "https://attack.mitre.org/techniques/T1548/001"
    ),
    "T1548.003": MitreTechnique(
        "T1548.003", "Sudo and Sudo Caching", "Privilege Escalation", "TA0004",
        "Abusing sudo for privilege escalation",
        "https://attack.mitre.org/techniques/T1548/003"
    ),
    "T1068": MitreTechnique(
        "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "TA0004",
        "Exploiting vulnerabilities for privesc",
        "https://attack.mitre.org/techniques/T1068"
    ),
    "T1574.006": MitreTechnique(
        "T1574.006", "Dynamic Linker Hijacking", "Privilege Escalation", "TA0004",
        "LD_PRELOAD hijacking",
        "https://attack.mitre.org/techniques/T1574/006"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # DEFENSE EVASION (TA0005)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1070": MitreTechnique(
        "T1070", "Indicator Removal", "Defense Evasion", "TA0005",
        "Removing evidence of activity",
        "https://attack.mitre.org/techniques/T1070"
    ),
    "T1070.002": MitreTechnique(
        "T1070.002", "Clear Linux or Mac System Logs", "Defense Evasion", "TA0005",
        "Clearing system logs",
        "https://attack.mitre.org/techniques/T1070/002"
    ),
    "T1070.003": MitreTechnique(
        "T1070.003", "Clear Command History", "Defense Evasion", "TA0005",
        "Clearing command history",
        "https://attack.mitre.org/techniques/T1070/003"
    ),
    "T1070.004": MitreTechnique(
        "T1070.004", "File Deletion", "Defense Evasion", "TA0005",
        "Secure file deletion",
        "https://attack.mitre.org/techniques/T1070/004"
    ),
    "T1070.006": MitreTechnique(
        "T1070.006", "Timestomp", "Defense Evasion", "TA0005",
        "Modifying file timestamps",
        "https://attack.mitre.org/techniques/T1070/006"
    ),
    "T1140": MitreTechnique(
        "T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion", "TA0005",
        "Decoding obfuscated content",
        "https://attack.mitre.org/techniques/T1140"
    ),
    "T1222": MitreTechnique(
        "T1222", "File and Directory Permissions Modification", "Defense Evasion", "TA0005",
        "Modifying file permissions",
        "https://attack.mitre.org/techniques/T1222"
    ),
    "T1562.001": MitreTechnique(
        "T1562.001", "Disable or Modify Tools", "Defense Evasion", "TA0005",
        "Disabling security tools",
        "https://attack.mitre.org/techniques/T1562/001"
    ),
    "T1562.004": MitreTechnique(
        "T1562.004", "Disable or Modify System Firewall", "Defense Evasion", "TA0005",
        "Disabling firewall",
        "https://attack.mitre.org/techniques/T1562/004"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # CREDENTIAL ACCESS (TA0006)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1003": MitreTechnique(
        "T1003", "OS Credential Dumping", "Credential Access", "TA0006",
        "Dumping credentials from OS",
        "https://attack.mitre.org/techniques/T1003"
    ),
    "T1552": MitreTechnique(
        "T1552", "Unsecured Credentials", "Credential Access", "TA0006",
        "Accessing unsecured credentials",
        "https://attack.mitre.org/techniques/T1552"
    ),
    "T1552.001": MitreTechnique(
        "T1552.001", "Credentials In Files", "Credential Access", "TA0006",
        "Credentials stored in files",
        "https://attack.mitre.org/techniques/T1552/001"
    ),
    "T1552.004": MitreTechnique(
        "T1552.004", "Private Keys", "Credential Access", "TA0006",
        "Stealing private keys",
        "https://attack.mitre.org/techniques/T1552/004"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # DISCOVERY (TA0007)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1007": MitreTechnique(
        "T1007", "System Service Discovery", "Discovery", "TA0007",
        "Enumerating system services",
        "https://attack.mitre.org/techniques/T1007"
    ),
    "T1016": MitreTechnique(
        "T1016", "System Network Configuration Discovery", "Discovery", "TA0007",
        "Discovering network configuration",
        "https://attack.mitre.org/techniques/T1016"
    ),
    "T1033": MitreTechnique(
        "T1033", "System Owner/User Discovery", "Discovery", "TA0007",
        "Identifying system users",
        "https://attack.mitre.org/techniques/T1033"
    ),
    "T1046": MitreTechnique(
        "T1046", "Network Service Discovery", "Discovery", "TA0007",
        "Scanning for network services",
        "https://attack.mitre.org/techniques/T1046"
    ),
    "T1049": MitreTechnique(
        "T1049", "System Network Connections Discovery", "Discovery", "TA0007",
        "Listing network connections",
        "https://attack.mitre.org/techniques/T1049"
    ),
    "T1057": MitreTechnique(
        "T1057", "Process Discovery", "Discovery", "TA0007",
        "Listing running processes",
        "https://attack.mitre.org/techniques/T1057"
    ),
    "T1082": MitreTechnique(
        "T1082", "System Information Discovery", "Discovery", "TA0007",
        "Gathering system information",
        "https://attack.mitre.org/techniques/T1082"
    ),
    "T1083": MitreTechnique(
        "T1083", "File and Directory Discovery", "Discovery", "TA0007",
        "Listing files and directories",
        "https://attack.mitre.org/techniques/T1083"
    ),
    "T1087": MitreTechnique(
        "T1087", "Account Discovery", "Discovery", "TA0007",
        "Enumerating user accounts",
        "https://attack.mitre.org/techniques/T1087"
    ),
    "T1518": MitreTechnique(
        "T1518", "Software Discovery", "Discovery", "TA0007",
        "Enumerating installed software",
        "https://attack.mitre.org/techniques/T1518"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT (TA0008)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1021.001": MitreTechnique(
        "T1021.001", "Remote Desktop Protocol", "Lateral Movement", "TA0008",
        "RDP for lateral movement",
        "https://attack.mitre.org/techniques/T1021/001"
    ),
    "T1021.002": MitreTechnique(
        "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", "TA0008",
        "SMB for lateral movement",
        "https://attack.mitre.org/techniques/T1021/002"
    ),
    "T1021.004": MitreTechnique(
        "T1021.004", "SSH", "Lateral Movement", "TA0008",
        "SSH for lateral movement",
        "https://attack.mitre.org/techniques/T1021/004"
    ),
    "T1021.006": MitreTechnique(
        "T1021.006", "Windows Remote Management", "Lateral Movement", "TA0008",
        "WinRM for lateral movement",
        "https://attack.mitre.org/techniques/T1021/006"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # COLLECTION (TA0009)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1005": MitreTechnique(
        "T1005", "Data from Local System", "Collection", "TA0009",
        "Collecting data from local system",
        "https://attack.mitre.org/techniques/T1005"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # COMMAND AND CONTROL (TA0011)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1105": MitreTechnique(
        "T1105", "Ingress Tool Transfer", "Command and Control", "TA0011",
        "Downloading tools from external sources",
        "https://attack.mitre.org/techniques/T1105"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # EXFILTRATION (TA0010)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1048": MitreTechnique(
        "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "TA0010",
        "Data exfiltration via non-standard protocols",
        "https://attack.mitre.org/techniques/T1048"
    ),
    "T1048.003": MitreTechnique(
        "T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "Exfiltration", "TA0010",
        "Exfiltration via unencrypted channels",
        "https://attack.mitre.org/techniques/T1048/003"
    ),

    # ═══════════════════════════════════════════════════════════════════════════
    # IMPACT (TA0040)
    # ═══════════════════════════════════════════════════════════════════════════
    "T1485": MitreTechnique(
        "T1485", "Data Destruction", "Impact", "TA0040",
        "Destroying data on target systems",
        "https://attack.mitre.org/techniques/T1485"
    ),
    "T1486": MitreTechnique(
        "T1486", "Data Encrypted for Impact", "Impact", "TA0040",
        "Encrypting data (ransomware)",
        "https://attack.mitre.org/techniques/T1486"
    ),
    "T1489": MitreTechnique(
        "T1489", "Service Stop", "Impact", "TA0040",
        "Stopping critical services",
        "https://attack.mitre.org/techniques/T1489"
    ),
    "T1496": MitreTechnique(
        "T1496", "Resource Hijacking", "Impact", "TA0040",
        "Cryptomining and resource abuse",
        "https://attack.mitre.org/techniques/T1496"
    ),
    "T1499": MitreTechnique(
        "T1499", "Endpoint Denial of Service", "Impact", "TA0040",
        "Denial of service attacks",
        "https://attack.mitre.org/techniques/T1499"
    ),
    "T1529": MitreTechnique(
        "T1529", "System Shutdown/Reboot", "Impact", "TA0040",
        "Shutting down or rebooting systems",
        "https://attack.mitre.org/techniques/T1529"
    ),
}

# Ordre des tactiques dans la kill chain
TACTIC_ORDER = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]


class MitreMapper:
    """Mappe les activités vers MITRE ATT&CK."""

    def __init__(self) -> None:
        self._techniques = MITRE_TECHNIQUES
        self._tactic_order = {tid: i for i, (tid, _) in enumerate(TACTIC_ORDER)}

    def map_techniques(self, technique_ids: list[str]) -> MitreMapping:
        """
        Mappe une liste d'IDs de techniques vers leurs détails.

        Args:
            technique_ids: Liste des IDs de techniques (ex: ["T1059", "T1082"]).

        Returns:
            MitreMapping avec les techniques et statistiques.
        """
        mapping = MitreMapping()
        tactics_seen = {}

        for tid in technique_ids:
            if tid in self._techniques:
                technique = self._techniques[tid]
                mapping.techniques.append(technique)

                # Compter les tactiques
                tactic = technique.tactic
                tactics_seen[tactic] = tactics_seen.get(tactic, 0) + 1

        mapping.tactics_coverage = tactics_seen

        # Déterminer la phase d'attaque
        if tactics_seen:
            mapping.attack_phase = self._determine_phase(tactics_seen)
            mapping.kill_chain_progress = self._calculate_progress(tactics_seen)

        return mapping

    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        """Récupère une technique par son ID."""
        return self._techniques.get(technique_id)

    def _determine_phase(self, tactics: dict[str, int]) -> str:
        """Détermine la phase d'attaque principale."""
        # Trouver la tactique la plus avancée dans la kill chain
        max_order = -1
        phase = "reconnaissance"

        for tactic in tactics:
            tactic_id = next(
                (tid for tid, name in TACTIC_ORDER if name == tactic),
                None
            )
            if tactic_id and self._tactic_order.get(tactic_id, -1) > max_order:
                max_order = self._tactic_order[tactic_id]
                phase = tactic.lower().replace(" ", "_")

        return phase

    def _calculate_progress(self, tactics: dict[str, int]) -> float:
        """Calcule le progrès dans la kill chain (0.0 - 1.0)."""
        if not tactics:
            return 0.0

        # Trouver la phase la plus avancée
        max_order = -1
        for tactic in tactics:
            tactic_id = next(
                (tid for tid, name in TACTIC_ORDER if name == tactic),
                None
            )
            if tactic_id:
                order = self._tactic_order.get(tactic_id, -1)
                if order > max_order:
                    max_order = order

        if max_order < 0:
            return 0.0

        # Normaliser (0 = Recon, 13 = Impact)
        return min(1.0, (max_order + 1) / len(TACTIC_ORDER))

    def get_all_tactics(self) -> list[tuple[str, str]]:
        """Retourne toutes les tactiques dans l'ordre."""
        return TACTIC_ORDER.copy()


# Singleton
mitre_mapper = MitreMapper()
