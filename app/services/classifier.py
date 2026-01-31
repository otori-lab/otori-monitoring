"""
Classificateur de commandes.
Catégorise les commandes exécutées dans le honeypot.
"""

import re
from dataclasses import dataclass
from enum import Enum


class CommandCategory(str, Enum):
    """Catégories de commandes."""

    RECONNAISSANCE = "recon"  # Collecte d'informations système
    CREDENTIAL_ACCESS = "credential"  # Vol de credentials
    EXECUTION = "execution"  # Exécution de code/scripts
    PERSISTENCE = "persist"  # Installation de backdoors
    PRIVILEGE_ESCALATION = "privesc"  # Élévation de privilèges
    DEFENSE_EVASION = "evasion"  # Contournement de défenses
    LATERAL_MOVEMENT = "lateral"  # Mouvement latéral
    EXFILTRATION = "exfil"  # Exfiltration de données
    DOWNLOAD = "download"  # Téléchargement de malware
    IMPACT = "impact"  # Actions destructrices
    BENIGN = "benign"  # Commandes bénignes
    UNKNOWN = "unknown"  # Non classifié


class Severity(str, Enum):
    """Niveaux de sévérité."""

    CRITICAL = "critical"  # Très dangereux
    HIGH = "high"  # Dangereux
    MEDIUM = "medium"  # Modéré
    LOW = "low"  # Faible risque
    INFO = "info"  # Informatif


@dataclass
class CommandAnalysis:
    """Résultat de l'analyse d'une commande."""

    command: str
    category: CommandCategory
    severity: Severity
    description: str
    tags: list[str]
    mitre_techniques: list[str]

    def to_dict(self) -> dict:
        """Convertit en dictionnaire."""
        return {
            "command": self.command,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "tags": self.tags,
            "mitre_techniques": self.mitre_techniques,
        }


# Patterns de classification
COMMAND_PATTERNS: list[tuple[str, CommandCategory, Severity, str, list[str]]] = [
    # ═══════════════════════════════════════════════════════════════════════════
    # RECONNAISSANCE
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\buname\b",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "System info gathering",
        ["T1082"],
    ),
    (
        r"\bhostname\b",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Hostname discovery",
        ["T1082"],
    ),
    (r"\bwhoami\b", CommandCategory.RECONNAISSANCE, Severity.LOW, "User discovery", ["T1033"]),
    (r"\bid\b", CommandCategory.RECONNAISSANCE, Severity.LOW, "User/group discovery", ["T1033"]),
    (
        r"\bcat\s+/etc/passwd\b",
        CommandCategory.RECONNAISSANCE,
        Severity.MEDIUM,
        "User enumeration",
        ["T1087"],
    ),
    (
        r"\bcat\s+/etc/shadow\b",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.CRITICAL,
        "Password hash access",
        ["T1003"],
    ),
    (
        r"\bcat\s+/etc/hosts\b",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Network discovery",
        ["T1016"],
    ),
    (
        r"\bifconfig\b|\bip\s+a",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Network config discovery",
        ["T1016"],
    ),
    (
        r"\bnetstat\b|\bss\s+-",
        CommandCategory.RECONNAISSANCE,
        Severity.MEDIUM,
        "Network connections discovery",
        ["T1049"],
    ),
    (
        r"\bps\s+aux|\bps\s+-ef",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Process discovery",
        ["T1057"],
    ),
    (
        r"\btop\b|\bhtop\b",
        CommandCategory.RECONNAISSANCE,
        Severity.INFO,
        "Process monitoring",
        ["T1057"],
    ),
    (
        r"\bdf\b|\bdu\b",
        CommandCategory.RECONNAISSANCE,
        Severity.INFO,
        "Disk usage discovery",
        ["T1082"],
    ),
    (
        r"\bfree\b|\bcat\s+/proc/meminfo",
        CommandCategory.RECONNAISSANCE,
        Severity.INFO,
        "Memory info",
        ["T1082"],
    ),
    (
        r"\bcat\s+/proc/cpuinfo",
        CommandCategory.RECONNAISSANCE,
        Severity.INFO,
        "CPU info",
        ["T1082"],
    ),
    (r"\blscpu\b", CommandCategory.RECONNAISSANCE, Severity.INFO, "CPU architecture", ["T1082"]),
    (
        r"\blsb_release\b|\bcat\s+/etc/.*release",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "OS version discovery",
        ["T1082"],
    ),
    (
        r"\benv\b|\bprintenv\b",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Environment discovery",
        ["T1082"],
    ),
    (
        r"\bfind\s+/",
        CommandCategory.RECONNAISSANCE,
        Severity.MEDIUM,
        "File system enumeration",
        ["T1083"],
    ),
    (r"\blocate\b", CommandCategory.RECONNAISSANCE, Severity.LOW, "File search", ["T1083"]),
    (
        r"\bwhich\b|\bwhereis\b",
        CommandCategory.RECONNAISSANCE,
        Severity.INFO,
        "Binary location",
        ["T1083"],
    ),
    (
        r"\bls\s+-la\s+/root",
        CommandCategory.RECONNAISSANCE,
        Severity.MEDIUM,
        "Root directory enumeration",
        ["T1083"],
    ),
    (
        r"\bcat\s+/root/\.bash_history",
        CommandCategory.RECONNAISSANCE,
        Severity.HIGH,
        "Command history access",
        ["T1552"],
    ),
    (r"\bhistory\b", CommandCategory.RECONNAISSANCE, Severity.LOW, "Command history", ["T1552"]),
    (
        r"\blast\b|\blastlog\b",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Login history",
        ["T1087"],
    ),
    (
        r"\bw\b\s*$|\bwho\b",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Logged users discovery",
        ["T1033"],
    ),
    (
        r"\bcrontab\s+-l",
        CommandCategory.RECONNAISSANCE,
        Severity.MEDIUM,
        "Scheduled tasks discovery",
        ["T1053"],
    ),
    (
        r"\biptables\s+-L",
        CommandCategory.RECONNAISSANCE,
        Severity.MEDIUM,
        "Firewall rules discovery",
        ["T1016"],
    ),
    (
        r"\bsystemctl\s+list",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Service enumeration",
        ["T1007"],
    ),
    (
        r"\bservice\s+--status-all",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Service status",
        ["T1007"],
    ),
    (
        r"\bdpkg\s+-l|\brpm\s+-qa",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Installed packages",
        ["T1518"],
    ),
    (
        r"\bapt\s+list\s+--installed",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Installed packages",
        ["T1518"],
    ),
    (r"\blsmod\b", CommandCategory.RECONNAISSANCE, Severity.LOW, "Kernel modules", ["T1082"]),
    (r"\bdmesg\b", CommandCategory.RECONNAISSANCE, Severity.LOW, "Kernel messages", ["T1082"]),
    (
        r"\bcat\s+/var/log/",
        CommandCategory.RECONNAISSANCE,
        Severity.MEDIUM,
        "Log file access",
        ["T1005"],
    ),
    (r"\bnmap\b", CommandCategory.RECONNAISSANCE, Severity.HIGH, "Network scanning", ["T1046"]),
    (r"\bmasscan\b", CommandCategory.RECONNAISSANCE, Severity.HIGH, "Port scanning", ["T1046"]),
    (
        r"\barp\s+-a",
        CommandCategory.RECONNAISSANCE,
        Severity.MEDIUM,
        "ARP table discovery",
        ["T1016"],
    ),
    (
        r"\broute\b|\bip\s+route",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "Routing table",
        ["T1016"],
    ),
    (
        r"\bdig\b|\bnslookup\b|\bhost\b",
        CommandCategory.RECONNAISSANCE,
        Severity.LOW,
        "DNS lookup",
        ["T1016"],
    ),
    # ═══════════════════════════════════════════════════════════════════════════
    # CREDENTIAL ACCESS
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\bcat\s+.*\.ssh/",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.CRITICAL,
        "SSH key access",
        ["T1552.004"],
    ),
    (
        r"\bcat\s+.*id_rsa",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.CRITICAL,
        "Private key theft",
        ["T1552.004"],
    ),
    (
        r"\bcat\s+.*authorized_keys",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.HIGH,
        "SSH authorized keys",
        ["T1552.004"],
    ),
    (
        r"\bcat\s+.*\.gnupg/",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.HIGH,
        "GPG key access",
        ["T1552"],
    ),
    (
        r"\bcat\s+.*\.aws/credentials",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.CRITICAL,
        "AWS credentials",
        ["T1552.001"],
    ),
    (
        r"\bcat\s+.*\.docker/config",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.HIGH,
        "Docker credentials",
        ["T1552.001"],
    ),
    (
        r"\bcat\s+.*\.kube/config",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.HIGH,
        "Kubernetes config",
        ["T1552.001"],
    ),
    (
        r"\bcat\s+.*\.git-credentials",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.HIGH,
        "Git credentials",
        ["T1552.001"],
    ),
    (
        r"\bcat\s+.*\.netrc",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.HIGH,
        "Network credentials",
        ["T1552.001"],
    ),
    (
        r"\bcat\s+.*wp-config\.php",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.HIGH,
        "WordPress DB creds",
        ["T1552.001"],
    ),
    (
        r"\bcat\s+.*config\.php",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.MEDIUM,
        "PHP config access",
        ["T1552.001"],
    ),
    (
        r"\bcat\s+.*\.env",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.HIGH,
        "Environment secrets",
        ["T1552.001"],
    ),
    (
        r"\bstrings\b.*passwd|shadow",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.HIGH,
        "Credential extraction",
        ["T1003"],
    ),
    (
        r"\bjohn\b|\bhashcat\b",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.CRITICAL,
        "Password cracking",
        ["T1110.002"],
    ),
    (
        r"\bhydra\b|\bmedusa\b",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.CRITICAL,
        "Brute force tool",
        ["T1110"],
    ),
    (
        r"\bmimikatz\b",
        CommandCategory.CREDENTIAL_ACCESS,
        Severity.CRITICAL,
        "Credential dumping",
        ["T1003"],
    ),
    # ═══════════════════════════════════════════════════════════════════════════
    # DOWNLOAD / STAGING
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\bwget\s+http",
        CommandCategory.DOWNLOAD,
        Severity.HIGH,
        "File download via wget",
        ["T1105"],
    ),
    (
        r"\bcurl\s+.*-[oO]",
        CommandCategory.DOWNLOAD,
        Severity.HIGH,
        "File download via curl",
        ["T1105"],
    ),
    (
        r"\bcurl\s+http.*\|\s*(sh|bash)",
        CommandCategory.DOWNLOAD,
        Severity.CRITICAL,
        "Remote script execution",
        ["T1105", "T1059"],
    ),
    (
        r"\bwget\s+.*\|\s*(sh|bash)",
        CommandCategory.DOWNLOAD,
        Severity.CRITICAL,
        "Remote script execution",
        ["T1105", "T1059"],
    ),
    (r"\bftp\s+", CommandCategory.DOWNLOAD, Severity.MEDIUM, "FTP transfer", ["T1105"]),
    (r"\bscp\s+", CommandCategory.DOWNLOAD, Severity.MEDIUM, "SCP transfer", ["T1105"]),
    (r"\brsync\s+", CommandCategory.DOWNLOAD, Severity.MEDIUM, "Rsync transfer", ["T1105"]),
    (r"\btftp\s+", CommandCategory.DOWNLOAD, Severity.HIGH, "TFTP transfer", ["T1105"]),
    (
        r"\bnc\s+.*-e|\bncat\s+",
        CommandCategory.DOWNLOAD,
        Severity.CRITICAL,
        "Netcat transfer/shell",
        ["T1105"],
    ),
    (
        r"\bpython.*http\.server|SimpleHTTP",
        CommandCategory.DOWNLOAD,
        Severity.MEDIUM,
        "Python HTTP server",
        ["T1105"],
    ),
    # ═══════════════════════════════════════════════════════════════════════════
    # EXECUTION
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\bchmod\s+\+x",
        CommandCategory.EXECUTION,
        Severity.MEDIUM,
        "Make file executable",
        ["T1059"],
    ),
    (
        r"\bchmod\s+777",
        CommandCategory.EXECUTION,
        Severity.HIGH,
        "Overly permissive chmod",
        ["T1222"],
    ),
    (
        r"\bpython\s+-c",
        CommandCategory.EXECUTION,
        Severity.MEDIUM,
        "Python one-liner",
        ["T1059.006"],
    ),
    (r"\bperl\s+-e", CommandCategory.EXECUTION, Severity.MEDIUM, "Perl one-liner", ["T1059"]),
    (r"\bruby\s+-e", CommandCategory.EXECUTION, Severity.MEDIUM, "Ruby one-liner", ["T1059"]),
    (r"\bphp\s+-r", CommandCategory.EXECUTION, Severity.MEDIUM, "PHP one-liner", ["T1059"]),
    (
        r"\bbash\s+-c",
        CommandCategory.EXECUTION,
        Severity.MEDIUM,
        "Bash command execution",
        ["T1059.004"],
    ),
    (
        r"\bsh\s+-c",
        CommandCategory.EXECUTION,
        Severity.MEDIUM,
        "Shell command execution",
        ["T1059.004"],
    ),
    (r"\beval\b", CommandCategory.EXECUTION, Severity.HIGH, "Dynamic code execution", ["T1059"]),
    (r"\bexec\b", CommandCategory.EXECUTION, Severity.MEDIUM, "Process execution", ["T1059"]),
    (r"\bnohup\b", CommandCategory.EXECUTION, Severity.MEDIUM, "Background execution", ["T1059"]),
    (r"\bscreen\s+-dm", CommandCategory.EXECUTION, Severity.MEDIUM, "Detached screen", ["T1059"]),
    (r"\btmux\s+new.*-d", CommandCategory.EXECUTION, Severity.MEDIUM, "Detached tmux", ["T1059"]),
    (
        r"\bat\s+|atq\b",
        CommandCategory.EXECUTION,
        Severity.MEDIUM,
        "Scheduled execution",
        ["T1053.002"],
    ),
    (
        r"\b\./[a-zA-Z]",
        CommandCategory.EXECUTION,
        Severity.HIGH,
        "Local binary execution",
        ["T1059"],
    ),
    # ═══════════════════════════════════════════════════════════════════════════
    # PERSISTENCE
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\bcrontab\s+-e|\bcrontab\s+.*>",
        CommandCategory.PERSISTENCE,
        Severity.HIGH,
        "Cron job modification",
        ["T1053.003"],
    ),
    (
        r"echo.*>>\s*/etc/cron",
        CommandCategory.PERSISTENCE,
        Severity.CRITICAL,
        "Cron persistence",
        ["T1053.003"],
    ),
    (
        r"echo.*>>\s*.*\.bashrc",
        CommandCategory.PERSISTENCE,
        Severity.HIGH,
        "Bashrc persistence",
        ["T1546.004"],
    ),
    (
        r"echo.*>>\s*.*\.profile",
        CommandCategory.PERSISTENCE,
        Severity.HIGH,
        "Profile persistence",
        ["T1546.004"],
    ),
    (
        r"echo.*>>\s*/etc/rc\.local",
        CommandCategory.PERSISTENCE,
        Severity.CRITICAL,
        "RC local persistence",
        ["T1037.004"],
    ),
    (
        r"echo.*>>\s*.*authorized_keys",
        CommandCategory.PERSISTENCE,
        Severity.CRITICAL,
        "SSH key injection",
        ["T1098.004"],
    ),
    (
        r"\bsystemctl\s+enable",
        CommandCategory.PERSISTENCE,
        Severity.HIGH,
        "Service persistence",
        ["T1543.002"],
    ),
    (
        r"\bchkconfig\b.*on",
        CommandCategory.PERSISTENCE,
        Severity.HIGH,
        "Service persistence",
        ["T1543.002"],
    ),
    (
        r"\bupdate-rc\.d\b",
        CommandCategory.PERSISTENCE,
        Severity.HIGH,
        "Init script persistence",
        ["T1037"],
    ),
    (
        r"\buseradd\b|\badduser\b",
        CommandCategory.PERSISTENCE,
        Severity.CRITICAL,
        "User creation",
        ["T1136.001"],
    ),
    (
        r"\busermod\s+.*-aG.*sudo",
        CommandCategory.PERSISTENCE,
        Severity.CRITICAL,
        "Sudo group add",
        ["T1098"],
    ),
    (r"\bpasswd\b", CommandCategory.PERSISTENCE, Severity.HIGH, "Password change", ["T1098"]),
    (
        r"echo.*>>\s*/etc/sudoers",
        CommandCategory.PERSISTENCE,
        Severity.CRITICAL,
        "Sudoers modification",
        ["T1548.003"],
    ),
    (r"\bvisudo\b", CommandCategory.PERSISTENCE, Severity.HIGH, "Sudoers edit", ["T1548.003"]),
    (
        r"\bsed\s+.*-i.*sshd_config",
        CommandCategory.PERSISTENCE,
        Severity.CRITICAL,
        "SSH config modification",
        ["T1098"],
    ),
    # ═══════════════════════════════════════════════════════════════════════════
    # PRIVILEGE ESCALATION
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\bsudo\s+",
        CommandCategory.PRIVILEGE_ESCALATION,
        Severity.MEDIUM,
        "Sudo usage",
        ["T1548.003"],
    ),
    (
        r"\bsu\s+-?\s*$|\bsu\s+root",
        CommandCategory.PRIVILEGE_ESCALATION,
        Severity.HIGH,
        "Switch to root",
        ["T1548"],
    ),
    (
        r"\bsudo\s+-i|\bsudo\s+su",
        CommandCategory.PRIVILEGE_ESCALATION,
        Severity.HIGH,
        "Root shell",
        ["T1548.003"],
    ),
    (
        r"SUID|SGID|find.*-perm.*4000",
        CommandCategory.PRIVILEGE_ESCALATION,
        Severity.HIGH,
        "SUID binary search",
        ["T1548.001"],
    ),
    (
        r"\bcapabilities\b|getcap\b|setcap\b",
        CommandCategory.PRIVILEGE_ESCALATION,
        Severity.HIGH,
        "Capabilities manipulation",
        ["T1548"],
    ),
    (
        r"LD_PRELOAD|LD_LIBRARY_PATH",
        CommandCategory.PRIVILEGE_ESCALATION,
        Severity.CRITICAL,
        "Library injection",
        ["T1574.006"],
    ),
    (
        r"\bpkexec\b",
        CommandCategory.PRIVILEGE_ESCALATION,
        Severity.HIGH,
        "Polkit execution",
        ["T1548"],
    ),
    (
        r"\bdirtycow\b|dirty_cow",
        CommandCategory.PRIVILEGE_ESCALATION,
        Severity.CRITICAL,
        "Dirty COW exploit",
        ["T1068"],
    ),
    # ═══════════════════════════════════════════════════════════════════════════
    # DEFENSE EVASION
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\brm\s+-rf\s+/var/log",
        CommandCategory.DEFENSE_EVASION,
        Severity.CRITICAL,
        "Log deletion",
        ["T1070.002"],
    ),
    (
        r"\brm\s+.*\.bash_history",
        CommandCategory.DEFENSE_EVASION,
        Severity.HIGH,
        "History deletion",
        ["T1070.003"],
    ),
    (
        r"\bhistory\s+-c",
        CommandCategory.DEFENSE_EVASION,
        Severity.HIGH,
        "History clearing",
        ["T1070.003"],
    ),
    (
        r"\bunset\s+HISTFILE",
        CommandCategory.DEFENSE_EVASION,
        Severity.HIGH,
        "History disable",
        ["T1070.003"],
    ),
    (
        r"HISTSIZE=0|HISTFILESIZE=0",
        CommandCategory.DEFENSE_EVASION,
        Severity.HIGH,
        "History disable",
        ["T1070.003"],
    ),
    (
        r"\bshred\b|\bwipe\b",
        CommandCategory.DEFENSE_EVASION,
        Severity.HIGH,
        "Secure deletion",
        ["T1070.004"],
    ),
    (
        r"\btouch\s+-t",
        CommandCategory.DEFENSE_EVASION,
        Severity.MEDIUM,
        "Timestamp modification",
        ["T1070.006"],
    ),
    (
        r"\bchattr\s+\+i",
        CommandCategory.DEFENSE_EVASION,
        Severity.HIGH,
        "File immutability",
        ["T1222"],
    ),
    (
        r"\biptables\s+-F",
        CommandCategory.DEFENSE_EVASION,
        Severity.HIGH,
        "Firewall flush",
        ["T1562.004"],
    ),
    (
        r"\bsetenforce\s+0",
        CommandCategory.DEFENSE_EVASION,
        Severity.HIGH,
        "SELinux disable",
        ["T1562.001"],
    ),
    (
        r"\bsystemctl\s+stop.*firewall",
        CommandCategory.DEFENSE_EVASION,
        Severity.HIGH,
        "Firewall stop",
        ["T1562.004"],
    ),
    (
        r"\bkillall\s+.*av|antivirus",
        CommandCategory.DEFENSE_EVASION,
        Severity.CRITICAL,
        "AV kill",
        ["T1562.001"],
    ),
    (
        r"base64\s+-d|base64\s+--decode",
        CommandCategory.DEFENSE_EVASION,
        Severity.MEDIUM,
        "Base64 decode",
        ["T1140"],
    ),
    (
        r"\bgunzip\b|\bbunzip2\b|\bxz\s+-d",
        CommandCategory.DEFENSE_EVASION,
        Severity.LOW,
        "Decompression",
        ["T1140"],
    ),
    # ═══════════════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\bssh\s+.*@",
        CommandCategory.LATERAL_MOVEMENT,
        Severity.HIGH,
        "SSH connection",
        ["T1021.004"],
    ),
    (
        r"\bsshpass\b",
        CommandCategory.LATERAL_MOVEMENT,
        Severity.HIGH,
        "SSH password auth",
        ["T1021.004"],
    ),
    (
        r"\bpsexec\b",
        CommandCategory.LATERAL_MOVEMENT,
        Severity.CRITICAL,
        "PsExec usage",
        ["T1021.002"],
    ),
    (
        r"\bwinexe\b",
        CommandCategory.LATERAL_MOVEMENT,
        Severity.CRITICAL,
        "WinExe usage",
        ["T1021.002"],
    ),
    (
        r"\brdp\b|\brdesktop\b|\bxfreerdp\b",
        CommandCategory.LATERAL_MOVEMENT,
        Severity.HIGH,
        "RDP connection",
        ["T1021.001"],
    ),
    (
        r"\bsmb.*mount|mount.*cifs",
        CommandCategory.LATERAL_MOVEMENT,
        Severity.HIGH,
        "SMB mount",
        ["T1021.002"],
    ),
    (r"\bwmic\b", CommandCategory.LATERAL_MOVEMENT, Severity.HIGH, "WMI usage", ["T1021.006"]),
    # ═══════════════════════════════════════════════════════════════════════════
    # EXFILTRATION
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\btar\s+.*czf.*\|.*curl|nc|ssh",
        CommandCategory.EXFILTRATION,
        Severity.CRITICAL,
        "Archive exfiltration",
        ["T1048"],
    ),
    (r"\bzip\s+-r.*\|", CommandCategory.EXFILTRATION, Severity.HIGH, "Zip exfiltration", ["T1048"]),
    (
        r"\bcat\s+.*\|\s*(nc|curl|wget)",
        CommandCategory.EXFILTRATION,
        Severity.HIGH,
        "File exfiltration",
        ["T1048"],
    ),
    (
        r"curl\s+.*-d\s*@|curl\s+.*--data.*@",
        CommandCategory.EXFILTRATION,
        Severity.HIGH,
        "Data upload",
        ["T1048"],
    ),
    (
        r"\bsendmail\b|\bmail\b.*<",
        CommandCategory.EXFILTRATION,
        Severity.MEDIUM,
        "Email exfiltration",
        ["T1048.003"],
    ),
    (
        r"dns.*txt.*record|nslookup.*-type=txt",
        CommandCategory.EXFILTRATION,
        Severity.HIGH,
        "DNS exfiltration",
        ["T1048.003"],
    ),
    # ═══════════════════════════════════════════════════════════════════════════
    # IMPACT
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\brm\s+-rf\s+/",
        CommandCategory.IMPACT,
        Severity.CRITICAL,
        "System wipe attempt",
        ["T1485"],
    ),
    (r"\bdd\s+if=/dev/zero", CommandCategory.IMPACT, Severity.CRITICAL, "Disk wipe", ["T1485"]),
    (r"\bmkfs\b", CommandCategory.IMPACT, Severity.CRITICAL, "Filesystem format", ["T1485"]),
    (
        r"\bkill\s+-9\s+-1",
        CommandCategory.IMPACT,
        Severity.CRITICAL,
        "Kill all processes",
        ["T1489"],
    ),
    (
        r"\bshutdown\b|\breboot\b|\binit\s+0",
        CommandCategory.IMPACT,
        Severity.HIGH,
        "System shutdown",
        ["T1529"],
    ),
    (r"\bhalt\b|\bpoweroff\b", CommandCategory.IMPACT, Severity.HIGH, "System halt", ["T1529"]),
    (r":\(\)\{.*:\|:.*\}", CommandCategory.IMPACT, Severity.CRITICAL, "Fork bomb", ["T1499"]),
    (
        r"\bcryptsetup\b.*luksFormat",
        CommandCategory.IMPACT,
        Severity.CRITICAL,
        "Encryption/Ransomware",
        ["T1486"],
    ),
    (
        r"\bopenssl\s+enc\s+-aes",
        CommandCategory.IMPACT,
        Severity.HIGH,
        "File encryption",
        ["T1486"],
    ),
    # ═══════════════════════════════════════════════════════════════════════════
    # CRYPTO MINING
    # ═══════════════════════════════════════════════════════════════════════════
    (
        r"\bxmrig\b|\bcpuminer\b|\bminerd\b",
        CommandCategory.IMPACT,
        Severity.HIGH,
        "Crypto miner",
        ["T1496"],
    ),
    (
        r"stratum\+tcp://|pool\.",
        CommandCategory.IMPACT,
        Severity.HIGH,
        "Mining pool connection",
        ["T1496"],
    ),
    (r"\bcoinhive\b|\bmonero\b", CommandCategory.IMPACT, Severity.HIGH, "Crypto mining", ["T1496"]),
    # ═══════════════════════════════════════════════════════════════════════════
    # BENIGN (lower priority)
    # ═══════════════════════════════════════════════════════════════════════════
    (r"^ls\s*$|^ls\s+-[la]+\s*$", CommandCategory.BENIGN, Severity.INFO, "List directory", []),
    (r"^pwd\s*$", CommandCategory.BENIGN, Severity.INFO, "Print directory", []),
    (r"^cd\s+", CommandCategory.BENIGN, Severity.INFO, "Change directory", []),
    (r"^echo\s+", CommandCategory.BENIGN, Severity.INFO, "Echo command", []),
    (r"^cat\s+[^/]", CommandCategory.BENIGN, Severity.INFO, "Read file", []),
    (r"^exit\s*$|^logout\s*$", CommandCategory.BENIGN, Severity.INFO, "Session exit", []),
    (r"^clear\s*$", CommandCategory.BENIGN, Severity.INFO, "Clear screen", []),
    (r"^man\s+", CommandCategory.BENIGN, Severity.INFO, "Manual page", []),
    (r"^help\s*$|^--help", CommandCategory.BENIGN, Severity.INFO, "Help request", []),
]


class CommandClassifier:
    """Classificateur de commandes."""

    def __init__(self) -> None:
        # Compile les patterns pour performance
        self._patterns = [
            (re.compile(pattern, re.IGNORECASE), cat, sev, desc, mitre)
            for pattern, cat, sev, desc, mitre in COMMAND_PATTERNS
        ]

    def classify(self, command: str) -> CommandAnalysis:
        """
        Classifie une commande.

        Args:
            command: La commande à classifier.

        Returns:
            CommandAnalysis avec la classification.
        """
        if not command:
            return CommandAnalysis(
                command="",
                category=CommandCategory.UNKNOWN,
                severity=Severity.INFO,
                description="Empty command",
                tags=[],
                mitre_techniques=[],
            )

        command = command.strip()
        tags = []
        mitre_techniques = []

        # Chercher le premier pattern correspondant (priorité haute d'abord)
        for regex, category, severity, description, mitre in self._patterns:
            if regex.search(command):
                tags = self._extract_tags(command)
                mitre_techniques = mitre
                return CommandAnalysis(
                    command=command,
                    category=category,
                    severity=severity,
                    description=description,
                    tags=tags,
                    mitre_techniques=mitre_techniques,
                )

        # Pas de pattern trouvé
        return CommandAnalysis(
            command=command,
            category=CommandCategory.UNKNOWN,
            severity=Severity.INFO,
            description="Unclassified command",
            tags=self._extract_tags(command),
            mitre_techniques=[],
        )

    def _extract_tags(self, command: str) -> list[str]:
        """Extrait des tags de la commande."""
        tags = []

        # Détecte les URLs
        if re.search(r"https?://", command):
            tags.append("url")

        # Détecte les IPs
        if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", command):
            tags.append("ip")

        # Détecte les pipes
        if "|" in command:
            tags.append("piped")

        # Détecte les redirections
        if re.search(r">>|>|2>&1", command):
            tags.append("redirect")

        # Détecte les variables
        if "$" in command:
            tags.append("variable")

        # Détecte le background
        if command.rstrip().endswith("&"):
            tags.append("background")

        return tags

    def get_severity_score(self, severity: Severity) -> int:
        """Retourne un score numérique pour la sévérité."""
        scores = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return scores.get(severity, 0)


# Singleton
classifier = CommandClassifier()
