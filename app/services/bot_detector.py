"""
Détecteur de bots.
Analyse les sessions pour déterminer si l'attaquant est un bot ou un humain.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AttackerType(str, Enum):
    """Type d'attaquant."""

    BOT = "bot"  # Automatisé (script, botnet)
    HUMAN = "human"  # Humain
    HYBRID = "hybrid"  # Mix des deux
    UNKNOWN = "unknown"  # Impossible à déterminer


@dataclass
class BotAnalysis:
    """Résultat de l'analyse bot/humain."""

    attacker_type: AttackerType
    confidence: float  # 0.0 - 1.0
    bot_score: int  # 0 - 100
    human_score: int  # 0 - 100

    # Indicateurs
    typing_speed_suspicious: bool = False
    pattern_repetition: bool = False
    known_bot_signature: bool = False
    sequential_commands: bool = False
    timing_too_regular: bool = False
    copy_paste_detected: bool = False

    # Détails
    avg_command_interval: Optional[float] = None
    command_variance: Optional[float] = None
    unique_command_ratio: float = 0.0

    # Signatures détectées
    signatures_matched: list[str] = None

    def __post_init__(self):
        if self.signatures_matched is None:
            self.signatures_matched = []

    def to_dict(self) -> dict:
        """Convertit en dictionnaire."""
        return {
            "attacker_type": self.attacker_type.value,
            "confidence": round(self.confidence, 2),
            "bot_score": self.bot_score,
            "human_score": self.human_score,
            "typing_speed_suspicious": self.typing_speed_suspicious,
            "pattern_repetition": self.pattern_repetition,
            "known_bot_signature": self.known_bot_signature,
            "sequential_commands": self.sequential_commands,
            "timing_too_regular": self.timing_too_regular,
            "copy_paste_detected": self.copy_paste_detected,
            "avg_command_interval": self.avg_command_interval,
            "command_variance": self.command_variance,
            "unique_command_ratio": round(self.unique_command_ratio, 2),
            "signatures_matched": self.signatures_matched,
        }


class BotDetector:
    """Détecte si une session est automatisée ou humaine."""

    # Signatures connues de bots/malwares
    KNOWN_BOT_SIGNATURES = [
        # Mirai et variantes
        (r"cd\s+/tmp.*busybox", "mirai"),
        (r"cat\s+/proc/mounts.*busybox", "mirai"),
        (r"\./\w+\s+\w+\.[\w\.]+", "mirai-dropper"),

        # Autres botnets
        (r"uname\s+-a.*cat\s+/proc/cpuinfo", "botnet-recon"),
        (r"(wget|curl).*\|\s*(sh|bash)", "dropper"),
        (r"echo.*>>\s*/etc/crontab", "cron-persistence"),

        # Brute-force tools
        (r"^root$|^admin$|^password$|^123456$", "common-creds"),

        # Crypto miners
        (r"xmrig|cpuminer|minerd", "cryptominer"),
        (r"stratum\+tcp", "mining-pool"),

        # Common attack scripts
        (r"rm\s+-rf\s+/tmp/\*.*wget", "cleanup-download"),
        (r"chmod\s+777.*\./", "chmod-execute"),
        (r"nohup.*&\s*$", "background-exec"),
    ]

    # Séquences de commandes typiques de bots
    BOT_COMMAND_SEQUENCES = [
        ["uname -a", "cat /proc/cpuinfo", "free -m"],
        ["cd /tmp", "wget", "chmod", "./"],
        ["cat /etc/passwd", "cat /etc/shadow"],
        ["w", "uname -a", "cat /proc/cpuinfo"],
        ["ps aux", "kill -9", "rm -rf"],
    ]

    def __init__(self) -> None:
        # Compile les patterns
        self._signatures = [
            (re.compile(pattern, re.IGNORECASE), name)
            for pattern, name in self.KNOWN_BOT_SIGNATURES
        ]

    def analyze(
        self,
        commands: list[str],
        timestamps: Optional[list[float]] = None,
        login_attempts: int = 0,
        usernames: Optional[list[str]] = None,
        passwords: Optional[list[str]] = None,
    ) -> BotAnalysis:
        """
        Analyse une session pour détecter si c'est un bot.

        Args:
            commands: Liste des commandes exécutées.
            timestamps: Timestamps des commandes (epoch).
            login_attempts: Nombre de tentatives de login.
            usernames: Usernames tentés.
            passwords: Passwords tentés.

        Returns:
            BotAnalysis avec le résultat.
        """
        analysis = BotAnalysis(
            attacker_type=AttackerType.UNKNOWN,
            confidence=0.0,
            bot_score=0,
            human_score=0,
        )

        if not commands:
            return analysis

        # Analyse des signatures connues
        self._check_known_signatures(analysis, commands)

        # Analyse du timing
        if timestamps and len(timestamps) > 1:
            self._analyze_timing(analysis, timestamps)

        # Analyse des patterns de commandes
        self._analyze_command_patterns(analysis, commands)

        # Analyse des credentials
        if usernames or passwords:
            self._analyze_credentials(analysis, usernames or [], passwords or [])

        # Analyse des tentatives de login
        if login_attempts > 0:
            self._analyze_login_attempts(analysis, login_attempts)

        # Calculer les scores finaux
        self._calculate_final_scores(analysis)

        return analysis

    def _check_known_signatures(
        self, analysis: BotAnalysis, commands: list[str]
    ) -> None:
        """Vérifie les signatures de bots connues."""
        full_text = " ".join(commands)

        for regex, name in self._signatures:
            if regex.search(full_text):
                analysis.known_bot_signature = True
                analysis.signatures_matched.append(name)
                analysis.bot_score += 25

    def _analyze_timing(
        self, analysis: BotAnalysis, timestamps: list[float]
    ) -> None:
        """Analyse le timing entre les commandes."""
        intervals = []
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i - 1]
            if interval >= 0:
                intervals.append(interval)

        if not intervals:
            return

        avg_interval = sum(intervals) / len(intervals)
        analysis.avg_command_interval = round(avg_interval, 3)

        # Variance
        if len(intervals) > 1:
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            analysis.command_variance = round(variance, 3)

            # Timing trop régulier = bot probable
            if variance < 0.5 and len(intervals) >= 3:
                analysis.timing_too_regular = True
                analysis.bot_score += 20

        # Vitesse de frappe suspecte (< 0.5s entre commandes)
        if avg_interval < 0.5:
            analysis.typing_speed_suspicious = True
            analysis.bot_score += 30

        # Délais humains typiques (2-10s)
        if 2.0 <= avg_interval <= 10.0 and (analysis.command_variance or 0) > 2:
            analysis.human_score += 20

    def _analyze_command_patterns(
        self, analysis: BotAnalysis, commands: list[str]
    ) -> None:
        """Analyse les patterns de commandes."""
        # Ratio de commandes uniques
        unique_commands = set(commands)
        analysis.unique_command_ratio = len(unique_commands) / len(commands)

        # Répétition de patterns
        if analysis.unique_command_ratio < 0.5:
            analysis.pattern_repetition = True
            analysis.bot_score += 15

        # Détecter les séquences de bots connues
        cmd_lower = [c.lower().strip() for c in commands]
        for seq in self.BOT_COMMAND_SEQUENCES:
            if self._contains_sequence(cmd_lower, seq):
                analysis.sequential_commands = True
                analysis.bot_score += 20
                break

        # Détecter le copy-paste (commandes très longues)
        for cmd in commands:
            if len(cmd) > 200:
                analysis.copy_paste_detected = True
                analysis.bot_score += 10
                break

        # Commandes interactives = plus humain
        interactive_cmds = ["vim", "vi", "nano", "less", "more", "top", "htop"]
        if any(any(ic in cmd.lower() for ic in interactive_cmds) for cmd in commands):
            analysis.human_score += 25

        # Erreurs de typo = humain
        typo_patterns = [r"\bls\s+-la\b", r"\bcd\s+\.\.", r"\bpwd\b"]
        if any(re.search(p, " ".join(commands)) for p in typo_patterns):
            analysis.human_score += 10

    def _analyze_credentials(
        self,
        analysis: BotAnalysis,
        usernames: list[str],
        passwords: list[str],
    ) -> None:
        """Analyse les credentials utilisés."""
        # Credentials communs = bot probable
        common_users = {"root", "admin", "user", "test", "guest", "ubuntu", "pi"}
        common_passwords = {
            "123456", "password", "admin", "root", "12345678",
            "qwerty", "abc123", "111111", "123123", "admin123",
        }

        user_matches = sum(1 for u in usernames if u.lower() in common_users)
        pass_matches = sum(1 for p in passwords if p.lower() in common_passwords)

        if user_matches > 0 or pass_matches > 0:
            analysis.bot_score += min(25, (user_matches + pass_matches) * 5)

        # Credentials séquentiels = wordlist = bot
        if len(set(usernames)) < len(usernames) * 0.3:
            analysis.bot_score += 15

    def _analyze_login_attempts(
        self, analysis: BotAnalysis, login_attempts: int
    ) -> None:
        """Analyse le nombre de tentatives de login."""
        if login_attempts > 10:
            analysis.bot_score += min(30, login_attempts)
        elif login_attempts <= 3:
            analysis.human_score += 10

    def _calculate_final_scores(self, analysis: BotAnalysis) -> None:
        """Calcule les scores finaux et détermine le type."""
        # Normaliser les scores
        analysis.bot_score = min(100, analysis.bot_score)
        analysis.human_score = min(100, analysis.human_score)

        # Déterminer le type
        diff = analysis.bot_score - analysis.human_score

        if diff >= 30:
            analysis.attacker_type = AttackerType.BOT
            analysis.confidence = min(0.95, 0.5 + (diff / 100))
        elif diff <= -30:
            analysis.attacker_type = AttackerType.HUMAN
            analysis.confidence = min(0.95, 0.5 + (abs(diff) / 100))
        elif analysis.bot_score > 40 and analysis.human_score > 40:
            analysis.attacker_type = AttackerType.HYBRID
            analysis.confidence = 0.6
        else:
            analysis.attacker_type = AttackerType.UNKNOWN
            analysis.confidence = max(0.3, abs(diff) / 100)

    def _contains_sequence(
        self, commands: list[str], sequence: list[str]
    ) -> bool:
        """Vérifie si une séquence de commandes est présente."""
        seq_idx = 0
        for cmd in commands:
            if seq_idx < len(sequence) and sequence[seq_idx] in cmd:
                seq_idx += 1
                if seq_idx == len(sequence):
                    return True
        return False


# Singleton
bot_detector = BotDetector()
