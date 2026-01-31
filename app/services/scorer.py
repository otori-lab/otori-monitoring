"""
Service de scoring des sessions.
Évalue le niveau de dangerosité d'une session basé sur ses activités.
"""

from dataclasses import dataclass, field
from enum import Enum

from app.services.classifier import (
    CommandAnalysis,
    CommandCategory,
    Severity,
    classifier,
)


class DangerLevel(str, Enum):
    """Niveaux de danger d'une session."""

    CRITICAL = "critical"  # Attaque active confirmée
    HIGH = "high"  # Comportement très suspect
    MEDIUM = "medium"  # Activité suspecte
    LOW = "low"  # Légèrement suspect
    MINIMAL = "minimal"  # Probablement bénin


@dataclass
class SessionScore:
    """Score de dangerosité d'une session."""

    # Score total (0-100)
    total_score: int = 0

    # Niveau de danger
    danger_level: DangerLevel = DangerLevel.MINIMAL

    # Composants du score
    command_score: int = 0
    credential_score: int = 0
    persistence_score: int = 0
    evasion_score: int = 0
    lateral_score: int = 0
    exfil_score: int = 0
    impact_score: int = 0

    # Statistiques
    total_commands: int = 0
    critical_commands: int = 0
    high_commands: int = 0
    unique_categories: int = 0

    # Facteurs aggravants
    has_download: bool = False
    has_execution: bool = False
    has_persistence: bool = False
    has_credential_access: bool = False
    has_lateral_movement: bool = False
    has_exfiltration: bool = False
    has_impact: bool = False

    # MITRE techniques observées
    mitre_techniques: list[str] = field(default_factory=list)

    # Résumé
    summary: str = ""

    def to_dict(self) -> dict:
        """Convertit en dictionnaire."""
        return {
            "total_score": self.total_score,
            "danger_level": self.danger_level.value,
            "command_score": self.command_score,
            "credential_score": self.credential_score,
            "persistence_score": self.persistence_score,
            "evasion_score": self.evasion_score,
            "lateral_score": self.lateral_score,
            "exfil_score": self.exfil_score,
            "impact_score": self.impact_score,
            "total_commands": self.total_commands,
            "critical_commands": self.critical_commands,
            "high_commands": self.high_commands,
            "unique_categories": self.unique_categories,
            "has_download": self.has_download,
            "has_execution": self.has_execution,
            "has_persistence": self.has_persistence,
            "has_credential_access": self.has_credential_access,
            "has_lateral_movement": self.has_lateral_movement,
            "has_exfiltration": self.has_exfiltration,
            "has_impact": self.has_impact,
            "mitre_techniques": self.mitre_techniques,
            "summary": self.summary,
        }


class SessionScorer:
    """Évalue le niveau de dangerosité des sessions."""

    # Points par niveau de sévérité
    SEVERITY_POINTS = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 1,
    }

    # Points bonus par catégorie (pour diversité d'attaque)
    CATEGORY_BONUS = {
        CommandCategory.CREDENTIAL_ACCESS: 15,
        CommandCategory.PERSISTENCE: 20,
        CommandCategory.PRIVILEGE_ESCALATION: 15,
        CommandCategory.LATERAL_MOVEMENT: 15,
        CommandCategory.EXFILTRATION: 20,
        CommandCategory.IMPACT: 25,
        CommandCategory.DOWNLOAD: 10,
        CommandCategory.DEFENSE_EVASION: 10,
    }

    # Seuils de danger
    DANGER_THRESHOLDS = {
        DangerLevel.CRITICAL: 80,
        DangerLevel.HIGH: 50,
        DangerLevel.MEDIUM: 25,
        DangerLevel.LOW: 10,
    }

    def __init__(self) -> None:
        self._classifier = classifier

    def score_session(
        self,
        commands: list[str],
        login_success: bool = False,
        login_attempts: int = 0,
        duration_sec: float | None = None,
    ) -> SessionScore:
        """
        Calcule le score de dangerosité d'une session.

        Args:
            commands: Liste des commandes exécutées.
            login_success: Si le login a réussi.
            login_attempts: Nombre de tentatives de login.
            duration_sec: Durée de la session en secondes.

        Returns:
            SessionScore avec l'évaluation complète.
        """
        score = SessionScore()
        categories_seen = set()
        all_mitre = set()

        # Analyser chaque commande
        for cmd in commands:
            if not cmd:
                continue

            analysis = self._classifier.classify(cmd)
            score.total_commands += 1

            # Points de sévérité
            points = self.SEVERITY_POINTS.get(analysis.severity, 0)
            score.command_score += points

            # Compteurs de sévérité
            if analysis.severity == Severity.CRITICAL:
                score.critical_commands += 1
            elif analysis.severity == Severity.HIGH:
                score.high_commands += 1

            # Tracker les catégories
            categories_seen.add(analysis.category)

            # Tracker MITRE
            all_mitre.update(analysis.mitre_techniques)

            # Points par catégorie spécifique
            self._add_category_score(score, analysis)

        # Bonus pour diversité de catégories
        score.unique_categories = len(categories_seen)
        for cat in categories_seen:
            if cat in self.CATEGORY_BONUS:
                score.command_score += self.CATEGORY_BONUS[cat]

        # Facteurs supplémentaires
        self._add_behavioral_factors(score, login_success, login_attempts, duration_sec)

        # Calculer le score total
        score.total_score = min(
            100,
            sum(
                [
                    score.command_score,
                    score.credential_score,
                    score.persistence_score,
                    score.evasion_score,
                    score.lateral_score,
                    score.exfil_score,
                    score.impact_score,
                ]
            ),
        )

        # Déterminer le niveau de danger
        score.danger_level = self._determine_danger_level(score)

        # MITRE techniques
        score.mitre_techniques = sorted(all_mitre)

        # Générer le résumé
        score.summary = self._generate_summary(score)

        return score

    def _add_category_score(self, score: SessionScore, analysis: CommandAnalysis) -> None:
        """Ajoute les points spécifiques à la catégorie."""
        cat = analysis.category
        points = self.SEVERITY_POINTS.get(analysis.severity, 0)

        if cat == CommandCategory.CREDENTIAL_ACCESS:
            score.credential_score += points
            score.has_credential_access = True

        elif cat == CommandCategory.PERSISTENCE:
            score.persistence_score += points
            score.has_persistence = True

        elif cat == CommandCategory.DEFENSE_EVASION:
            score.evasion_score += points

        elif cat == CommandCategory.LATERAL_MOVEMENT:
            score.lateral_score += points
            score.has_lateral_movement = True

        elif cat == CommandCategory.EXFILTRATION:
            score.exfil_score += points
            score.has_exfiltration = True

        elif cat == CommandCategory.IMPACT:
            score.impact_score += points
            score.has_impact = True

        elif cat == CommandCategory.DOWNLOAD:
            score.has_download = True

        elif cat == CommandCategory.EXECUTION:
            score.has_execution = True

    def _add_behavioral_factors(
        self,
        score: SessionScore,
        login_success: bool,
        login_attempts: int,
        duration_sec: float | None,
    ) -> None:
        """Ajoute des points basés sur le comportement."""
        # Brute force détecté
        if login_attempts > 5:
            score.credential_score += min(20, login_attempts * 2)

        # Session longue avec login réussi = plus de temps pour faire des dégâts
        if login_success and duration_sec and duration_sec > 60:
            score.command_score += 5

        # Session très courte avec beaucoup de commandes = automatisé
        if duration_sec and duration_sec < 10 and score.total_commands > 5:
            score.command_score += 10

    def _determine_danger_level(self, score: SessionScore) -> DangerLevel:
        """Détermine le niveau de danger basé sur le score."""
        # Règles de promotion immédiate
        if score.has_impact and score.impact_score > 20:
            return DangerLevel.CRITICAL

        if score.critical_commands >= 2:
            return DangerLevel.CRITICAL

        if score.has_persistence and score.has_credential_access:
            return DangerLevel.CRITICAL

        if score.has_exfiltration and score.has_credential_access:
            return DangerLevel.CRITICAL

        # Basé sur le score total
        if score.total_score >= self.DANGER_THRESHOLDS[DangerLevel.CRITICAL]:
            return DangerLevel.CRITICAL
        elif score.total_score >= self.DANGER_THRESHOLDS[DangerLevel.HIGH]:
            return DangerLevel.HIGH
        elif score.total_score >= self.DANGER_THRESHOLDS[DangerLevel.MEDIUM]:
            return DangerLevel.MEDIUM
        elif score.total_score >= self.DANGER_THRESHOLDS[DangerLevel.LOW]:
            return DangerLevel.LOW
        else:
            return DangerLevel.MINIMAL

    def _generate_summary(self, score: SessionScore) -> str:
        """Génère un résumé textuel du score."""
        parts = []

        if score.danger_level == DangerLevel.CRITICAL:
            parts.append("CRITICAL THREAT")
        elif score.danger_level == DangerLevel.HIGH:
            parts.append("High risk session")
        elif score.danger_level == DangerLevel.MEDIUM:
            parts.append("Suspicious activity")
        elif score.danger_level == DangerLevel.LOW:
            parts.append("Minor concerns")
        else:
            parts.append("Normal activity")

        activities = []
        if score.has_credential_access:
            activities.append("credential theft")
        if score.has_persistence:
            activities.append("persistence")
        if score.has_lateral_movement:
            activities.append("lateral movement")
        if score.has_exfiltration:
            activities.append("data exfiltration")
        if score.has_impact:
            activities.append("destructive actions")

        if activities:
            parts.append(f"({', '.join(activities)})")

        parts.append(f"- {score.total_commands} commands")
        parts.append(f"- Score: {score.total_score}/100")

        return " ".join(parts)


# Singleton
scorer = SessionScorer()
