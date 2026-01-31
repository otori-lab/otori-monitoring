"""
Service de géolocalisation IP.
Utilise MaxMind GeoLite2 pour la localisation géographique.
"""

import logging
from dataclasses import dataclass
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class GeoInfo:
    """Informations géographiques d'une IP."""

    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    asn_org: str | None = None
    is_anonymous_proxy: bool = False
    is_satellite_provider: bool = False

    def to_dict(self) -> dict:
        """Convertit en dictionnaire."""
        return {
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "is_anonymous_proxy": self.is_anonymous_proxy,
            "is_satellite_provider": self.is_satellite_provider,
        }


class GeoIPService:
    """Service de géolocalisation des adresses IP."""

    def __init__(self) -> None:
        self._reader = None
        self._asn_reader = None
        self._enabled = settings.GEOIP_ENABLED
        self._db_path = Path(settings.GEOIP_DB_PATH)
        self._initialized = False

    def _init_reader(self) -> None:
        """Initialise le lecteur GeoIP (lazy loading)."""
        if self._initialized:
            return

        self._initialized = True

        if not self._enabled:
            logger.info("GeoIP désactivé par configuration")
            return

        try:
            import geoip2.database

            if self._db_path.exists():
                self._reader = geoip2.database.Reader(str(self._db_path))
                logger.info(f"GeoIP initialisé: {self._db_path}")

                # Essayer de charger la base ASN si disponible
                asn_path = self._db_path.parent / "GeoLite2-ASN.mmdb"
                if asn_path.exists():
                    self._asn_reader = geoip2.database.Reader(str(asn_path))
                    logger.info(f"GeoIP ASN initialisé: {asn_path}")
            else:
                logger.warning(f"Base GeoIP non trouvée: {self._db_path}")
        except ImportError:
            logger.warning("Module geoip2 non installé")
        except Exception as e:
            logger.error(f"Erreur initialisation GeoIP: {e}")

    def lookup(self, ip: str) -> GeoInfo:
        """
        Recherche les informations géographiques d'une IP.

        Args:
            ip: Adresse IP à rechercher.

        Returns:
            GeoInfo avec les informations trouvées.
        """
        self._init_reader()

        info = GeoInfo()

        if not self._reader or not ip:
            return info

        # Ignorer les IPs privées
        if self._is_private_ip(ip):
            info.country_code = "PRIVATE"
            info.country_name = "Private Network"
            return info

        try:
            response = self._reader.city(ip)

            info.country_code = response.country.iso_code
            info.country_name = response.country.name
            info.city = response.city.name
            info.latitude = response.location.latitude
            info.longitude = response.location.longitude

            # Traits spéciaux
            if hasattr(response, "traits"):
                info.is_anonymous_proxy = getattr(response.traits, "is_anonymous_proxy", False)
                info.is_satellite_provider = getattr(
                    response.traits, "is_satellite_provider", False
                )

        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")

        # ASN lookup
        if self._asn_reader:
            try:
                asn_response = self._asn_reader.asn(ip)
                info.asn = asn_response.autonomous_system_number
                info.asn_org = asn_response.autonomous_system_organization
            except Exception:
                pass

        return info

    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si une IP est privée."""
        try:
            import ipaddress

            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            return False

    def close(self) -> None:
        """Ferme les lecteurs."""
        if self._reader:
            self._reader.close()
            self._reader = None
        if self._asn_reader:
            self._asn_reader.close()
            self._asn_reader = None


# Singleton
geoip_service = GeoIPService()
