# Otori Monitoring

Plateforme de monitoring et analytics pour honeypots Otori. Projet de Fin d'Etudes (PFE) - ECE Paris 2025.

## Features

- Dashboard temps reel avec WebSocket
- Geolocalisation des attaquants (MaxMind GeoIP)
- Classification des commandes (100+ patterns)
- Mapping MITRE ATT&CK (~70 techniques)
- Detection de bots automatises
- Scoring de menace (0-100)
- Support multi-honeypots

## Quick Start

### Via otori-cli (recommande)

```bash
# Installer otori-cli
git clone https://github.com/otori-lab/otori-cli.git
cd otori-cli && make install

# Demarrer le monitoring
otori monitoring start

# Dashboard disponible sur http://localhost:8000
```

### Via Docker Compose

```bash
cd docker
docker compose up -d

# Dashboard : http://localhost:8000
```

### Developpement local

```bash
# Installer les dependances
make install

# Lancer le serveur (SQLite)
make run

# Dashboard : http://localhost:8000
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│    Honeypot     │────▶│    Shipper      │
│  (Cowrie/LLM)   │     │   (Sidecar)     │
└─────────────────┘     └────────┬────────┘
                                 │ POST /ingest
                                 ▼
┌─────────────────┐     ┌─────────────────┐
│   PostgreSQL    │◀────│    FastAPI      │
│   (otori-db)    │     │  (otori-api)    │
└─────────────────┘     └────────┬────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │   Dashboard     │
                        │  (SPA + Charts) │
                        └─────────────────┘
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML |
| `/health` | GET | Health check |
| `/ingest` | POST | Ingestion d'evenements |
| `/kpi` | GET | Metriques et KPIs |
| `/sessions/recent` | GET | Sessions recentes |
| `/ws` | WebSocket | Updates temps reel |

## Pages du Dashboard

1. **Overview** - KPIs globaux, timeline, authentifications
2. **Geography** - Carte mondiale des attaques
3. **Analytics** - Categories de commandes, severite, MITRE
4. **Sessions** - Detail des sessions avec scoring

## Services d'analyse

### GeoIP (`app/services/geoip.py`)
- Base MaxMind GeoLite2
- Pays, ville, coordonnees GPS
- ASN et ISP

### Classifier (`app/services/classifier.py`)
- 100+ patterns de commandes
- 11 categories : recon, credential, download, execution, persistence, etc.

### MITRE Mapper (`app/services/mitre.py`)
- ~70 techniques ATT&CK
- Mapping automatique des commandes

### Scorer (`app/services/scorer.py`)
- Score de menace 0-100
- Niveaux : info, low, medium, high, critical

### Bot Detector (`app/services/bot_detector.py`)
- Detection par signatures
- Analyse temporelle
- Patterns de scan

## Configuration

Variables d'environnement :

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./otori.db` | URL PostgreSQL ou SQLite |
| `ENVIRONMENT` | `development` | Environnement |
| `LOG_LEVEL` | `INFO` | Niveau de log |
| `GEOIP_ENABLED` | `true` | Activer la geolocalisation |
| `ANALYTICS_ENABLED` | `true` | Activer les analytics avances |

## Structure

```
otori-monitoring/
├── app/
│   ├── main.py           # FastAPI application
│   ├── models.py         # SQLAlchemy models
│   ├── db.py             # Database setup
│   ├── config.py         # Configuration
│   ├── kpi.py            # Calculs KPI
│   ├── cowrie_mapper.py  # Mapping Cowrie -> Otori
│   ├── services/         # Analytics services
│   │   ├── geoip.py
│   │   ├── classifier.py
│   │   ├── scorer.py
│   │   ├── bot_detector.py
│   │   └── mitre.py
│   └── web/              # Frontend
│       ├── index.html
│       ├── css/
│       └── js/
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── tests/
└── tools/
    └── stream_cowrie_file.py
```

## Reseau Docker

Le monitoring utilise le reseau `otori-network` pour communiquer avec les honeypots :

```bash
# Cree automatiquement par otori-cli
docker network create otori-network
```

Les honeypots deployes via `otori deploy` se connectent automatiquement a ce reseau.

## Commandes Make

```bash
make install      # Installer les dependances
make run          # Lancer en local (SQLite)
make test         # Lancer les tests
make up           # Docker Compose up
make down         # Docker Compose down
make logs         # Voir les logs Docker
```

## License

MIT
