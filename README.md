# Otori Monitoring

Dashboard de monitoring et analytics pour honeypots Otori.

## Quick Start

### Développement local (SQLite)

```bash
# Installer les dépendances
make install

# Lancer le serveur
make run

# Dans un autre terminal, lancer le streamer
make stream
```

Accéder au dashboard : http://localhost:8000

### Docker (PostgreSQL)

```bash
# Build et démarrer
make docker-up

# Voir les logs
make docker-logs

# Arrêter
make docker-down
```

## Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  PostgreSQL  │◄───│   FastAPI    │◄───│    Nginx     │
│   (otori-db) │    │  (otori-api) │    │  (optional)  │
└──────────────┘    └──────────────┘    └──────────────┘
```

## Structure

```
otori-monitoring/
├── app/
│   ├── config.py      # Configuration (env vars)
│   ├── db.py          # Database connection
│   ├── main.py        # FastAPI application
│   ├── models.py      # SQLAlchemy models
│   ├── kpi.py         # KPI calculations
│   └── web/           # Frontend (HTML/CSS/JS)
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── nginx.conf
├── tests/
└── tools/
    └── stream_cowrie_file.py
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard HTML |
| `/health` | GET | Health check |
| `/ingest` | POST | Ingère un événement |
| `/kpi` | GET | Récupère les KPIs |
| `/sessions/recent` | GET | Sessions récentes |
| `/ws` | WebSocket | Updates temps réel |

## Configuration

Variables d'environnement (voir `.env.example`) :

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./otori.db` | URL de connexion DB |
| `ENVIRONMENT` | `development` | Environnement |
| `DEBUG` | `false` | Mode debug |
| `LOG_LEVEL` | `INFO` | Niveau de log |
| `GEOIP_ENABLED` | `true` | Activer GeoIP |

## Commandes Make

```bash
make help           # Affiche l'aide
make install        # Installe les dépendances
make dev            # Installe les dépendances dev
make run            # Lance le serveur local
make test           # Lance les tests
make lint           # Vérifie le code
make format         # Formate le code
make docker-up      # Démarre Docker
make docker-down    # Arrête Docker
make docker-logs    # Affiche les logs
```

## Licence

MIT
