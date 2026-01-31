# ═══════════════════════════════════════════════════════════════════════════════
# Otori Monitoring - API Container
# ═══════════════════════════════════════════════════════════════════════════════
# Multi-stage build optimisé pour production
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# ───────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Installer les dépendances système pour la compilation
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Installer uv (gestionnaire de packages Python ultra-rapide)
# hadolint ignore=DL3013
RUN pip install --no-cache-dir uv

# Copier les fichiers de dépendances
COPY pyproject.toml ./
COPY uv.lock* ./
COPY README.md ./

# Installer les dépendances dans un virtualenv
RUN uv venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN uv pip install --no-cache-dir .

# ───────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime
# ───────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Métadonnées
LABEL org.opencontainers.image.title="Otori Monitoring"
LABEL org.opencontainers.image.description="Honeypot monitoring and analytics platform"
LABEL org.opencontainers.image.vendor="Otori Lab"
LABEL org.opencontainers.image.source="https://github.com/otori-lab/otori-monitoring"

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_HOME=/app

WORKDIR $APP_HOME

# Installer uniquement les dépendances runtime
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copier le virtualenv depuis le builder
COPY --from=builder /opt/venv /opt/venv

# Créer un utilisateur non-root
RUN groupadd --gid 1000 otori \
    && useradd --uid 1000 --gid otori --shell /bin/bash --create-home otori

# Copier le code source
COPY --chown=otori:otori app/ ./app/
COPY --chown=otori:otori tools/ ./tools/
COPY --chown=otori:otori data/ ./data/

# Créer les répertoires nécessaires
RUN mkdir -p /app/data /app/logs \
    && chown -R otori:otori /app

# Passer à l'utilisateur non-root
USER otori

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Port exposé
EXPOSE 8000

# Commande par défaut
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
