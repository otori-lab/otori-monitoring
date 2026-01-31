-- ═══════════════════════════════════════════════════════════════════════════════
-- Otori Monitoring - Database Initialization
-- ═══════════════════════════════════════════════════════════════════════════════
-- Ce script est exécuté automatiquement lors de la première création du container.
-- Il configure les extensions et les paramètres de performance.
-- ═══════════════════════════════════════════════════════════════════════════════

-- ───────────────────────────────────────────────────────────────────────────────
-- Extensions PostgreSQL
-- ───────────────────────────────────────────────────────────────────────────────

-- Extension pour la recherche full-text et similarity
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Extension pour les UUID (si besoin futur)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ───────────────────────────────────────────────────────────────────────────────
-- Configuration de performance
-- ───────────────────────────────────────────────────────────────────────────────

-- Ces paramètres sont appliqués pour optimiser les requêtes analytiques
-- Note: Les tables sont créées par SQLAlchemy/Alembic, pas ici

-- Commentaire informatif
COMMENT ON DATABASE otori IS 'Otori Monitoring - Honeypot analytics database';

-- ───────────────────────────────────────────────────────────────────────────────
-- Grants (au cas où on ajoute des users plus tard)
-- ───────────────────────────────────────────────────────────────────────────────

-- L'utilisateur principal a déjà tous les droits via POSTGRES_USER
-- Ces grants sont pour référence future

-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO otori;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO otori;
-- GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO otori;

-- ═══════════════════════════════════════════════════════════════════════════════
-- Fin de l'initialisation
-- ═══════════════════════════════════════════════════════════════════════════════
