-- ==============================================================================
-- ScamON Enterprise Email Analysis Agent - PostgreSQL + pgvector Initialization
-- ==============================================================================

-- Enable vector extension for pgvector semantic search
CREATE EXTENSION IF NOT EXISTS vector;

-- Enable UUID extension for unique primary keys
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Log verification of extension status
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'vector'
    ) THEN
        RAISE NOTICE 'pgvector extension successfully activated.';
    ELSE
        RAISE EXCEPTION 'pgvector extension activation failed.';
    END IF;
END $$;
