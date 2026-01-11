#!/bin/bash
set -e

# Run SQL commands using psql
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Create replication user
    CREATE USER replicator WITH REPLICATION ENCRYPTED PASSWORD 'replicatorpass';
EOSQL

# Add pg_hba.conf entries directly via shell commands
# This allows replication connections
echo "host replication replicator 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"
# This allows standard connections for the pgpool health check
echo "host all replicator 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"

echo "Master setup complete."