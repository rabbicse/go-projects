#!/bin/bash
set -e

echo "Starting replica setup..."

# Stop PostgreSQL if it's already running to perform the base backup
pg_ctl -D "$PGDATA" -m fast -w stop

# Ensure the data directory is clean before the base backup
echo "Removing old data from $PGDATA..."
rm -rf "$PGDATA"/*

# Perform a base backup from the master. The PGPASSWORD env variable is used here.
# -P is for progress, -R is for the recovery.conf file.
until pg_basebackup -h postgres-master -U replicator -D "$PGDATA" -P -R; do
  echo 'Waiting for postgres-master to be ready for replication...';
  sleep 2;
done

# Start PostgreSQL
echo "Starting PostgreSQL replica..."
postgres -c hot_standby=on

echo "Replica setup complete."