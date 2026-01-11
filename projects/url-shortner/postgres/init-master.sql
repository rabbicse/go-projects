-- postgres/init-master.sql
-- Create replication user
CREATE USER replicator WITH REPLICATION ENCRYPTED PASSWORD 'replicatorpass';

-- Alter the PostgreSQL configuration to listen on all interfaces
ALTER SYSTEM SET listen_addresses TO '*';

-- Add a rule to the pg_hba.conf file to allow replication connections
-- from any host on the network
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_hostname = on;
ALTER SYSTEM SET log_replication_commands = on;
ALTER SYSTEM SET logging_collector = on;
ALTER SYSTEM SET log_destination = 'stderr';
ALTER SYSTEM SET pg_hba_file = '/var/lib/postgresql/data/pg_hba.conf';