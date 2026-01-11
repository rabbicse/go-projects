# PostgreSQL Replication with Docker

A hands-on implementation of PostgreSQL database replication using Docker, demonstrating high availability through master-slave configuration. This project showcases database replication, failover scenarios, and container orchestration skills using Docker Compose.

## Overview

This project implements:
- Primary-Standby PostgreSQL replication
- Write-Ahead Logging (WAL) configuration
- Automated container orchestration
- Data persistence across container restarts
- Basic failover handling

## Prerequisites

- Docker Engine
- Docker Compose
- Git

## Project Structure

```
├── docker-compose.yml
├── postgres-1/
│   └── config/
│       ├── postgresql.conf
│       └── pg_hba.conf
└── postgres-2/
    └── config/
        ├── postgresql.conf
        └── pg_hba.conf
```

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/pawarspeaks/postgresql-cluster.git
cd postgresql-cluster
```

2. Launch the cluster:
```bash
docker-compose up -d
```

3. Verify cluster status:
```bash
docker-compose ps
```

## Testing Replication

1. Connect to primary node:
```bash
docker exec -it postgres-1 psql -U postgres
```

2. Check replication status:
```sql
SELECT * FROM pg_stat_replication;
```

## Testing Failover

1. Simulate primary node failure:
```bash
docker-compose stop postgres-1
```

2. Verify secondary node status:
```bash
docker exec -it postgres-2 psql -U postgres -c "SELECT pg_is_in_recovery();"
```

## Configuration Details

Key configuration files:
- `postgresql.conf`: Contains replication settings like WAL configuration
- `pg_hba.conf`: Manages host-based authentication for replication
- `docker-compose.yml`: Orchestrates the PostgreSQL containers

## Author

@Pawarspeaks