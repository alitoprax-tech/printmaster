# PostgreSQL and TimescaleDB Upgrades

PrintMaster's Compose examples use `timescale/timescaledb:latest-pg18` for new
deployments. The server supports PostgreSQL 18 and TimescaleDB through the
standard `pgx` driver and TimescaleDB APIs.

## Important warning

Changing `latest-pg15` to `latest-pg18` while keeping the existing
`/var/lib/postgresql/data` volume will not perform a PostgreSQL major upgrade.
PostgreSQL 15 and 18 use incompatible data-directory formats. The container
will normally refuse to start, and deleting the volume would destroy data.

Make a tested backup before starting. Keep the old volume until the new
database has been verified.

## Existing Compose database: dump and restore

The commands below assume the database service is named `db`, the database is
named `printmaster`, and the credentials match your Compose file.

1. Check the current database and create logical backups while the old service
   is running:

```bash
docker compose exec -T db pg_dump -U printmaster -d printmaster -Fc > printmaster-pg15.dump
docker compose exec -T db pg_dumpall -U printmaster --globals-only > printmaster-globals.sql
```

2. Stop the application and database, but do not remove volumes:

```bash
docker compose stop server db
```

3. Change the database image to
   `timescale/timescaledb:latest-pg18` and change the database volume or host
   directory to a new, empty location. For the named-volume example, use a new
   volume name such as `printmaster_db_data_pg18`.

4. Start only the new database and wait for it to become healthy:

```bash
docker compose up -d db
docker compose ps db
```

5. Restore the database dump. The TimescaleDB extension is available in the
   new image; PrintMaster will initialize its extension objects when the
   server connects. The Compose-created `printmaster` role already exists, so
   restore `printmaster-globals.sql` only if you have additional roles or
   tablespaces to migrate.

```bash
docker compose exec -T db pg_restore -U printmaster -d printmaster --clean --if-exists < printmaster-pg15.dump
```

If additional global objects are needed, restore them separately as a database
superuser and resolve any already-exists messages for the Compose-created role:

```bash
docker compose exec -T db psql -U printmaster -d postgres < printmaster-globals.sql
```

6. Start PrintMaster and verify login, agents, devices, metrics, hypertables,
   and scheduled jobs before retiring the old volume:

```bash
docker compose up -d server
docker compose logs --tail=100 server
```

Do not run `docker compose down -v` during this procedure. Remove the old
volume only after a separate restore test and application verification.

## Image updates within PostgreSQL 18

Refreshing `latest-pg18` can update the TimescaleDB patch release without a
PostgreSQL major-version migration. Still back up first, pull the image, and
recreate the database container:

```bash
docker compose pull db
docker compose up -d db
```

For production, replace the mutable `latest-pg18` tag with a tested,
date-reviewed TimescaleDB release tag and let Dependabot propose Docker image
updates through `.github/dependabot.yml`.