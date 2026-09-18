# PostgreSQL and TimescaleDB Upgrades

PrintMaster's Compose examples use `timescale/timescaledb:latest-pg18` for new
deployments. The server supports PostgreSQL 18 and TimescaleDB through the
standard `pgx` driver and TimescaleDB APIs.

## Important warning

Changing `latest-pg15` to `latest-pg18` while keeping the existing
`/var/lib/postgresql` volume will not perform a PostgreSQL major upgrade.
PostgreSQL 15 and 18 use incompatible data-directory formats. The container
will normally refuse to start, and deleting the volume would destroy data.

For PG18, mount the volume at `/var/lib/postgresql`, not
`/var/lib/postgresql/data`. The PG18 image manages its version-specific data
directory below that root.

Make a tested backup before starting. Keep the old volume until the new
database has been verified.

## Existing Compose database: dump and restore

The commands below assume the database service is named `db`, the database is
named `printmaster`, and the credentials match your Compose file.

1. Check the current database and create logical backups while the old service
    is running. Record the TimescaleDB extension version:

```bash
docker compose exec -T db psql -U printmaster -d printmaster \
   -c "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb';"
docker compose exec -T db pg_dump -U printmaster -d printmaster -Fc > printmaster-pg15.dump
docker compose exec -T db pg_dumpall -U printmaster --globals-only > printmaster-globals.sql
```

The source and target must use the same TimescaleDB extension version during
the dump/restore. For example, if the source reports `2.28.1` but the PG18
image reports `2.30.1`, do not restore yet. First update the old PG15 image to
the image containing the target extension version, then update the extension
on the PG15 database and take fresh dumps:

```bash
# Run these against the original PG15 data directory, not database-18.
docker compose pull db
docker compose up -d db
docker compose exec -T db psql -U printmaster -d printmaster \
   -c "ALTER EXTENSION timescaledb UPDATE;"
docker compose exec -T db psql -U printmaster -d printmaster \
   -c "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb';"
```

Proceed only when the PG15 source version matches the PG18 target version.
Take new dump files after the extension update; do not reuse a dump created
with the older extension catalog.

2. Stop the application and database, but do not remove volumes:

```bash
docker compose stop server db
```

3. Change the database image to
   `timescale/timescaledb:latest-pg18` and change the database volume or host
   directory to a new, empty location. For the named-volume example, use a new
   volume name such as `printmaster_db_data_pg18`. Mount it at
   `/var/lib/postgresql`, not `/var/lib/postgresql/data`.

4. Start only the new database and wait for it to become healthy:

```bash
docker compose up -d db
docker compose ps db
```

5. Prepare a clean database and enable TimescaleDB. If a previous restore was
   attempted, do not retry over it: discard the failed `database-18` directory,
   create a new empty one, and start PG18 again. The Compose-created
   `printmaster` role already exists.

```bash
docker compose exec -T db psql -U printmaster -d postgres \
   -c "DROP DATABASE IF EXISTS printmaster;"
docker compose exec -T db psql -U printmaster -d postgres \
   -c "CREATE DATABASE printmaster OWNER printmaster;"
docker compose exec -T db psql -U printmaster -d printmaster \
   -c "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;"
```

6. Put TimescaleDB into restore mode, restore the complete custom-format dump,
    then leave restore mode. These hooks are important when the dump contains
    compressed hypertable chunks. Do not use `--data-only` and do not ignore
    restore errors.

```bash
docker compose exec -T db psql -U printmaster -d printmaster \
   -c "SELECT timescaledb_pre_restore();"
docker compose exec -T db pg_restore --no-owner --no-privileges \
   -U printmaster -d printmaster < printmaster-pg15.dump
docker compose exec -T db psql -U printmaster -d printmaster \
   -c "SELECT timescaledb_post_restore();"
```

The restore command must finish without `errors ignored on restore`. Errors
such as `chunk not found` indicate an incomplete restore; drop and recreate the
target database and repeat the sequence above. Never proceed to production
verification after a non-zero restore result.

If `timescaledb_post_restore()` reports a catalog version mismatch, the source
dump and target image use different TimescaleDB versions. Upgrade the source
extension, create a fresh dump, reset the target, and repeat the restore.
Changing only the PostgreSQL image is not sufficient.

If additional global objects are needed, restore them separately as a database
superuser and resolve any already-exists messages for the Compose-created role:

```bash
docker compose exec -T db psql -U printmaster -d postgres < printmaster-globals.sql
```

7. Start PrintMaster and verify login, agents, devices, metrics, hypertables,
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