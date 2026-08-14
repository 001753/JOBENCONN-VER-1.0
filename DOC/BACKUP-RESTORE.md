# Backup and Restore Foundation

## Current gate

**IMPLEMENTED as an operator foundation; isolated restore smoke is blocked.**

This repository does not verify a provider-managed backup retention policy or
have a separately provisioned restore database. It therefore makes no
production-grade disaster-recovery claim and does not create a fake backup
artifact.

## Required operator flow

1. Run `pg_dump --format=custom --no-owner --file=backup.dump "$DATABASE_URL"`.
2. Write a manifest containing the UTC creation time, migration status, schema
   name, source environment, and dump file SHA-256 checksum.
3. Restore into a disposable, isolated PostgreSQL database with
   `pg_restore --clean --if-exists --no-owner`.
4. Run `npm run prisma:status` against the restored URL.
5. Verify core table references, migration version, and tenant counts with
   read-only SQL.
6. Record pass/fail evidence and retain the manifest with the backup.

The source database must never be used as the restore target. A future
operations environment must provide an isolated restore URL before
`BACKUP_RESTORE_SMOKE` can be promoted to `VERIFIED`.