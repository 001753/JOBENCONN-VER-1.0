# Migration Runbook

## Verify

```sh
node --version                 # must be 24.x
npm ci
npm run prisma:status
npm run prisma:generate
npm run typecheck
```

## Development

Create and apply a reviewed migration:

```sh
npm run prisma:migrate:dev -- --name descriptive_change
```

The migration directory is committed. Never use `prisma db push` as the
production schema process.

## Deployment

Run the committed migrations before starting application traffic:

```sh
npm run prisma:migrate:deploy
npm start
```

The current baseline migration is reproducible from an empty PostgreSQL
database. Existing databases receive only unapplied versioned migrations.

## Rollback limitation

Prisma migrations in this repository do not provide an automatically safe down
migration. Rollback means restore from a verified backup or apply a new
expand/contract migration; never delete production data to reverse a schema
change.