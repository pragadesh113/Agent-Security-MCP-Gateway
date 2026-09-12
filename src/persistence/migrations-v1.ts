import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";

import type { Pool } from "pg";

const migrationFilePattern = /^(\d{4,})_[a-z0-9_]+\.sql$/u;

export interface AppliedMigrationV1 {
  readonly version: string;
  readonly filename: string;
  readonly checksum: string;
}

export async function runForwardMigrationsV1(
  pool: Pool,
  migrationsDirectory = resolve(process.cwd(), "migrations")
): Promise<readonly AppliedMigrationV1[]> {
  const entries = (await readdir(migrationsDirectory, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && migrationFilePattern.test(entry.name))
    .map((entry) => entry.name)
    .sort((left, right) => left.localeCompare(right));
  if (entries.length === 0) {
    throw new Error("No forward PostgreSQL migrations were found");
  }

  const client = await pool.connect();
  const applied: AppliedMigrationV1[] = [];
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version text PRIMARY KEY,
        filename text NOT NULL UNIQUE,
        checksum char(64) NOT NULL CHECK (checksum ~ '^[a-f0-9]{64}$'),
        applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
      )
    `);
    await client.query("SELECT pg_advisory_lock(hashtext('agent-security:migrations:v1'))");
    try {
      for (const filename of entries) {
        const match = migrationFilePattern.exec(filename);
        if (match === null) continue;
        const version = match[1];
        if (version === undefined) continue;
        const sql = await readFile(resolve(migrationsDirectory, filename), "utf8");
        const checksum = createHash("sha256").update(sql, "utf8").digest("hex");
        const existing = await client.query<{ checksum: string; filename: string }>(
          "SELECT checksum, filename FROM schema_migrations WHERE version = $1",
          [version]
        );
        if (existing.rowCount === 1) {
          const row = existing.rows[0];
          if (row === undefined || row.checksum !== checksum || row.filename !== filename) {
            throw new Error(`Applied migration ${version} does not match the repository`);
          }
          continue;
        }
        await client.query("BEGIN");
        try {
          await client.query(sql);
          await client.query(
            "INSERT INTO schema_migrations(version, filename, checksum) VALUES ($1, $2, $3)",
            [version, filename, checksum]
          );
          await client.query("COMMIT");
          applied.push({ version, filename, checksum });
        } catch (error) {
          await client.query("ROLLBACK");
          throw error;
        }
      }
    } finally {
      await client.query("SELECT pg_advisory_unlock(hashtext('agent-security:migrations:v1'))");
    }
  } finally {
    client.release();
  }
  return applied;
}
