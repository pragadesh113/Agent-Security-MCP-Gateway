import { describe, expect, it } from "vitest";

import {
  PersistenceUnavailableV1,
  PostgresTrajectoryStoreV1,
  postgresPersistenceConfigV1Schema
} from "../../src/index.js";

describe("PostgreSQL persistence startup boundary", () => {
  it("requires an explicit PostgreSQL URL and has no in-memory fallback", async () => {
    await expect(PostgresTrajectoryStoreV1.connectFromEnvironment({}))
      .rejects.toBeInstanceOf(PersistenceUnavailableV1);
    expect(postgresPersistenceConfigV1Schema.safeParse({
      connectionString: "sqlite:///tmp/not-accepted.db"
    }).success).toBe(false);
  });

  it("fails startup when the configured PostgreSQL dependency is unavailable", async () => {
    await expect(PostgresTrajectoryStoreV1.connect({
      connectionString: "postgresql://postgres:disposable@127.0.0.1:1/postgres",
      connectionTimeoutMs: 100
    })).rejects.toBeInstanceOf(PersistenceUnavailableV1);
  });
});
