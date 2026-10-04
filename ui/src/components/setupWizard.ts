// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { SetupRequest } from "../types/gateon";

/**
 * What first-run setup will keep rather than take from the wizard (ADR 0057),
 * as IsSetupRequired answers it.
 *
 * On a gateway whose configuration already names its database -- the Helm
 * chart's externalDatabase -- the wizard's database step used to submit SQLite
 * anyway. The administrator went into the configured database, global.json
 * was switched to SQLite, and the next start refused to run. With the session
 * key from GATEON_SESSION_KEY the wizard showed a generated key that was never
 * used. Setup now keeps both; these say so before the operator chooses.
 */
export interface SetupStatus {
  databaseConfigured: boolean;
  databaseDriver: string;
  /** Host, port and database, or the SQLite file; "" without the setup token. */
  databaseDescription: string;
  /** The audit database when it is not the management one. */
  loggingDatabaseDescription: string;
  sessionKeyFromEnvironment: boolean;
}

const DRIVER_LABELS: Record<string, string> = { postgres: "PostgreSQL", sqlite: "SQLite" };

/** The configured database in words: "PostgreSQL db.internal:5432/gateon", or the engine alone. */
export function configuredDatabaseLabel(status: Pick<SetupStatus, "databaseDriver" | "databaseDescription">): string {
  const engine = DRIVER_LABELS[status.databaseDriver] ?? (status.databaseDriver || "a database");
  return status.databaseDescription ? `${engine} ${status.databaseDescription}` : engine;
}

/** The logging database in words, when setup keeps the configured one. */
export function configuredLoggingLabel(status: SetupStatus): string {
  return status.loggingDatabaseDescription || "the same database as management";
}

/**
 * The request Setup is sent: the databases and the session key Setup keeps are
 * left out, so a wizard default can neither replace them nor be refused for
 * trying to.
 */
export function keepConfigured(req: SetupRequest, status: SetupStatus | null): SetupRequest {
  if (!status) return req;
  const out: SetupRequest = { ...req };
  if (status.databaseConfigured) {
    delete out.databaseUrl;
    delete out.databaseConfig;
    delete out.loggingDatabaseUrl;
    delete out.loggingDatabaseConfig;
  }
  if (status.sessionKeyFromEnvironment) {
    out.pasetoSecret = "";
  }
  return out;
}
