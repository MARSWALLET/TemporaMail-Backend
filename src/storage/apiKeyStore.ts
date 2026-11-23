import { and, desc, eq, isNull, sql } from 'drizzle-orm';
import type { ApiKeyScope } from '../auth/apiKey.js';
import type { Database } from './db.js';
import { apiKeys, apiKeyUsageDaily, users } from './schema.js';

export interface ApiKeyRecord {
  readonly id: string;
  readonly userId: string;
  readonly name: string;
  readonly keyPrefix: string;
  readonly last4: string;
  readonly scopes: readonly ApiKeyScope[];
  readonly createdAt: Date;
  readonly lastUsedAt: Date | null;
  readonly lastIp: string | null;
  readonly revokedAt: Date | null;
}

export interface ApiKeyLookupResult {
  readonly key: ApiKeyRecord;
  readonly userPlanId: string;
  readonly userStatus: 'active' | 'banned' | 'deleted';
}

export interface DailyUsageRow {
  readonly day: string;
  readonly count: number;
}

export interface ApiKeyStore {
  listUserApiKeys(userId: string): Promise<ApiKeyRecord[]>;
  countActiveUserApiKeys(userId: string): Promise<number>;
  createApiKey(input: {
    readonly userId: string;
    readonly name: string;
    readonly keyPrefix: string;
    readonly last4: string;
    readonly keyHash: string;
    readonly scopes: readonly ApiKeyScope[];
  }): Promise<ApiKeyRecord>;
  updateApiKey(
    userId: string,
    keyId: string,
    input: { readonly name?: string; readonly scopes?: readonly ApiKeyScope[] },
  ): Promise<ApiKeyRecord | null>;
  revokeApiKey(userId: string, keyId: string): Promise<boolean>;
  revokeAllUserApiKeys(userId: string): Promise<number>;
  findApiKeyByHash(keyHash: string): Promise<ApiKeyLookupResult | null>;
  recordApiKeyUsage(keyId: string, ip: string, day: string): Promise<void>;
  getApiKeyUsage(userId: string, keyId: string, limitDays?: number): Promise<DailyUsageRow[] | null>;
}

function mapKeyRow(row: typeof apiKeys.$inferSelect): ApiKeyRecord {
  return {
    id: row.id,
    userId: row.userId,
    name: row.name,
    keyPrefix: row.keyPrefix,
    last4: row.last4,
    scopes: row.scopes as ApiKeyScope[],
    createdAt: row.createdAt,
    lastUsedAt: row.lastUsedAt,
    lastIp: row.lastIp,
    revokedAt: row.revokedAt,
  };
}

export function createDbApiKeyStore(db: Database): ApiKeyStore {
  return {
    async listUserApiKeys(userId) {
      const rows = await db
        .select()
        .from(apiKeys)
        .where(eq(apiKeys.userId, userId))
        .orderBy(desc(apiKeys.createdAt));
      return rows.map(mapKeyRow);
    },

    async countActiveUserApiKeys(userId) {
      const [row] = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(apiKeys)
        .where(and(eq(apiKeys.userId, userId), isNull(apiKeys.revokedAt)));
      return row?.count ?? 0;
    },

    async createApiKey(input) {
      const [row] = await db
        .insert(apiKeys)
        .values({
          userId: input.userId,
          name: input.name.trim(),
          keyPrefix: input.keyPrefix,
          last4: input.last4,
          keyHash: input.keyHash,
          scopes: [...input.scopes],
        })
        .returning();
      if (!row) {
        throw new Error('Failed to create API key');
      }
      return mapKeyRow(row);
    },

    async updateApiKey(userId, keyId, input) {
      const updates: { name?: string; scopes?: string[] } = {};
      if (input.name !== undefined) {
        updates.name = input.name.trim();
      }
      if (input.scopes !== undefined) {
        updates.scopes = [...input.scopes];
      }

      const [row] = await db
        .update(apiKeys)
        .set(updates)
        .where(and(eq(apiKeys.id, keyId), eq(apiKeys.userId, userId), isNull(apiKeys.revokedAt)))
        .returning();
      return row ? mapKeyRow(row) : null;
    },

    async revokeApiKey(userId, keyId) {
      const rows = await db
        .update(apiKeys)
        .set({ revokedAt: new Date() })
        .where(and(eq(apiKeys.id, keyId), eq(apiKeys.userId, userId), isNull(apiKeys.revokedAt)))
        .returning({ id: apiKeys.id });
      return rows.length > 0;
    },

    async revokeAllUserApiKeys(userId) {
      const rows = await db
        .update(apiKeys)
        .set({ revokedAt: new Date() })
        .where(and(eq(apiKeys.userId, userId), isNull(apiKeys.revokedAt)))
        .returning({ id: apiKeys.id });
      return rows.length;
    },

    async findApiKeyByHash(keyHash) {
      const [row] = await db
        .select({
          key: apiKeys,
          userPlanId: users.planId,
          userStatus: users.status,
        })
        .from(apiKeys)
        .innerJoin(users, eq(apiKeys.userId, users.id))
        .where(eq(apiKeys.keyHash, keyHash))
        .limit(1);

      if (!row) {
        return null;
      }

      return {
        key: mapKeyRow(row.key),
        userPlanId: row.userPlanId,
        userStatus: row.userStatus as 'active' | 'banned' | 'deleted',
      };
    },

    async recordApiKeyUsage(keyId, ip, day) {
      await db
        .update(apiKeys)
        .set({ lastUsedAt: new Date(), lastIp: ip })
        .where(eq(apiKeys.id, keyId));

      await db
        .insert(apiKeyUsageDaily)
        .values({ apiKeyId: keyId, day, count: 1 })
        .onConflictDoUpdate({
          target: [apiKeyUsageDaily.apiKeyId, apiKeyUsageDaily.day],
          set: { count: sql`${apiKeyUsageDaily.count} + 1` },
        });
    },

    async getApiKeyUsage(userId, keyId, limitDays = 30) {
      const [owned] = await db
        .select({ id: apiKeys.id })
        .from(apiKeys)
        .where(and(eq(apiKeys.id, keyId), eq(apiKeys.userId, userId)))
        .limit(1);

      if (!owned) {
        return null;
      }

      const rows = await db
        .select({ day: apiKeyUsageDaily.day, count: apiKeyUsageDaily.count })
        .from(apiKeyUsageDaily)
        .where(eq(apiKeyUsageDaily.apiKeyId, keyId))
        .orderBy(desc(apiKeyUsageDaily.day))
        .limit(limitDays);

      return rows.map((r) => ({ day: r.day, count: r.count }));
    },
  };
}
