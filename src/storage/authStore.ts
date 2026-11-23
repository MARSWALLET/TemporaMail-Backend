import { and, eq, isNull } from 'drizzle-orm';
import type { Database } from './db.js';
import { planLimitsSchema, type PlanLimits } from './plans.js';
import { emailTokens, oauthAccounts, plans, recoveryCodes, totpSecrets, users } from './schema.js';

export interface UserRecord {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string | null;
  readonly emailVerifiedAt: Date | null;
  readonly planId: string;
  readonly status: 'active' | 'banned' | 'deleted';
  readonly totpEnabled: boolean;
  readonly createdAt: Date;
  readonly lastLoginAt: Date | null;
}

export interface EmailTokenRecord {
  readonly id: string;
  readonly userId: string;
  readonly type: 'verify' | 'reset' | 'change_email';
  readonly targetEmail: string | null;
  readonly tokenHash: string;
  readonly expiresAt: Date;
  readonly usedAt: Date | null;
}

export interface OAuthAccountRecord {
  readonly id: string;
  readonly userId: string;
  readonly provider: 'google';
  readonly providerUserId: string;
  readonly email: string;
  readonly createdAt: Date;
}

export interface AuthStore {
  findUserByEmail(email: string): Promise<UserRecord | null>;
  findUserById(id: string): Promise<UserRecord | null>;
  createUser(input: {
    readonly email: string;
    readonly passwordHash: string | null;
    readonly emailVerifiedAt?: Date | null;
    readonly planId?: string;
  }): Promise<UserRecord>;
  markEmailVerified(userId: string): Promise<UserRecord | null>;
  updatePasswordHash(userId: string, passwordHash: string): Promise<void>;
  updateLastLogin(userId: string): Promise<void>;
  deleteUser(userId: string): Promise<void>;
  createEmailToken(input: {
    readonly userId: string;
    readonly type: 'verify' | 'reset' | 'change_email';
    readonly tokenHash: string;
    readonly expiresAt: Date;
    readonly targetEmail?: string | null;
  }): Promise<EmailTokenRecord>;
  consumeEmailToken(
    tokenHash: string,
    type: 'verify' | 'reset' | 'change_email',
  ): Promise<EmailTokenRecord | null>;
  findOAuthAccount(provider: 'google', providerUserId: string): Promise<OAuthAccountRecord | null>;
  linkOAuthAccount(input: {
    readonly userId: string;
    readonly provider: 'google';
    readonly providerUserId: string;
    readonly email: string;
  }): Promise<OAuthAccountRecord>;
  unlinkOAuthAccount(userId: string, provider: 'google'): Promise<boolean>;
  listOAuthAccounts(userId: string): Promise<OAuthAccountRecord[]>;
  setTotpSecret(userId: string, secretEncrypted: string): Promise<void>;
  getTotpSecret(userId: string): Promise<string | null>;
  enableTotp(userId: string, recoveryCodeHashes: readonly string[]): Promise<void>;
  disableTotp(userId: string): Promise<void>;
  replaceRecoveryCodes(userId: string, recoveryCodeHashes: readonly string[]): Promise<void>;
  consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean>;
  loadPlansMap(): Promise<Map<string, PlanLimits>>;
}

function mapUserRow(row: typeof users.$inferSelect): UserRecord {
  return {
    id: row.id,
    email: row.email.toLowerCase(),
    passwordHash: row.passwordHash,
    emailVerifiedAt: row.emailVerifiedAt,
    planId: row.planId,
    status: row.status as 'active' | 'banned' | 'deleted',
    totpEnabled: row.totpEnabled,
    createdAt: row.createdAt,
    lastLoginAt: row.lastLoginAt,
  };
}

export function createDbAuthStore(db: Database): AuthStore {
  return {
    async findUserByEmail(email) {
      const [row] = await db
        .select()
        .from(users)
        .where(eq(users.email, email.trim().toLowerCase()))
        .limit(1);
      return row ? mapUserRow(row) : null;
    },

    async findUserById(id) {
      const [row] = await db.select().from(users).where(eq(users.id, id)).limit(1);
      return row ? mapUserRow(row) : null;
    },

    async createUser(input) {
      const [row] = await db
        .insert(users)
        .values({
          email: input.email.trim().toLowerCase(),
          passwordHash: input.passwordHash,
          emailVerifiedAt: input.emailVerifiedAt ?? null,
          planId: input.planId ?? 'free',
          status: 'active',
        })
        .returning();
      if (!row) {
        throw new Error('Failed to create user');
      }
      return mapUserRow(row);
    },

    async markEmailVerified(userId) {
      const [row] = await db
        .update(users)
        .set({ emailVerifiedAt: new Date() })
        .where(eq(users.id, userId))
        .returning();
      return row ? mapUserRow(row) : null;
    },

    async updatePasswordHash(userId, passwordHash) {
      await db.update(users).set({ passwordHash }).where(eq(users.id, userId));
    },

    async updateLastLogin(userId) {
      await db.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, userId));
    },

    async deleteUser(userId) {
      await db.delete(users).where(eq(users.id, userId));
    },

    async createEmailToken(input) {
      const [row] = await db
        .insert(emailTokens)
        .values({
          userId: input.userId,
          type: input.type,
          targetEmail: input.targetEmail ?? null,
          tokenHash: input.tokenHash,
          expiresAt: input.expiresAt,
        })
        .returning();
      if (!row) {
        throw new Error('Failed to create email token');
      }
      return {
        id: row.id,
        userId: row.userId,
        type: row.type as 'verify' | 'reset' | 'change_email',
        targetEmail: row.targetEmail,
        tokenHash: row.tokenHash,
        expiresAt: row.expiresAt,
        usedAt: row.usedAt,
      };
    },

    async consumeEmailToken(tokenHash, type) {
      const now = new Date();
      const [row] = await db
        .update(emailTokens)
        .set({ usedAt: now })
        .where(
          and(
            eq(emailTokens.tokenHash, tokenHash),
            eq(emailTokens.type, type),
            isNull(emailTokens.usedAt),
          ),
        )
        .returning();

      if (!row || row.expiresAt.getTime() < now.getTime()) {
        return null;
      }

      return {
        id: row.id,
        userId: row.userId,
        type: row.type as 'verify' | 'reset' | 'change_email',
        targetEmail: row.targetEmail,
        tokenHash: row.tokenHash,
        expiresAt: row.expiresAt,
        usedAt: row.usedAt,
      };
    },

    async findOAuthAccount(provider, providerUserId) {
      const [row] = await db
        .select()
        .from(oauthAccounts)
        .where(
          and(
            eq(oauthAccounts.provider, provider),
            eq(oauthAccounts.providerUserId, providerUserId),
          ),
        )
        .limit(1);

      if (!row) return null;
      return {
        id: row.id,
        userId: row.userId,
        provider: row.provider as 'google',
        providerUserId: row.providerUserId,
        email: row.email.toLowerCase(),
        createdAt: row.createdAt,
      };
    },

    async linkOAuthAccount(input) {
      const [row] = await db
        .insert(oauthAccounts)
        .values({
          userId: input.userId,
          provider: input.provider,
          providerUserId: input.providerUserId,
          email: input.email.trim().toLowerCase(),
        })
        .returning();
      if (!row) {
        throw new Error('Failed to link OAuth account');
      }
      return {
        id: row.id,
        userId: row.userId,
        provider: row.provider as 'google',
        providerUserId: row.providerUserId,
        email: row.email.toLowerCase(),
        createdAt: row.createdAt,
      };
    },

    async unlinkOAuthAccount(userId, provider) {
      const rows = await db
        .delete(oauthAccounts)
        .where(and(eq(oauthAccounts.userId, userId), eq(oauthAccounts.provider, provider)))
        .returning({ id: oauthAccounts.id });
      return rows.length > 0;
    },

    async listOAuthAccounts(userId) {
      const rows = await db
        .select()
        .from(oauthAccounts)
        .where(eq(oauthAccounts.userId, userId));
      return rows.map((row) => ({
        id: row.id,
        userId: row.userId,
        provider: row.provider as 'google',
        providerUserId: row.providerUserId,
        email: row.email.toLowerCase(),
        createdAt: row.createdAt,
      }));
    },

    async setTotpSecret(userId, secretEncrypted) {
      await db
        .insert(totpSecrets)
        .values({ userId, secretEncrypted })
        .onConflictDoUpdate({
          target: totpSecrets.userId,
          set: { secretEncrypted, createdAt: new Date() },
        });
    },

    async getTotpSecret(userId) {
      const [row] = await db
        .select({ secretEncrypted: totpSecrets.secretEncrypted })
        .from(totpSecrets)
        .where(eq(totpSecrets.userId, userId))
        .limit(1);
      return row?.secretEncrypted ?? null;
    },

    async enableTotp(userId, recoveryCodeHashes) {
      await db.update(users).set({ totpEnabled: true }).where(eq(users.id, userId));
      await db.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId));
      if (recoveryCodeHashes.length > 0) {
        await db.insert(recoveryCodes).values(
          recoveryCodeHashes.map((codeHash) => ({
            userId,
            codeHash,
          })),
        );
      }
    },

    async disableTotp(userId) {
      await db.update(users).set({ totpEnabled: false }).where(eq(users.id, userId));
      await db.delete(totpSecrets).where(eq(totpSecrets.userId, userId));
      await db.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId));
    },

    async replaceRecoveryCodes(userId, recoveryCodeHashes) {
      await db.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId));
      if (recoveryCodeHashes.length > 0) {
        await db.insert(recoveryCodes).values(
          recoveryCodeHashes.map((codeHash) => ({
            userId,
            codeHash,
          })),
        );
      }
    },

    async consumeRecoveryCode(userId, codeHash) {
      const rows = await db
        .update(recoveryCodes)
        .set({ usedAt: new Date() })
        .where(
          and(
            eq(recoveryCodes.userId, userId),
            eq(recoveryCodes.codeHash, codeHash),
            isNull(recoveryCodes.usedAt),
          ),
        )
        .returning({ id: recoveryCodes.id });
      return rows.length > 0;
    },

    async loadPlansMap() {
      const rows = await db.select().from(plans);
      const map = new Map<string, PlanLimits>();
      for (const row of rows) {
        const parsed = planLimitsSchema.safeParse(row.limits);
        if (parsed.success) {
          map.set(row.id, parsed.data);
        }
      }
      return map;
    },
  };
}
