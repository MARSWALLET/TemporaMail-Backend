import { and, eq, isNull } from 'drizzle-orm';
import type { Database } from './db.js';
import { planLimitsSchema, type PlanLimits } from './plans.js';
import { emailTokens, plans, users } from './schema.js';

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
