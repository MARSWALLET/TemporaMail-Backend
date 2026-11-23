import { and, desc, eq, ilike, isNull } from 'drizzle-orm';
import type { AdminRole } from '../admin/permissions.js';
import type { Database } from './db.js';
import {
  adminRecoveryCodes,
  adminUsers,
  announcements,
  apiKeys,
  reservedNames,
  users,
} from './schema.js';

export interface AdminUserRecord {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly role: AdminRole;
  readonly totpSecretEncrypted: string | null;
  readonly totpEnabled: boolean;
  readonly status: 'active' | 'disabled';
  readonly createdAt: Date;
  readonly lastLoginAt: Date | null;
}

export interface AdminManagedUserRow {
  readonly id: string;
  readonly email: string;
  readonly planId: string;
  readonly status: 'active' | 'banned' | 'deleted';
  readonly emailVerified: boolean;
  readonly totpEnabled: boolean;
  readonly createdAt: Date;
  readonly lastLoginAt: Date | null;
}

export interface AdminManagedApiKeyRow {
  readonly id: string;
  readonly userId: string;
  readonly name: string;
  readonly keyPrefix: string;
  readonly last4: string;
  readonly scopes: readonly string[];
  readonly revokedAt: Date | null;
  readonly createdAt: Date;
}

export interface ReservedNameRow {
  readonly name: string;
  readonly reason: string;
  readonly createdAt: Date;
}

export interface AnnouncementRow {
  readonly id: number;
  readonly title: string;
  readonly body: string;
  readonly severity: 'info' | 'warning' | 'critical';
  readonly active: boolean;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface AdminPanelStore {
  // Admin users
  findAdminByEmail(email: string): Promise<AdminUserRecord | null>;
  findAdminById(id: string): Promise<AdminUserRecord | null>;
  listAdminUsers(): Promise<AdminUserRecord[]>;
  createAdminUser(input: {
    readonly email: string;
    readonly passwordHash: string;
    readonly role: AdminRole;
  }): Promise<AdminUserRecord>;
  updateAdminUser(
    id: string,
    input: { readonly role?: AdminRole; readonly status?: 'active' | 'disabled' },
  ): Promise<AdminUserRecord | null>;
  setAdminTotp(
    id: string,
    secretEncrypted: string,
    enabled: boolean,
    recoveryCodeHashes?: readonly string[],
  ): Promise<void>;
  resetAdminTotp(id: string): Promise<boolean>;
  consumeAdminRecoveryCode(adminUserId: string, codeHash: string): Promise<boolean>;
  updateAdminLastLogin(id: string): Promise<void>;

  // End-user management
  searchUsers(query?: string, limit?: number): Promise<AdminManagedUserRow[]>;
  updateUserStatus(userId: string, status: 'active' | 'banned'): Promise<AdminManagedUserRow | null>;
  updateUserPlan(userId: string, planId: string): Promise<AdminManagedUserRow | null>;

  // API keys admin management
  searchApiKeys(prefix?: string, limit?: number): Promise<AdminManagedApiKeyRow[]>;
  disableApiKeyById(keyId: string): Promise<boolean>;
  disableAllApiKeysForUser(userId: string): Promise<number>;

  // Reserved names
  listReservedNames(): Promise<ReservedNameRow[]>;
  addReservedName(name: string, reason: string): Promise<ReservedNameRow>;
  deleteReservedName(name: string): Promise<boolean>;

  // Announcements
  listAnnouncements(): Promise<AnnouncementRow[]>;
  createAnnouncement(input: {
    readonly title: string;
    readonly body: string;
    readonly severity?: 'info' | 'warning' | 'critical';
    readonly active?: boolean;
  }): Promise<AnnouncementRow>;
  updateAnnouncement(
    id: number,
    input: {
      readonly title?: string;
      readonly body?: string;
      readonly severity?: 'info' | 'warning' | 'critical';
      readonly active?: boolean;
    },
  ): Promise<AnnouncementRow | null>;
}

function mapAdminUser(row: typeof adminUsers.$inferSelect): AdminUserRecord {
  return {
    id: row.id,
    email: row.email.toLowerCase(),
    passwordHash: row.passwordHash,
    role: row.role as AdminRole,
    totpSecretEncrypted: row.totpSecretEncrypted,
    totpEnabled: row.totpEnabled,
    status: row.status as 'active' | 'disabled',
    createdAt: row.createdAt,
    lastLoginAt: row.lastLoginAt,
  };
}

function mapManagedUser(row: typeof users.$inferSelect): AdminManagedUserRow {
  return {
    id: row.id,
    email: row.email.toLowerCase(),
    planId: row.planId,
    status: row.status as 'active' | 'banned' | 'deleted',
    emailVerified: row.emailVerifiedAt !== null,
    totpEnabled: row.totpEnabled,
    createdAt: row.createdAt,
    lastLoginAt: row.lastLoginAt,
  };
}

export function createDbAdminPanelStore(db: Database): AdminPanelStore {
  return {
    async findAdminByEmail(email) {
      const [row] = await db
        .select()
        .from(adminUsers)
        .where(eq(adminUsers.email, email.trim().toLowerCase()))
        .limit(1);
      return row ? mapAdminUser(row) : null;
    },

    async findAdminById(id) {
      const [row] = await db.select().from(adminUsers).where(eq(adminUsers.id, id)).limit(1);
      return row ? mapAdminUser(row) : null;
    },

    async listAdminUsers() {
      const rows = await db.select().from(adminUsers).orderBy(desc(adminUsers.createdAt));
      return rows.map(mapAdminUser);
    },

    async createAdminUser(input) {
      const [row] = await db
        .insert(adminUsers)
        .values({
          email: input.email.trim().toLowerCase(),
          passwordHash: input.passwordHash,
          role: input.role,
          status: 'active',
        })
        .returning();
      if (!row) throw new Error('Failed to create admin user');
      return mapAdminUser(row);
    },

    async updateAdminUser(id, input) {
      const updates: { role?: string; status?: string } = {};
      if (input.role !== undefined) updates.role = input.role;
      if (input.status !== undefined) updates.status = input.status;
      const [row] = await db
        .update(adminUsers)
        .set(updates)
        .where(eq(adminUsers.id, id))
        .returning();
      return row ? mapAdminUser(row) : null;
    },

    async setAdminTotp(id, secretEncrypted, enabled, recoveryCodeHashes) {
      await db
        .update(adminUsers)
        .set({ totpSecretEncrypted: secretEncrypted, totpEnabled: enabled })
        .where(eq(adminUsers.id, id));
      if (recoveryCodeHashes) {
        await db.delete(adminRecoveryCodes).where(eq(adminRecoveryCodes.adminUserId, id));
        if (recoveryCodeHashes.length > 0) {
          await db.insert(adminRecoveryCodes).values(
            recoveryCodeHashes.map((codeHash) => ({ adminUserId: id, codeHash })),
          );
        }
      }
    },

    async resetAdminTotp(id) {
      const rows = await db
        .update(adminUsers)
        .set({ totpSecretEncrypted: null, totpEnabled: false })
        .where(eq(adminUsers.id, id))
        .returning({ id: adminUsers.id });
      if (rows.length === 0) return false;
      await db.delete(adminRecoveryCodes).where(eq(adminRecoveryCodes.adminUserId, id));
      return true;
    },

    async consumeAdminRecoveryCode(adminUserId, codeHash) {
      const rows = await db
        .update(adminRecoveryCodes)
        .set({ usedAt: new Date() })
        .where(
          and(
            eq(adminRecoveryCodes.adminUserId, adminUserId),
            eq(adminRecoveryCodes.codeHash, codeHash),
            isNull(adminRecoveryCodes.usedAt),
          ),
        )
        .returning({ id: adminRecoveryCodes.id });
      return rows.length > 0;
    },

    async updateAdminLastLogin(id) {
      await db.update(adminUsers).set({ lastLoginAt: new Date() }).where(eq(adminUsers.id, id));
    },

    async searchUsers(query, limit = 50) {
      const capped = Math.min(Math.max(limit, 1), 200);
      const rows = query
        ? await db
            .select()
            .from(users)
            .where(ilike(users.email, `%${query.trim()}%`))
            .orderBy(desc(users.createdAt))
            .limit(capped)
        : await db.select().from(users).orderBy(desc(users.createdAt)).limit(capped);
      return rows.map(mapManagedUser);
    },

    async updateUserStatus(userId, status) {
      const [row] = await db
        .update(users)
        .set({ status })
        .where(eq(users.id, userId))
        .returning();
      return row ? mapManagedUser(row) : null;
    },

    async updateUserPlan(userId, planId) {
      const [row] = await db
        .update(users)
        .set({ planId })
        .where(eq(users.id, userId))
        .returning();
      return row ? mapManagedUser(row) : null;
    },

    async searchApiKeys(prefix, limit = 50) {
      const capped = Math.min(Math.max(limit, 1), 200);
      const rows = prefix
        ? await db
            .select()
            .from(apiKeys)
            .where(ilike(apiKeys.keyPrefix, `%${prefix.trim()}%`))
            .orderBy(desc(apiKeys.createdAt))
            .limit(capped)
        : await db.select().from(apiKeys).orderBy(desc(apiKeys.createdAt)).limit(capped);
      return rows.map((r) => ({
        id: r.id,
        userId: r.userId,
        name: r.name,
        keyPrefix: r.keyPrefix,
        last4: r.last4,
        scopes: r.scopes,
        revokedAt: r.revokedAt,
        createdAt: r.createdAt,
      }));
    },

    async disableApiKeyById(keyId) {
      const rows = await db
        .update(apiKeys)
        .set({ revokedAt: new Date() })
        .where(and(eq(apiKeys.id, keyId), isNull(apiKeys.revokedAt)))
        .returning({ id: apiKeys.id });
      return rows.length > 0;
    },

    async disableAllApiKeysForUser(userId) {
      const rows = await db
        .update(apiKeys)
        .set({ revokedAt: new Date() })
        .where(and(eq(apiKeys.userId, userId), isNull(apiKeys.revokedAt)))
        .returning({ id: apiKeys.id });
      return rows.length;
    },

    async listReservedNames() {
      return db.select().from(reservedNames).orderBy(reservedNames.name);
    },

    async addReservedName(name, reason) {
      const [row] = await db
        .insert(reservedNames)
        .values({ name: name.trim().toLowerCase(), reason: reason.trim() || 'reserved' })
        .returning();
      if (!row) throw new Error('Failed to add reserved name');
      return row;
    },

    async deleteReservedName(name) {
      const rows = await db
        .delete(reservedNames)
        .where(eq(reservedNames.name, name.trim().toLowerCase()))
        .returning({ name: reservedNames.name });
      return rows.length > 0;
    },

    async listAnnouncements() {
      const rows = await db.select().from(announcements).orderBy(desc(announcements.id));
      return rows.map((r) => ({
        id: r.id,
        title: r.title,
        body: r.body,
        severity: r.severity as 'info' | 'warning' | 'critical',
        active: r.active,
        createdAt: r.createdAt,
        updatedAt: r.updatedAt,
      }));
    },

    async createAnnouncement(input) {
      const [row] = await db
        .insert(announcements)
        .values({
          title: input.title.trim(),
          body: input.body.trim(),
          severity: input.severity ?? 'info',
          active: input.active ?? false,
        })
        .returning();
      if (!row) throw new Error('Failed to create announcement');
      return {
        id: row.id,
        title: row.title,
        body: row.body,
        severity: row.severity as 'info' | 'warning' | 'critical',
        active: row.active,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      };
    },

    async updateAnnouncement(id, input) {
      const updates: Record<string, unknown> = { updatedAt: new Date() };
      if (input.title !== undefined) updates.title = input.title.trim();
      if (input.body !== undefined) updates.body = input.body.trim();
      if (input.severity !== undefined) updates.severity = input.severity;
      if (input.active !== undefined) updates.active = input.active;
      const [row] = await db
        .update(announcements)
        .set(updates)
        .where(eq(announcements.id, id))
        .returning();
      if (!row) return null;
      return {
        id: row.id,
        title: row.title,
        body: row.body,
        severity: row.severity as 'info' | 'warning' | 'critical',
        active: row.active,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      };
    },
  };
}
