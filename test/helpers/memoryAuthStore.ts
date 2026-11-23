import { randomUUID } from 'node:crypto';
import type {
  AuthStore,
  EmailTokenRecord,
  OAuthAccountRecord,
  UserRecord,
} from '../../src/storage/authStore.js';
import { DEFAULT_PLAN_LIMITS, type PlanLimits } from '../../src/storage/plans.js';

export function createMemoryAuthStore() {
  const usersById = new Map<string, UserRecord>();
  const usersByEmail = new Map<string, string>();
  const oauthByKey = new Map<string, OAuthAccountRecord>();
  const tokensByHash = new Map<string, EmailTokenRecord>();
  const totpByUserId = new Map<string, string>();
  const recoveryByUserId = new Map<string, Map<string, Date | null>>();

  const store: AuthStore = {
    async findUserByEmail(email) {
      const id = usersByEmail.get(email.trim().toLowerCase());
      return id ? (usersById.get(id) ?? null) : null;
    },
    async findUserById(id) {
      return usersById.get(id) ?? null;
    },
    async createUser(input) {
      const email = input.email.trim().toLowerCase();
      const user: UserRecord = {
        id: randomUUID(),
        email,
        passwordHash: input.passwordHash,
        emailVerifiedAt: input.emailVerifiedAt ?? null,
        planId: input.planId ?? 'free',
        status: 'active',
        totpEnabled: false,
        createdAt: new Date(),
        lastLoginAt: null,
      };
      usersById.set(user.id, user);
      usersByEmail.set(email, user.id);
      return user;
    },
    async markEmailVerified(userId) {
      const existing = usersById.get(userId);
      if (!existing) return null;
      const updated: UserRecord = { ...existing, emailVerifiedAt: new Date() };
      usersById.set(userId, updated);
      return updated;
    },
    async updatePasswordHash(userId, passwordHash) {
      const existing = usersById.get(userId);
      if (!existing) return;
      usersById.set(userId, { ...existing, passwordHash });
    },
    async updateLastLogin(userId) {
      const existing = usersById.get(userId);
      if (!existing) return;
      usersById.set(userId, { ...existing, lastLoginAt: new Date() });
    },
    async deleteUser(userId) {
      const existing = usersById.get(userId);
      if (existing) {
        usersByEmail.delete(existing.email);
        usersById.delete(userId);
      }
      totpByUserId.delete(userId);
      recoveryByUserId.delete(userId);
    },
    async createEmailToken(input) {
      const record: EmailTokenRecord = {
        id: randomUUID(),
        userId: input.userId,
        type: input.type,
        targetEmail: input.targetEmail ?? null,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt,
        usedAt: null,
      };
      tokensByHash.set(input.tokenHash, record);
      return record;
    },
    async consumeEmailToken(tokenHash, type) {
      const record = tokensByHash.get(tokenHash);
      if (!record || record.type !== type || record.usedAt !== null) {
        return null;
      }
      if (record.expiresAt.getTime() < Date.now()) {
        return null;
      }
      const consumed: EmailTokenRecord = { ...record, usedAt: new Date() };
      tokensByHash.set(tokenHash, consumed);
      return consumed;
    },
    async findOAuthAccount(provider, providerUserId) {
      return oauthByKey.get(`${provider}:${providerUserId}`) ?? null;
    },
    async linkOAuthAccount(input) {
      const rec: OAuthAccountRecord = {
        id: randomUUID(),
        userId: input.userId,
        provider: input.provider,
        providerUserId: input.providerUserId,
        email: input.email.toLowerCase(),
        createdAt: new Date(),
      };
      oauthByKey.set(`${input.provider}:${input.providerUserId}`, rec);
      return rec;
    },
    async unlinkOAuthAccount(userId, provider) {
      for (const [k, v] of oauthByKey.entries()) {
        if (v.userId === userId && v.provider === provider) {
          oauthByKey.delete(k);
          return true;
        }
      }
      return false;
    },
    async listOAuthAccounts(userId) {
      return Array.from(oauthByKey.values()).filter((v) => v.userId === userId);
    },
    async setTotpSecret(userId, secretEncrypted) {
      totpByUserId.set(userId, secretEncrypted);
    },
    async getTotpSecret(userId) {
      return totpByUserId.get(userId) ?? null;
    },
    async enableTotp(userId, recoveryCodeHashes) {
      const existing = usersById.get(userId);
      if (existing) {
        usersById.set(userId, { ...existing, totpEnabled: true });
      }
      const map = new Map<string, Date | null>();
      for (const hash of recoveryCodeHashes) {
        map.set(hash, null);
      }
      recoveryByUserId.set(userId, map);
    },
    async disableTotp(userId) {
      const existing = usersById.get(userId);
      if (existing) {
        usersById.set(userId, { ...existing, totpEnabled: false });
      }
      totpByUserId.delete(userId);
      recoveryByUserId.delete(userId);
    },
    async replaceRecoveryCodes(userId, recoveryCodeHashes) {
      const map = new Map<string, Date | null>();
      for (const hash of recoveryCodeHashes) {
        map.set(hash, null);
      }
      recoveryByUserId.set(userId, map);
    },
    async consumeRecoveryCode(userId, codeHash) {
      const map = recoveryByUserId.get(userId);
      if (!map || !map.has(codeHash) || map.get(codeHash) !== null) {
        return false;
      }
      map.set(codeHash, new Date());
      return true;
    },
    async loadPlansMap() {
      return new Map<string, PlanLimits>([
        ['anonymous', DEFAULT_PLAN_LIMITS.anonymous],
        ['free', DEFAULT_PLAN_LIMITS.free],
        ['premium', DEFAULT_PLAN_LIMITS.premium],
      ]);
    },
  };

  return { store, oauthByKey, totpByUserId };
}
