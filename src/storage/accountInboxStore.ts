import { and, desc, eq, gt, lt } from 'drizzle-orm';
import type { StoredMessage } from '../pipeline/types.js';
import type { Database } from './db.js';
import { accountMessages, reservedNames, userInboxes } from './schema.js';

export interface UserInboxRecord {
  readonly id: string;
  readonly userId: string;
  readonly address: string;
  readonly customName: boolean;
  readonly createdAt: Date;
  readonly expiresAt: Date;
}

export interface StoredAccountAttachment {
  readonly index: number;
  readonly filename: string;
  readonly contentType: string;
  readonly size: number;
  readonly contentBase64: string;
}

export interface AccountInboxStore {
  isReservedName(name: string): Promise<boolean>;
  listUserInboxes(userId: string): Promise<UserInboxRecord[]>;
  findActiveInboxByAddress(address: string): Promise<UserInboxRecord | null>;
  findUserInboxById(userId: string, inboxId: string): Promise<UserInboxRecord | null>;
  createUserInbox(input: {
    readonly userId: string;
    readonly address: string;
    readonly customName: boolean;
    readonly expiresAt: Date;
  }): Promise<UserInboxRecord>;
  deleteUserInbox(userId: string, inboxId: string): Promise<UserInboxRecord | null>;
  storeAccountMessage(input: {
    readonly inboxId: string;
    readonly message: StoredMessage;
    readonly attachments: readonly StoredAccountAttachment[];
    readonly expiresAt: Date;
  }): Promise<void>;
  listAccountMessages(inboxId: string): Promise<StoredMessage[]>;
  getAccountMessage(inboxId: string, msgId: string): Promise<StoredMessage | null>;
  purgeExpired(now?: Date): Promise<{ readonly deletedInboxes: number; readonly deletedMessages: number }>;
}

function mapInboxRow(row: typeof userInboxes.$inferSelect): UserInboxRecord {
  return {
    id: row.id,
    userId: row.userId,
    address: row.address.toLowerCase(),
    customName: row.customName,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
  };
}

export function createDbAccountInboxStore(db: Database): AccountInboxStore {
  return {
    async isReservedName(name) {
      const [row] = await db
        .select({ name: reservedNames.name })
        .from(reservedNames)
        .where(eq(reservedNames.name, name.trim().toLowerCase()))
        .limit(1);
      return Boolean(row);
    },

    async listUserInboxes(userId) {
      const now = new Date();
      const rows = await db
        .select()
        .from(userInboxes)
        .where(and(eq(userInboxes.userId, userId), gt(userInboxes.expiresAt, now)))
        .orderBy(desc(userInboxes.createdAt));
      return rows.map(mapInboxRow);
    },

    async findActiveInboxByAddress(address) {
      const now = new Date();
      const [row] = await db
        .select()
        .from(userInboxes)
        .where(
          and(
            eq(userInboxes.address, address.trim().toLowerCase()),
            gt(userInboxes.expiresAt, now),
          ),
        )
        .limit(1);
      return row ? mapInboxRow(row) : null;
    },

    async findUserInboxById(userId, inboxId) {
      const now = new Date();
      const [row] = await db
        .select()
        .from(userInboxes)
        .where(
          and(
            eq(userInboxes.id, inboxId),
            eq(userInboxes.userId, userId),
            gt(userInboxes.expiresAt, now),
          ),
        )
        .limit(1);
      return row ? mapInboxRow(row) : null;
    },

    async createUserInbox(input) {
      const [row] = await db
        .insert(userInboxes)
        .values({
          userId: input.userId,
          address: input.address.trim().toLowerCase(),
          customName: input.customName,
          expiresAt: input.expiresAt,
        })
        .returning();
      if (!row) {
        throw new Error('Failed to create user inbox');
      }
      return mapInboxRow(row);
    },

    async deleteUserInbox(userId, inboxId) {
      const [row] = await db
        .delete(userInboxes)
        .where(and(eq(userInboxes.id, inboxId), eq(userInboxes.userId, userId)))
        .returning();
      return row ? mapInboxRow(row) : null;
    },

    async storeAccountMessage(input) {
      await db.insert(accountMessages).values({
        id: input.message.id,
        inboxId: input.inboxId,
        body: input.message,
        attachments: input.attachments,
        expiresAt: input.expiresAt,
      });
    },

    async listAccountMessages(inboxId) {
      const now = new Date();
      const rows = await db
        .select({ body: accountMessages.body })
        .from(accountMessages)
        .where(and(eq(accountMessages.inboxId, inboxId), gt(accountMessages.expiresAt, now)))
        .orderBy(desc(accountMessages.receivedAt));
      return rows.map((r) => r.body as StoredMessage);
    },

    async getAccountMessage(inboxId, msgId) {
      const now = new Date();
      const [row] = await db
        .select({ body: accountMessages.body })
        .from(accountMessages)
        .where(
          and(
            eq(accountMessages.inboxId, inboxId),
            eq(accountMessages.id, msgId),
            gt(accountMessages.expiresAt, now),
          ),
        )
        .limit(1);
      return row ? (row.body as StoredMessage) : null;
    },

    async purgeExpired(now = new Date()) {
      const deletedMessages = await db
        .delete(accountMessages)
        .where(lt(accountMessages.expiresAt, now))
        .returning({ id: accountMessages.id });
      const deletedInboxes = await db
        .delete(userInboxes)
        .where(lt(userInboxes.expiresAt, now))
        .returning({ id: userInboxes.id });
      return {
        deletedInboxes: deletedInboxes.length,
        deletedMessages: deletedMessages.length,
      };
    },
  };
}
