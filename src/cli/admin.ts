import { hashPassword, validatePasswordStrength } from '../auth/password.js';
import { loadEnv } from '../config/env.js';
import { createDbAdminPanelStore } from '../storage/adminPanelStore.js';
import { createDbConnection } from '../storage/db.js';

async function main(): Promise<void> {
  const [, , command, arg1, arg2] = process.argv;
  const config = loadEnv();

  if (!config.databaseUrl) {
    console.error('DATABASE_URL is required to run the admin break-glass CLI');
    process.exit(1);
  }

  const dbConn = createDbConnection(config.databaseUrl);
  const store = createDbAdminPanelStore(dbConn.db);

  try {
    if (command === 'create-owner') {
      if (!arg1 || !arg2) {
        console.error('Usage: npm run admin:cli -- create-owner <email> <password>');
        process.exit(1);
      }
      const pwCheck = validatePasswordStrength(arg2);
      if (!pwCheck.valid) {
        console.error(`Weak password: ${pwCheck.reason}`);
        process.exit(1);
      }
      const existing = await store.findAdminByEmail(arg1);
      if (existing) {
        console.error(`Admin account already exists for ${arg1}`);
        process.exit(1);
      }
      const created = await store.createAdminUser({
        email: arg1,
        passwordHash: await hashPassword(arg2),
        role: 'owner',
      });
      console.log(`Created owner admin account: ${created.email} (id: ${created.id})`);
      console.log('2FA enrollment will be required on first login.');
      return;
    }

    if (command === 'reset-2fa') {
      if (!arg1) {
        console.error('Usage: npm run admin:cli -- reset-2fa <email>');
        process.exit(1);
      }
      const admin = await store.findAdminByEmail(arg1);
      if (!admin) {
        console.error(`No admin user found for ${arg1}`);
        process.exit(1);
      }
      await store.resetAdminTotp(admin.id);
      console.log(`Reset 2FA for admin ${admin.email}. They must re-enroll TOTP on next login.`);
      return;
    }

    console.error('Unknown command. Available commands: create-owner, reset-2fa');
    process.exit(1);
  } finally {
    await dbConn.close();
  }
}

void main();
