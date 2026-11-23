export type AdminRole = 'owner' | 'admin' | 'moderator' | 'viewer';

export type AdminPermission =
  | 'dashboard:read'
  | 'domains:read'
  | 'domains:write'
  | 'blocklist:read'
  | 'blocklist:write'
  | 'settings:read'
  | 'settings:write'
  | 'abuse:read'
  | 'abuse:write'
  | 'logs:read'
  | 'inboxes:lookup'
  | 'inboxes:delete'
  | 'users:read'
  | 'users:write'
  | 'apikeys:read'
  | 'apikeys:write'
  | 'reserved_names:read'
  | 'reserved_names:write'
  | 'announcements:read'
  | 'announcements:write'
  | 'admins:manage'
  | 'audit:read';

const VIEWER_PERMISSIONS: readonly AdminPermission[] = [
  'dashboard:read',
  'domains:read',
  'blocklist:read',
  'settings:read',
  'abuse:read',
  'logs:read',
  'users:read',
  'apikeys:read',
  'reserved_names:read',
  'announcements:read',
  'audit:read',
];

const MODERATOR_PERMISSIONS: readonly AdminPermission[] = [
  ...VIEWER_PERMISSIONS,
  'abuse:write',
  'inboxes:lookup',
  'inboxes:delete',
  'blocklist:write',
];

const ADMIN_PERMISSIONS: readonly AdminPermission[] = [
  ...MODERATOR_PERMISSIONS,
  'domains:write',
  'settings:write',
  'users:write',
  'apikeys:write',
  'reserved_names:write',
  'announcements:write',
];

const OWNER_PERMISSIONS: readonly AdminPermission[] = [
  ...ADMIN_PERMISSIONS,
  'admins:manage',
];

const ROLE_PERMISSION_MAP: Readonly<Record<AdminRole, ReadonlySet<AdminPermission>>> = {
  viewer: new Set(VIEWER_PERMISSIONS),
  moderator: new Set(MODERATOR_PERMISSIONS),
  admin: new Set(ADMIN_PERMISSIONS),
  owner: new Set(OWNER_PERMISSIONS),
};

export function hasAdminPermission(role: AdminRole, permission: AdminPermission): boolean {
  return ROLE_PERMISSION_MAP[role]?.has(permission) ?? false;
}
