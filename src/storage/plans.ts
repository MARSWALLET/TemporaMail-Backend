import { z } from 'zod';

export type PlanId = 'anonymous' | 'free' | 'premium';

export const planLimitsSchema = z.object({
  maxInboxLifetimeMinutes: z.number().int().min(1),
  maxActiveAddresses: z.number().int().min(1),
  maxReservedCustomNames: z.number().int().min(0),
  maxApiKeys: z.number().int().min(0),
  apiRequestsPerDay: z.number().int().min(0),
  maxAttachmentBytes: z.number().int().min(0),
  privateDomain: z.boolean(),
});

export type PlanLimits = z.infer<typeof planLimitsSchema>;

export interface PlanEntitlements extends PlanLimits {
  readonly planId: string;
}

export const DEFAULT_PLAN_LIMITS: Readonly<Record<PlanId, PlanLimits>> = {
  anonymous: {
    maxInboxLifetimeMinutes: 60,
    maxActiveAddresses: 1,
    maxReservedCustomNames: 0,
    maxApiKeys: 0,
    apiRequestsPerDay: 0,
    maxAttachmentBytes: 2 * 1024 * 1024, // 2 MB
    privateDomain: false,
  },
  free: {
    maxInboxLifetimeMinutes: 24 * 60, // 24 hours
    maxActiveAddresses: 3,
    maxReservedCustomNames: 1,
    maxApiKeys: 2,
    apiRequestsPerDay: 500,
    maxAttachmentBytes: 5 * 1024 * 1024, // 5 MB
    privateDomain: false,
  },
  premium: {
    maxInboxLifetimeMinutes: 30 * 24 * 60, // 30 days
    maxActiveAddresses: 20,
    maxReservedCustomNames: 10,
    maxApiKeys: 10,
    apiRequestsPerDay: 50_000,
    maxAttachmentBytes: 10 * 1024 * 1024, // 10 MB
    privateDomain: true,
  },
};

export interface EntitlementUserLike {
  readonly planId?: string | null;
  readonly status?: string;
}

/**
 * Single centralized entitlements resolver backed by the `plans` table (with typed defaults).
 */
export function getEntitlements(
  user: EntitlementUserLike | null | undefined,
  plansById?: ReadonlyMap<string, PlanLimits>,
): PlanEntitlements {
  const planId = !user || user.status === 'banned' ? 'anonymous' : user.planId || 'free';

  const fromDb = plansById?.get(planId);
  if (fromDb) {
    return { planId, ...fromDb };
  }

  if (planId === 'free' || planId === 'premium' || planId === 'anonymous') {
    return { planId, ...DEFAULT_PLAN_LIMITS[planId] };
  }

  return { planId: 'free', ...DEFAULT_PLAN_LIMITS.free };
}
