const CUSTOM_NAME_REGEX = /^[a-z0-9](?:[a-z0-9.-]{1,28})[a-z0-9]$/;

export interface CustomNameValidationResult {
  readonly valid: boolean;
  readonly normalized: string;
  readonly reason?: string;
}

/**
 * Custom inbox local-part rules (Spec Section 4):
 * - 3 to 30 characters
 * - lowercase letters, digits, dots, hyphens
 * - no leading or trailing punctuation, no consecutive dots
 */
export function validateCustomName(rawName: string): CustomNameValidationResult {
  const normalized = rawName.trim().toLowerCase();

  if (normalized.length < 3 || normalized.length > 30) {
    return {
      valid: false,
      normalized,
      reason: 'Custom name must be between 3 and 30 characters',
    };
  }

  if (normalized.includes('..') || !CUSTOM_NAME_REGEX.test(normalized)) {
    return {
      valid: false,
      normalized,
      reason:
        'Custom name may contain only lowercase letters, digits, dots, and hyphens, with no leading/trailing punctuation or consecutive dots',
    };
  }

  return { valid: true, normalized };
}
