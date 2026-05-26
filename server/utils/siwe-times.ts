// Clock skew + page-open-to-sign delay tolerance. The GET handler issues
// timestamps at "now", but the user signs some time later — by the time we
// verify, message.expirationTime may exceed (verifyNow + maxSeconds) by a
// few seconds in either direction.
const CLOCK_SKEW_GRACE_MS = 60_000

export interface SiweTimePolicy {
  /** Max seconds from verification time. 0 disables the policy. */
  expirationTime: number
  notBefore: number
}

export interface SiweTimestamps {
  expirationTime?: string
  notBefore?: string
}

type Field = 'expirationTime' | 'notBefore'
type FailReason = 'missing' | 'exceeds_max' | 'invalid_format'

/**
 * Validate that a signed SIWE message satisfies the operator's policy:
 * when a window is configured, the field must be present, parse to a real
 * timestamp, and not be set further in the future than (now + window +
 * grace). The library's verify() already handles the "in the past" side for
 * expirationTime and "in the future" side for notBefore — this enforces
 * the upper bound on top.
 *
 * @returns Error descriptor, or null if valid.
 */
export function validateSiweTimestamps(
  message: SiweTimestamps,
  policy: SiweTimePolicy,
  now: number = Date.now(),
): { field: Field; reason: FailReason } | null {
  for (const field of ['expirationTime', 'notBefore'] as const) {
    const maxSeconds = policy[field]
    if (!Number.isFinite(maxSeconds) || maxSeconds <= 0) continue

    const value = message[field]
    if (!value) return { field, reason: 'missing' }

    // Date.parse returns NaN for unparseable input. NaN > max is false, so
    // without an explicit check a malformed timestamp would silently pass.
    const parsed = Date.parse(value)
    if (!Number.isFinite(parsed)) return { field, reason: 'invalid_format' }

    const max = now + maxSeconds * 1000 + CLOCK_SKEW_GRACE_MS
    if (parsed > max) return { field, reason: 'exceeds_max' }
  }
  return null
}

const FIELD_LABEL: Record<Field, string> = {
  expirationTime: 'Expiration Time',
  notBefore: 'Not Before',
}

export function siweTimestampErrorMessage(
  err: NonNullable<ReturnType<typeof validateSiweTimestamps>>,
): string {
  const label = FIELD_LABEL[err.field]
  switch (err.reason) {
    case 'missing':
      return `SIWE message must include ${label}`
    case 'invalid_format':
      return `SIWE ${label} is not a valid timestamp`
    case 'exceeds_max':
      return `SIWE ${label} exceeds configured maximum`
  }
}
