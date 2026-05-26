import { describe, it, expect } from 'vitest'
import {
  validateSiweTimestamps,
  siweTimestampErrorMessage,
} from '../server/utils/siwe-times'

const NOW = Date.parse('2026-01-01T00:00:00Z')
const iso = (offsetMs: number) => new Date(NOW + offsetMs).toISOString()

describe('validateSiweTimestamps', () => {
  it('passes when no policy is configured', () => {
    expect(
      validateSiweTimestamps({}, { expirationTime: 0, notBefore: 0 }, NOW),
    ).toBeNull()
  })

  it('rejects missing expirationTime when configured', () => {
    const err = validateSiweTimestamps(
      {},
      { expirationTime: 600, notBefore: 0 },
      NOW,
    )
    expect(err).toEqual({ field: 'expirationTime', reason: 'missing' })
    expect(siweTimestampErrorMessage(err!)).toBe(
      'SIWE message must include Expiration Time',
    )
  })

  it('rejects expirationTime past the configured maximum', () => {
    const err = validateSiweTimestamps(
      { expirationTime: iso(2 * 3600 * 1000) },
      { expirationTime: 600, notBefore: 0 },
      NOW,
    )
    expect(err).toEqual({ field: 'expirationTime', reason: 'exceeds_max' })
    expect(siweTimestampErrorMessage(err!)).toBe(
      'SIWE Expiration Time exceeds configured maximum',
    )
  })

  it('accepts expirationTime within the configured maximum', () => {
    expect(
      validateSiweTimestamps(
        { expirationTime: iso(600 * 1000) },
        { expirationTime: 600, notBefore: 0 },
        NOW,
      ),
    ).toBeNull()
  })

  it('accepts expirationTime up to grace window past maximum', () => {
    // 600s + 30s — inside the 60s grace
    expect(
      validateSiweTimestamps(
        { expirationTime: iso(630 * 1000) },
        { expirationTime: 600, notBefore: 0 },
        NOW,
      ),
    ).toBeNull()
  })

  it('rejects expirationTime past grace window', () => {
    // 600s + 120s — outside the 60s grace
    const err = validateSiweTimestamps(
      { expirationTime: iso(720 * 1000) },
      { expirationTime: 600, notBefore: 0 },
      NOW,
    )
    expect(err?.reason).toBe('exceeds_max')
  })

  it('rejects missing notBefore when configured', () => {
    const err = validateSiweTimestamps(
      { expirationTime: iso(600 * 1000) },
      { expirationTime: 600, notBefore: 300 },
      NOW,
    )
    expect(err).toEqual({ field: 'notBefore', reason: 'missing' })
    expect(siweTimestampErrorMessage(err!)).toBe(
      'SIWE message must include Not Before',
    )
  })

  it('rejects notBefore past the configured maximum', () => {
    const err = validateSiweTimestamps(
      {
        expirationTime: iso(600 * 1000),
        notBefore: iso(2 * 3600 * 1000),
      },
      { expirationTime: 600, notBefore: 300 },
      NOW,
    )
    expect(err).toEqual({ field: 'notBefore', reason: 'exceeds_max' })
  })

  it('skips fields whose policy is 0', () => {
    // notBefore present in message but policy is 0 — should ignore it
    expect(
      validateSiweTimestamps(
        { expirationTime: iso(600 * 1000), notBefore: iso(10 * 3600 * 1000) },
        { expirationTime: 600, notBefore: 0 },
        NOW,
      ),
    ).toBeNull()
  })

  it('reports expirationTime failure before notBefore', () => {
    const err = validateSiweTimestamps(
      {},
      { expirationTime: 600, notBefore: 300 },
      NOW,
    )
    expect(err?.field).toBe('expirationTime')
  })

  it('rejects malformed expirationTime (defense vs NaN-passes-bound)', () => {
    const err = validateSiweTimestamps(
      { expirationTime: 'not-a-date' },
      { expirationTime: 600, notBefore: 0 },
      NOW,
    )
    expect(err).toEqual({ field: 'expirationTime', reason: 'invalid_format' })
    expect(siweTimestampErrorMessage(err!)).toBe(
      'SIWE Expiration Time is not a valid timestamp',
    )
  })

  it('treats NaN policy as disabled (defensive against env misconfig)', () => {
    expect(
      validateSiweTimestamps(
        {},
        { expirationTime: NaN as unknown as number, notBefore: 0 },
        NOW,
      ),
    ).toBeNull()
  })

  it('accepts notBefore = now (the typical client-emitted value)', () => {
    expect(
      validateSiweTimestamps(
        {
          expirationTime: iso(600 * 1000),
          notBefore: iso(0),
        },
        { expirationTime: 600, notBefore: 300 },
        NOW,
      ),
    ).toBeNull()
  })
})
