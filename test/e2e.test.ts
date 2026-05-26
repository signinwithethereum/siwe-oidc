import { describe, it, expect } from 'vitest'
import { randomBytes, createHash } from 'node:crypto'
import { privateKeyToAccount } from 'viem/accounts'
import { importJWK, jwtVerify } from 'jose'

// Test wallet — Hardhat/Anvil account #0
const TEST_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const account = privateKeyToAccount(TEST_PRIVATE_KEY)

// Expects a running server + Redis: `npm run dev`
const BASE = process.env.TEST_BASE_URL || 'http://localhost:3000'

const serverAvailable = await fetch(BASE, {
  signal: AbortSignal.timeout(2000),
})
  .then(() => true)
  .catch(() => false)

if (!serverAvailable) {
  console.warn(
    '\n⚠  Skipping e2e tests — local server is not running.\n' +
      '   Start it with: pnpm dev\n',
  )
}

function apiUrl(path: string): string {
  return path.startsWith('http') ? path : `${BASE}${path}`
}

function createSiweMessage(params: {
  domain: string
  address: string
  uri: string
  chainId: number
  nonce: string
  statement?: string
  expirationTime?: string
  notBefore?: string
  resources?: string[]
}): string {
  const lines = [
    `${params.domain} wants you to sign in with your Ethereum account:`,
    params.address,
    '',
  ]
  if (params.statement) lines.push(params.statement)
  lines.push(
    '',
    `URI: ${params.uri}`,
    `Version: 1`,
    `Chain ID: ${params.chainId}`,
    `Nonce: ${params.nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  )
  if (params.expirationTime)
    lines.push(`Expiration Time: ${params.expirationTime}`)
  if (params.notBefore) lines.push(`Not Before: ${params.notBefore}`)
  if (params.resources?.length) {
    lines.push('Resources:')
    for (const r of params.resources) lines.push(`- ${r}`)
  }
  return lines.join('\n')
}

/** Default expirationTime far enough out to satisfy any sane policy. */
function defaultExpirationTime(): string {
  return new Date(Date.now() + 60 * 1000).toISOString()
}

/** Hex-encode a UID for use as an EIP-4361 compliant nonce. */
function hexNonce(uid: string): string {
  return Buffer.from(uid).toString('hex')
}

/** Generate a PKCE code_verifier and S256 code_challenge. */
function generatePkce() {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  return { verifier, challenge }
}

/** Collect Set-Cookie headers as a semicolon-joined string. */
function extractCookies(res: Response): string {
  return res.headers
    .getSetCookie()
    .map((c) => c.split(';')[0])
    .join('; ')
}

/** Merge multiple cookie strings, deduplicating by name (last wins). */
function mergeCookies(...parts: string[]): string {
  const map = new Map<string, string>()
  for (const part of parts) {
    for (const kv of part.split('; ').filter(Boolean)) {
      const name = kv.split('=')[0]!
      map.set(name, kv)
    }
  }
  return [...map.values()].join('; ')
}

describe.skipIf(!serverAvailable)('siwe-oidc', () => {
  /** Register a client, start an auth flow, and return the uid + cookies + clientId + PKCE verifier. */
  async function startInteraction(scope = 'openid profile') {
    const client = await fetch(apiUrl('/reg'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://example.com/callback'],
        token_endpoint_auth_method: 'none',
      }),
    }).then((r) => r.json())

    const pkce = generatePkce()
    const authUrl = new URL('/auth', BASE)
    authUrl.searchParams.set('client_id', client.client_id)
    authUrl.searchParams.set('redirect_uri', 'https://example.com/callback')
    authUrl.searchParams.set('response_type', 'code')
    authUrl.searchParams.set('scope', scope)
    authUrl.searchParams.set('code_challenge', pkce.challenge)
    authUrl.searchParams.set('code_challenge_method', 'S256')

    const authRes = await fetch(authUrl, { redirect: 'manual' })
    const interactionUrl = authRes.headers.get('location')!
    let cookies = extractCookies(authRes)
    const uid = interactionUrl.split('/interaction/')[1]!.split('?')[0]!

    const detailsRes = await fetch(apiUrl(`/api/interaction/${uid}`), {
      headers: { cookie: cookies },
    })
    cookies = mergeCookies(cookies, extractCookies(detailsRes))
    return { uid, cookies, clientId: client.client_id as string, codeVerifier: pkce.verifier }
  }

  /** Run the full SIWE auth flow and return tokens + the authorization code. */
  async function completeAuthFlow(scope = 'openid profile') {
    const { uid, cookies, clientId, codeVerifier } = await startInteraction(scope)

    const message = createSiweMessage({
      domain: new URL(BASE).host,
      address: account.address,
      uri: BASE,
      chainId: 1,
      nonce: hexNonce(uid),
      statement: 'Sign-In with Ethereum',
      expirationTime: defaultExpirationTime(),
      resources: ['https://example.com/callback'],
    })
    const signature = await account.signMessage({ message })

    const verifyRes = await fetch(apiUrl(`/api/interaction/${uid}`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', cookie: cookies },
      body: JSON.stringify({ message, signature }),
      redirect: 'manual',
    })

    let updatedCookies = mergeCookies(cookies, extractCookies(verifyRes))
    const verifyBody = (await verifyRes.json()) as { redirectTo: string }
    let location = verifyBody.redirectTo

    for (let i = 0; i < 5; i++) {
      if (location.startsWith('https://example.com')) break
      const res = await fetch(apiUrl(location), {
        headers: { cookie: updatedCookies },
        redirect: 'manual',
      })
      updatedCookies = mergeCookies(updatedCookies, extractCookies(res))
      location = res.headers.get('location')!
    }

    const code = new URL(location).searchParams.get('code')!

    const tokenRes = await fetch(apiUrl('/token'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://example.com/callback',
        client_id: clientId,
        code_verifier: codeVerifier,
      }),
    })
    const tokens = await tokenRes.json()

    return {
      accessToken: tokens.access_token as string,
      idToken: tokens.id_token as string,
      clientId,
      code,
      codeVerifier,
    }
  }

  describe('discovery', () => {
    it('serves OpenID configuration', async () => {
      const res = await fetch(apiUrl('/.well-known/openid-configuration'))
      expect(res.status).toBe(200)
      const config = await res.json()
      expect(config).toHaveProperty('issuer')
      expect(config).toHaveProperty('authorization_endpoint')
      expect(config).toHaveProperty('token_endpoint')
      expect(config).toHaveProperty('jwks_uri')
      expect(config).toHaveProperty('registration_endpoint')
      expect(config).toHaveProperty('userinfo_endpoint')
      expect(config.scopes_supported).toContain('openid')
      expect(config.scopes_supported).toContain('siwe')
      expect(config.claims_supported).toContain('siwe_message')
      expect(config.claims_supported).toContain('siwe_signature')
      expect(config.response_types_supported).toContain('code')
    })

    it('serves JWKS', async () => {
      const res = await fetch(apiUrl('/jwks'))
      expect(res.status).toBe(200)
      const jwks = await res.json()
      expect(jwks).toHaveProperty('keys')
      expect(jwks.keys.length).toBeGreaterThan(0)
      expect(jwks.keys[0]).toHaveProperty('kty', 'RSA')
      expect(jwks.keys[0]).toHaveProperty('kid', 'key1')
    })
  })

  describe('client registration', () => {
    it('registers a new client', async () => {
      const res = await fetch(apiUrl('/reg'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['https://example.com/callback'],
          application_type: 'web',
        }),
      })
      expect(res.status).toBe(201)
      const client = await res.json()
      expect(client).toHaveProperty('client_id')
      expect(client).toHaveProperty('client_secret')
      expect(client.redirect_uris).toContain('https://example.com/callback')
    })
  })

  describe('full auth flow', () => {
    it('completes SIWE login and issues tokens', async () => {
      // 1. Register client
      const client = await fetch(apiUrl('/reg'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['https://example.com/callback'],
          token_endpoint_auth_method: 'none',
        }),
      }).then((r) => r.json())

      // 2. Start auth flow — provider 303s to /interaction/{uid}
      const pkce = generatePkce()
      const authUrl = new URL('/auth', BASE)
      authUrl.searchParams.set('client_id', client.client_id)
      authUrl.searchParams.set('redirect_uri', 'https://example.com/callback')
      authUrl.searchParams.set('response_type', 'code')
      authUrl.searchParams.set('scope', 'openid profile')
      authUrl.searchParams.set('state', 'teststate')
      authUrl.searchParams.set('code_challenge', pkce.challenge)
      authUrl.searchParams.set('code_challenge_method', 'S256')

      const authRes = await fetch(authUrl, { redirect: 'manual' })
      expect(authRes.status).toBe(303)
      const interactionUrl = authRes.headers.get('location')!
      expect(interactionUrl).toMatch(/\/interaction\//)

      let cookies = extractCookies(authRes)
      const uid = interactionUrl.split('/interaction/')[1]!.split('?')[0]!

      // 3. Fetch interaction details (also updates cookies)
      const detailsRes = await fetch(apiUrl(`/api/interaction/${uid}`), {
        headers: { cookie: cookies },
      })
      expect(detailsRes.status).toBe(200)
      cookies = mergeCookies(cookies, extractCookies(detailsRes))
      const details = await detailsRes.json()
      expect(details.uid).toBe(uid)
      expect(details.params.client_id).toBe(client.client_id)
      expect(details.params.scope).toBe('openid profile')

      // 4. Create and sign SIWE message
      const message = createSiweMessage({
        domain: new URL(BASE).host,
        address: account.address,
        uri: BASE,
        chainId: 1,
        nonce: hexNonce(uid),
        statement: 'Sign-In with Ethereum',
        expirationTime: defaultExpirationTime(),
        resources: ['https://example.com/callback'],
      })
      const signature = await account.signMessage({ message })

      // 5. POST verification — provider writes 303 directly
      const verifyRes = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          cookie: cookies,
        },
        body: JSON.stringify({ message, signature }),
        redirect: 'manual',
      })

      expect(
        verifyRes.status,
        `verify failed: ${await verifyRes.clone().text()}`,
      ).toBe(200)

      // 6. Follow redirect chain until we reach the client callback
      cookies = mergeCookies(cookies, extractCookies(verifyRes))
      const verifyBody = (await verifyRes.json()) as { redirectTo: string }
      let location = verifyBody.redirectTo

      for (let i = 0; i < 5; i++) {
        if (location.startsWith('https://example.com')) break
        const res = await fetch(apiUrl(location), {
          headers: { cookie: cookies },
          redirect: 'manual',
        })
        cookies = mergeCookies(cookies, extractCookies(res))
        const next = res.headers.get('location')
        if (!next)
          throw new Error(
            `Redirect chain broke at hop ${i}: status=${res.status}`,
          )
        location = next
      }

      const callbackUrl = new URL(location)
      const code = callbackUrl.searchParams.get('code')
      expect(code).toBeTruthy()
      expect(callbackUrl.searchParams.get('state')).toBe('teststate')

      // 7. Exchange code for tokens
      const tokenRes = await fetch(apiUrl('/token'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code!,
          redirect_uri: 'https://example.com/callback',
          client_id: client.client_id,
          code_verifier: pkce.verifier,
        }),
      })
      expect(tokenRes.status).toBe(200)
      const tokens = await tokenRes.json()
      expect(tokens).toHaveProperty('access_token')
      expect(tokens).toHaveProperty('id_token')
      expect(tokens.token_type).toBe('Bearer')

      // 8. Verify id_token signature against the JWKS and check claims
      const jwksData = await fetch(apiUrl('/jwks')).then((r) => r.json())
      const pubKey = await importJWK(jwksData.keys[0], 'RS256')
      const { payload: claims } = await jwtVerify(tokens.id_token, pubKey, {
        issuer: BASE,
        audience: client.client_id,
      })
      expect(claims.sub).toMatch(/^eip155:1:0x/)
      expect(claims.sub).toContain(account.address)
      expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000))
      expect(claims.iat).toBeLessThanOrEqual(Math.floor(Date.now() / 1000))

      // 9. Verify userinfo endpoint
      const userinfoRes = await fetch(apiUrl('/me'), {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      })
      expect(userinfoRes.status).toBe(200)
      const userinfo = await userinfoRes.json()
      expect(userinfo.sub).toBe(claims.sub)
      expect(userinfo.preferred_username).toBe(account.address)
    })
  })

  describe('rejection cases', () => {
    it('rejects missing message or signature', async () => {
      const { uid, cookies } = await startInteraction()

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie: cookies },
        body: JSON.stringify({}),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/Missing message or signature/)
    })

    it('rejects wrong nonce', async () => {
      const { uid, cookies } = await startInteraction()

      const message = createSiweMessage({
        domain: new URL(BASE).host,
        address: account.address,
        uri: BASE,
        chainId: 1,
        nonce: 'deadbeefdeadbeef',
      })
      const signature = await account.signMessage({ message })

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie: cookies },
        body: JSON.stringify({ message, signature }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/Nonce mismatch/)
    })

    it('rejects invalid signature', async () => {
      const { uid, cookies } = await startInteraction()

      const message = createSiweMessage({
        domain: new URL(BASE).host,
        address: account.address,
        uri: BASE,
        chainId: 1,
        nonce: hexNonce(uid),
        expirationTime: defaultExpirationTime(),
        resources: ['https://example.com/callback'],
      })
      const badSig = '0x' + 'ab'.repeat(65) // garbage 65-byte signature

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie: cookies },
        body: JSON.stringify({ message, signature: badSig }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/signature/i)
    })

    it('rejects interaction without cookies', async () => {
      const { uid } = await startInteraction()

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'x', signature: '0x' }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/Invalid interaction session/)
    })
  })

  describe('OIDC endpoint availability', () => {
    it('advertises introspection, revocation, and end_session endpoints', async () => {
      const res = await fetch(apiUrl('/.well-known/openid-configuration'))
      const config = await res.json()
      expect(config).toHaveProperty('introspection_endpoint')
      expect(config).toHaveProperty('revocation_endpoint')
      expect(config).toHaveProperty('end_session_endpoint')
    })

    it('/introspection requires client identification', async () => {
      const res = await fetch(apiUrl('/token/introspection'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: 'fake-token' }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.error).toBe('invalid_request')
    })

    it('/revocation requires client identification', async () => {
      const res = await fetch(apiUrl('/token/revocation'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: 'fake-token' }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.error).toBe('invalid_request')
    })

    it('/end_session is routed to the provider', async () => {
      const res = await fetch(apiUrl('/session/end'))
      // Without a valid session the provider still handles the request (not a 404)
      expect(res.status).toBeLessThan(500)
    })
  })

  describe('client registration validation', () => {
    it('rejects http redirect_uri', async () => {
      const res = await fetch(apiUrl('/reg'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['http://example.com/callback'],
          application_type: 'web',
        }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.error).toBe('invalid_redirect_uri')
    })

    it('rejects registration with no redirect_uris', async () => {
      const res = await fetch(apiUrl('/reg'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ application_type: 'web' }),
      })
      expect(res.status).toBe(400)
    })

    it('rejects redirect_uri with fragment', async () => {
      const res = await fetch(apiUrl('/reg'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['https://example.com/callback#fragment'],
        }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.error).toBe('invalid_redirect_uri')
    })
  })

  describe('token exchange edge cases', () => {
    it('rejects a replayed authorization code', async () => {
      const { code, clientId, codeVerifier } = await completeAuthFlow()

      // Code was already exchanged — reuse with correct verifier should fail
      const tokenRes = await fetch(apiUrl('/token'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'https://example.com/callback',
          client_id: clientId,
          code_verifier: codeVerifier,
        }),
      })
      expect(tokenRes.status).toBe(400)
      const body = await tokenRes.json()
      expect(body.error).toBe('invalid_grant')
    })

    it('rejects a fabricated authorization code', async () => {
      const client = await fetch(apiUrl('/reg'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['https://example.com/callback'],
          token_endpoint_auth_method: 'none',
        }),
      }).then((r) => r.json())

      const tokenRes = await fetch(apiUrl('/token'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'totally-fabricated-code',
          redirect_uri: 'https://example.com/callback',
          client_id: client.client_id,
        }),
      })
      expect(tokenRes.status).toBe(400)
      const body = await tokenRes.json()
      expect(body.error).toBe('invalid_grant')
    })
  })

  describe('userinfo edge cases', () => {
    it('rejects request with no authorization header', async () => {
      const res = await fetch(apiUrl('/me'))
      expect(res.status).toBeGreaterThanOrEqual(400)
    })

    it('rejects request with invalid access token', async () => {
      const res = await fetch(apiUrl('/me'), {
        headers: { Authorization: 'Bearer totally-invalid-token' },
      })
      expect(res.status).toBe(401)
    })

    it('rejects request with wrong Bearer scheme', async () => {
      const res = await fetch(apiUrl('/me'), {
        headers: { Authorization: 'Basic dXNlcjpwYXNz' },
      })
      expect(res.status).toBeGreaterThanOrEqual(400)
    })
  })

  describe('SIWE message validation', () => {
    it('rejects SIWE message with empty address line', async () => {
      const { uid, cookies } = await startInteraction()

      const malformedMessage = [
        `${new URL(BASE).host} wants you to sign in with your Ethereum account:`,
        '', // empty address line
        '',
        `URI: ${BASE}`,
        `Version: 1`,
        `Chain ID: 1`,
        `Nonce: ${hexNonce(uid)}`,
        `Issued At: ${new Date().toISOString()}`,
      ].join('\n')
      const signature = await account.signMessage({ message: malformedMessage })

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie: cookies },
        body: JSON.stringify({ message: malformedMessage, signature }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/Invalid SIWE message/)
    })

    it('rejects SIWE message with malformed address', async () => {
      const { uid, cookies } = await startInteraction()

      const malformedMessage = [
        `${new URL(BASE).host} wants you to sign in with your Ethereum account:`,
        'not-a-valid-address',
        '',
        `URI: ${BASE}`,
        `Version: 1`,
        `Chain ID: 1`,
        `Nonce: ${hexNonce(uid)}`,
        `Issued At: ${new Date().toISOString()}`,
      ].join('\n')
      const signature = await account.signMessage({ message: malformedMessage })

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie: cookies },
        body: JSON.stringify({ message: malformedMessage, signature }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/Invalid SIWE message/)
    })

    it('rejects SIWE message with mismatched domain', async () => {
      const { uid, cookies } = await startInteraction()

      const message = createSiweMessage({
        domain: 'evil.com',
        address: account.address,
        uri: 'https://evil.com',
        chainId: 1,
        nonce: hexNonce(uid),
        statement: 'Sign-In with Ethereum',
        expirationTime: defaultExpirationTime(),
        resources: ['https://example.com/callback'],
      })
      const signature = await account.signMessage({ message })

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie: cookies },
        body: JSON.stringify({ message, signature }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/domain/i)
    })

    it('rejects SIWE message with missing resources', async () => {
      const { uid, cookies } = await startInteraction()

      const message = createSiweMessage({
        domain: new URL(BASE).host,
        address: account.address,
        uri: BASE,
        chainId: 1,
        nonce: hexNonce(uid),
        statement: 'Sign-In with Ethereum',
      })
      const signature = await account.signMessage({ message })

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie: cookies },
        body: JSON.stringify({ message, signature }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/Missing resource/)
    })

    it('rejects SIWE message with wrong redirect_uri in resources', async () => {
      const { uid, cookies } = await startInteraction()

      const message = createSiweMessage({
        domain: new URL(BASE).host,
        address: account.address,
        uri: BASE,
        chainId: 1,
        nonce: hexNonce(uid),
        statement: 'Sign-In with Ethereum',
        resources: ['https://evil.com/steal'],
      })
      const signature = await account.signMessage({ message })

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie: cookies },
        body: JSON.stringify({ message, signature }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/resource does not match redirect_uri/)
    })

    it('rejects SIWE message missing Expiration Time when policy is set', async () => {
      const { uid, cookies } = await startInteraction()

      const message = createSiweMessage({
        domain: new URL(BASE).host,
        address: account.address,
        uri: BASE,
        chainId: 1,
        nonce: hexNonce(uid),
        statement: 'Sign-In with Ethereum',
        resources: ['https://example.com/callback'],
        // expirationTime intentionally omitted
      })
      const signature = await account.signMessage({ message })

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie: cookies },
        body: JSON.stringify({ message, signature }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/Expiration Time/)
    })

    it('rejects SIWE message with Expiration Time past the configured maximum', async () => {
      const { uid, cookies } = await startInteraction()

      // Default policy is 600s + 60s grace; 7 days is well past.
      const farFuture = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString()
      const message = createSiweMessage({
        domain: new URL(BASE).host,
        address: account.address,
        uri: BASE,
        chainId: 1,
        nonce: hexNonce(uid),
        statement: 'Sign-In with Ethereum',
        expirationTime: farFuture,
        resources: ['https://example.com/callback'],
      })
      const signature = await account.signMessage({ message })

      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', cookie: cookies },
        body: JSON.stringify({ message, signature }),
      })
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.statusMessage).toMatch(/exceeds configured maximum/)
    })
  })

  describe('interaction details', () => {
    it('exposes SIWE policy durations the client materialises at sign time', async () => {
      const { uid, cookies } = await startInteraction()
      const res = await fetch(apiUrl(`/api/interaction/${uid}`), {
        headers: { cookie: cookies },
      })
      const details = await res.json()
      expect(details.siwe).toBeDefined()
      // Default policy: expirationTime=600 (seconds), notBefore disabled (null).
      // Durations not ISO strings — see [uid].get.ts. The client computes
      // fresh ISO timestamps at sign time so retries get a fresh window.
      expect(details.siwe.expirationTimeSeconds).toBe(600)
      expect(details.siwe.notBeforeToleranceSeconds).toBeNull()
    })
  })

  describe('siwe proof claims', () => {
    it('includes siwe_message and siwe_signature when siwe scope is requested', async () => {
      const { idToken, clientId } = await completeAuthFlow('openid profile siwe')

      const jwksData = await fetch(apiUrl('/jwks')).then((r) => r.json())
      const pubKey = await importJWK(jwksData.keys[0], 'RS256')
      const { payload: claims } = await jwtVerify(idToken, pubKey, {
        issuer: BASE,
        audience: clientId,
      })

      expect(claims).toHaveProperty('siwe_message')
      expect(claims).toHaveProperty('siwe_signature')
      expect(claims.siwe_message).toContain('wants you to sign in with your Ethereum account')
      expect(typeof claims.siwe_signature).toBe('string')
      expect((claims.siwe_signature as string).startsWith('0x')).toBe(true)
    })

    it('excludes siwe claims when siwe scope is not requested', async () => {
      const { idToken, clientId } = await completeAuthFlow('openid profile')

      const jwksData = await fetch(apiUrl('/jwks')).then((r) => r.json())
      const pubKey = await importJWK(jwksData.keys[0], 'RS256')
      const { payload: claims } = await jwtVerify(idToken, pubKey, {
        issuer: BASE,
        audience: clientId,
      })

      expect(claims).not.toHaveProperty('siwe_message')
      expect(claims).not.toHaveProperty('siwe_signature')
    })
  })
})
