import { getProvider } from '../../utils/provider'
import {
  SiweMessage,
  SiweError,
  createViemConfig,
} from '@signinwithethereum/siwe'
import {
  validateSiweTimestamps,
  siweTimestampErrorMessage,
} from '../../utils/siwe-times'

export default defineEventHandler(async (event) => {
  const provider = await getProvider()
  const {
    node: { req, res },
  } = event

  // Get interaction details — validates the session cookie
  let details
  try {
    details = await provider.interactionDetails(req, res)
  } catch (e) {
    console.error('interactionDetails failed:', e)
    throw createError({
      statusCode: 400,
      statusMessage: 'Invalid interaction session',
    })
  }

  const body = await readBody(event)
  const { message, signature } = body
  if (!message || !signature) {
    throw createError({
      statusCode: 400,
      statusMessage: 'Missing message or signature',
    })
  }

  // ABNF-strict parse — the nonce is the hex-encoded interaction UID.
  // oidc-provider UIDs contain dashes/underscores which violate EIP-4361's
  // alphanumeric-only nonce rule, so we hex-encode to stay spec-compliant.
  let siweMessage: SiweMessage
  try {
    siweMessage = new SiweMessage(message)
  } catch {
    throw createError({
      statusCode: 400,
      statusMessage: 'Invalid SIWE message',
    })
  }

  // Buffer.from(…, 'hex') silently drops non-hex chars and odd trailing
  // nibbles, so validate format before decoding the nonce.
  const nonce = siweMessage.nonce
  if (
    nonce.length % 2 !== 0 ||
    !/^[0-9a-f]+$/i.test(nonce) ||
    Buffer.from(nonce, 'hex').toString() !== details.uid
  ) {
    throw createError({
      statusCode: 400,
      statusMessage: 'Nonce mismatch',
    })
  }

  // Validate the first Resources entry matches the OIDC redirect_uri
  const redirectUri = details.params.redirect_uri as string | undefined
  const firstResource = siweMessage.resources?.[0]
  if (!firstResource) {
    throw createError({
      statusCode: 400,
      statusMessage: 'Missing resource in SIWE message',
    })
  }
  if (firstResource !== redirectUri) {
    throw createError({
      statusCode: 400,
      statusMessage: 'SIWE resource does not match redirect_uri',
    })
  }

  // Enforce server-configured validity windows. The SIWE library's verify()
  // rejects past expirationTime / future notBefore, but only when present —
  // when the operator sets a policy we require the field and bound how far
  // in the future it can be set.
  const { oidc } = useRuntimeConfig()
  const timestampError = validateSiweTimestamps(siweMessage, {
    expirationTime: oidc.siweExpirationTime,
    notBefore: oidc.siweNotBefore,
  })
  if (timestampError) {
    throw createError({
      statusCode: 400,
      statusMessage: siweTimestampErrorMessage(timestampError),
    })
  }

  // Verify signature + domain binding — supports EOA, EIP-1271 (contract
  // wallets like Safe), and EIP-6492 (pre-deployed ERC-4337 accounts).
  // verify() throws SiweError directly (4.1.0+) on failure.
  // The publicClient must target the SIWE message's chain so that EIP-1271
  // contract wallet signatures are verified on the correct network.
  const publicClient = createChainClient(oidc.ethProvider, siweMessage.chainId)
  const config = await createViemConfig({ publicClient })

  let accountId: string
  try {
    const { data } = await siweMessage.verify(
      {
        signature,
        domain: new URL(oidc.baseUrl).host,
        nonce: siweMessage.nonce,
        chainId: siweMessage.chainId,
        uri: siweMessage.uri,
      },
      { config, strict: true },
    )
    accountId = `eip155:${data.chainId}:${config.getAddress(data.address)}`
  } catch (e) {
    if (e instanceof SiweError) {
      throw createError({ statusCode: 400, statusMessage: e.message })
    }
    throw e
  }

  // Complete the interaction — provider stores the result and returns the
  // redirect URL as JSON so the client can navigate via full page load,
  // avoiding cross-origin fetch redirect CORS issues.
  const redirectTo = await provider.interactionResult(req, res, {
    login: { accountId },
    siwe: { message, signature },
  })

  return { redirectTo }
})
