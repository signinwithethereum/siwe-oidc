import { getProvider } from '../../utils/provider'

export default defineEventHandler(async (event) => {
  const provider = await getProvider()
  const {
    node: { req, res },
  } = event

  try {
    const details = await provider.interactionDetails(req, res)
    const client = await provider.Client.find(
      details.params.client_id as string,
    )
    const meta = client?.metadata()
    const { oidc } = useRuntimeConfig()
    // Send durations (seconds), not absolute ISO timestamps. The client
    // computes the ISO at sign time so a slow signer / retry isn't doomed
    // by a stale, pre-baked expirationTime. Sending notBefore as a delta
    // would also be wrong: emitting `now + N` makes verify() throw
    // NOT_YET_VALID for the first N seconds. The contract here is "policy",
    // and the client materialises the field as `now`-anchored at sign time.
    return {
      uid: details.uid,
      nonce: Buffer.from(details.uid).toString('hex'),
      prompt: details.prompt,
      params: {
        client_id: details.params.client_id,
        scope: details.params.scope,
        redirect_uri: details.params.redirect_uri,
      },
      client: {
        name: meta?.client_name,
        logo_uri: meta?.logo_uri,
        client_uri: meta?.client_uri,
        policy_uri: meta?.policy_uri,
        tos_uri: meta?.tos_uri,
      },
      siwe: {
        expirationTimeSeconds:
          oidc.siweExpirationTime > 0 ? oidc.siweExpirationTime : null,
        notBeforeToleranceSeconds:
          oidc.siweNotBefore > 0 ? oidc.siweNotBefore : null,
      },
    }
  } catch (e) {
    console.error('interactionDetails failed:', e)
    throw createError({
      statusCode: 400,
      statusMessage: 'Invalid interaction session',
    })
  }
})
