export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: true },
  ssr: true,

  app: {
    head: {
      link: [
        { rel: 'icon', type: 'image/png', href: '/favicon.png' },
      ],
    },
  },

  extends: ['@1001-digital/layers.evm'],

  routeRules: {
    '/auth': { cors: true },
    '/token': { cors: true },
    '/me': { cors: true },
    '/jwks': { cors: true },
    '/reg': { cors: true },
    '/token/introspection': { cors: true },
    '/token/revocation': { cors: true },
    '/.well-known/**': { cors: true },
  },

  runtimeConfig: {
    oidc: {
      baseUrl: 'http://localhost:3000',
      redisUrl: 'redis://localhost:6379',
      rsaPem: '',
      requireSecret: true,
      ethProvider: '',
      defaultClients: '{}',
      cookieKeys: '',
      // SIWE message validity window. Seconds from issuance.
      // 0 disables — message omits the corresponding field.
      siweExpirationTime: 600,
      siweNotBefore: 0,
    },
  },
})
