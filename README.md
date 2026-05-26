# SIWE OIDC Provider

An OpenID Connect identity provider that authenticates users with their Ethereum wallets via [Sign in with Ethereum](https://siwe.xyz) (EIP-4361).

Any application that supports OIDC can use this provider to let users log in with their Ethereum address — no passwords, no email, no custodial accounts.

## How it works

```
┌────────┐     ┌─────────────┐     ┌───────────────┐
│  App   │────▶│ SIWE OIDC   │────▶│ User's Wallet │
│(Client)│◀────│  Provider   │◀────│  (MetaMask…)  │
└────────┘     └─────────────┘     └───────────────┘
  OIDC code      interaction         SIWE signature
  flow           + consent
```

1. Your app starts a standard OIDC authorization code flow
2. The provider presents a wallet-connect login page
3. The user signs a [SIWE message](https://eips.ethereum.org/EIPS/eip-4361) — this replaces both password entry and consent
4. The provider verifies the signature and issues OIDC tokens
5. Your app receives an ID token with the user's Ethereum identity

The user's SIWE signature **is** their consent — no additional consent screen needed.

## Features

- Full OIDC authorization code flow with PKCE
- Dynamic client registration (`/reg`)
- Pre-configured default clients via environment variable
- ENS name and avatar resolution (returned as `preferred_username` and `picture` claims)
- Smart wallet support: EOA, EIP-1271 (contract wallets), EIP-6492 (counterfactual)
- Token introspection and revocation
- RP-Initiated Logout
- Redis-backed session storage
- Auto-generated RSA signing keys (shared safely across workers)
- Docker and Docker Compose deployment

## Quick start

### Prerequisites

- Node.js 22+
- Redis
- pnpm

### Run locally

```bash
# Install dependencies
pnpm install

# Copy and configure environment
cp .env.example .env

# Start development server
pnpm dev
```

The provider starts at `http://localhost:3000`. Visit `http://localhost:3000/.well-known/openid-configuration` to see the OIDC discovery document.

### Run with Docker

```bash
docker compose up
```

This starts both the provider and a Redis instance.

## Configuration

All configuration is via environment variables (see `.env.example`):

| Variable                                    | Description                                                    | Default                  |
| ------------------------------------------- | -------------------------------------------------------------- | ------------------------ |
| `NUXT_OIDC_BASE_URL`                        | Issuer URL                                                     | `http://localhost:3000`  |
| `NUXT_OIDC_REDIS_URL`                       | Redis connection URL                                           | `redis://localhost:6379` |
| `NUXT_OIDC_COOKIE_KEYS`                     | Cookie signing keys (comma-separated)                          | _required_               |
| `NUXT_OIDC_RSA_PEM`                         | RSA private key in PEM format                                  | auto-generated           |
| `NUXT_OIDC_REQUIRE_SECRET`                  | Require client secret for token exchange                       | `true`                   |
| `NUXT_OIDC_ETH_PROVIDER`                    | Ethereum RPC URL for ENS resolution                            | public default           |
| `NUXT_OIDC_DEFAULT_CLIENTS`                 | Pre-configured clients (JSON)                                  | `{}`                     |
| `NUXT_OIDC_SIWE_EXPIRATION_TIME`            | SIWE Expiration Time policy (seconds, `0`=off)                 | `600`                    |
| `NUXT_OIDC_SIWE_NOT_BEFORE`                 | SIWE Not Before tolerance (seconds, `0`=off)                   | `0`                      |
| `NUXT_PUBLIC_EVM_WALLET_CONNECT_PROJECT_ID` | WalletConnect project ID                                       | —                        |
| `NUXT_PUBLIC_EVM_CHAINS_MAINNET_RPCS`       | Ethereum mainnet RPC URLs                                      | —                        |

### SIWE message validity window

The server tells the client (in the interaction GET response) how many
seconds of validity to bake into the signed SIWE message, and then enforces
the policy on POST.

- `NUXT_OIDC_SIWE_EXPIRATION_TIME` — when non-zero, the signed message must
  include `Expiration Time`. The server rejects login if the field is
  missing or set further than `EXPIRATION_TIME + 60s` (clock-skew grace)
  past the verification time. The SIWE library separately rejects already
  expired messages. The client computes `Expiration Time = now + N` at sign
  time, so retries after an expired window get a fresh value.
- `NUXT_OIDC_SIWE_NOT_BEFORE` — when non-zero, the signed message must
  include `Not Before`. The client emits `Not Before = now` (immediate
  validity); the server rejects values more than `NOT_BEFORE + 60s` past
  the verification time. This is a *tolerance* — it bounds how far in the
  future a tampered or misconfigured client can push the field. Setting it
  does **not** delay sign-in by N seconds.

Set either to `0` to disable enforcement and omit the corresponding field
from the message the client signs.

### Default clients

Pre-register clients so they don't need to call `/reg`:

```bash
# Simple: client_id → redirect_uri
NUXT_OIDC_DEFAULT_CLIENTS='{"my-app": "https://myapp.com/callback"}'

# Rich: with display metadata shown on the login page
NUXT_OIDC_DEFAULT_CLIENTS='{
  "my-app": {
    "redirect_uri": "https://myapp.com/callback",
    "client_name": "My App",
    "logo_uri": "https://myapp.com/logo.png",
    "client_uri": "https://myapp.com",
    "policy_uri": "https://myapp.com/privacy",
    "tos_uri": "https://myapp.com/terms"
  }
}'
```

## OIDC endpoints

| Endpoint                                | Description                 |
| --------------------------------------- | --------------------------- |
| `GET /.well-known/openid-configuration` | Discovery document          |
| `POST /auth`                            | Authorization               |
| `POST /token`                           | Token exchange              |
| `GET /jwks`                             | JSON Web Key Set            |
| `GET /me`                               | UserInfo                    |
| `POST /reg`                             | Dynamic client registration |
| `POST /token/introspection`             | Token introspection         |
| `POST /token/revocation`                | Token revocation            |
| `POST /session/end`                     | RP-Initiated Logout         |

## Identity claims

| Claim                | Source                       | Scope     |
| -------------------- | ---------------------------- | --------- |
| `sub`                | `eip155:{chainId}:{address}` | `openid`  |
| `preferred_username` | ENS name or Ethereum address | `profile` |
| `picture`            | ENS avatar                   | `profile` |

## Development

```bash
pnpm dev          # Start dev server
pnpm test         # Run tests
pnpm typecheck    # Type check
pnpm format       # Format with Prettier
pnpm build        # Production build
```

## Tech stack

- [oidc-provider](https://github.com/panva/node-oidc-provider) — certified OIDC implementation
- [siwe](https://github.com/signinwithethereum/siwe) — Sign in with Ethereum
- [viem](https://viem.sh) — Ethereum client
- [ioredis](https://github.com/redis/ioredis) — Redis client
- [jose](https://github.com/panva/jose) — JWT/JWK operations
- [Nuxt 4](https://nuxt.com) — full-stack framework

## License

MIT — Copyright [EthID.org](https://ethid.org)
