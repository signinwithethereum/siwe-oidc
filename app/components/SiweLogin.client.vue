<script setup lang="ts">
const props = defineProps<{
  uid: string
  nonce: string
  clientId?: string
  redirectUri?: string
  expirationTimeSeconds?: number | null
  notBeforeToleranceSeconds?: number | null
}>()

const emit = defineEmits<{
  error: [message: string]
}>()

type Step = 'idle' | 'signing' | 'verifying' | 'complete' | 'error'

const step = ref<Step>('idle')
const errorMessage = ref('')

const { address, isConnected, chainId, connector } = useConnection()
const { mutateAsync: signMessageAsync } = useSignMessage()
const { mutateAsync: switchChainAsync } = useSwitchChain()
const { mutate: disconnectAccount } = useDisconnect()

const isBusy = computed(() =>
  ['signing', 'verifying', 'complete'].includes(step.value),
)
const statusText = computed(() => {
  switch (step.value) {
    case 'signing':
      return connector.value?.name
        ? `Requesting signature from ${connector.value.name}...`
        : 'Requesting signature...'
    case 'verifying':
      return 'Verifying signature...'
    default:
      return ''
  }
})
const userInitiated = ref(false)
const redirectTo = ref<string>()
// Reentrancy guard. step transitions to 'signing' only after several awaits
// (chainId, switchChain) — during that window the watcher would otherwise
// see step==='idle' and trigger a second concurrent handleSignIn.
const inFlight = ref(false)

function reset() {
  step.value = 'idle'
  errorMessage.value = ''
}

function disconnect() {
  reset()
  userInitiated.value = false
  disconnectAccount()
}

// Walk error cause chain — wallet libraries nest the user-rejection signal
// at varying depths (code 4001, message contains "reject"/"denied"/"cancel").
// Use a Set to break cycles in case some library produces self-referential
// cause links.
function isUserRejection(e: unknown): boolean {
  const re = /reject|denied|cancel/i
  const seen = new WeakSet<object>()
  let current = e as Record<string, unknown> | undefined
  while (current && typeof current === 'object' && !seen.has(current)) {
    seen.add(current)
    if ((current as { code?: number }).code === 4001) return true
    if (re.test((current as { details?: string }).details || '')) return true
    if (re.test((current as { message?: string }).message || '')) return true
    current = current.cause as Record<string, unknown> | undefined
  }
  return false
}

function failWith(msg: string) {
  errorMessage.value = msg
  step.value = 'error'
  emit('error', msg)
}

async function handleSignIn() {
  if (inFlight.value) return
  inFlight.value = true
  try {
    redirectTo.value = undefined
    errorMessage.value = ''

    const currentAddress = address.value
    const currentChainId = chainId.value
    if (!currentAddress || !currentChainId) {
      failWith('Wallet not connected.')
      return
    }

    try {
      const connectorChainId = await connector.value?.getChainId()
      if (
        typeof connectorChainId === 'number' &&
        connectorChainId !== currentChainId
      ) {
        await switchChainAsync({ chainId: currentChainId })
      }
    } catch (e: unknown) {
      if (isUserRejection(e)) {
        failWith('Network switch rejected by user.')
      } else {
        failWith('Failed to switch to the required network.')
      }
      return
    }

    // Build timestamps fresh at sign time so a retry after EXPIRED_MESSAGE
    // gets a new window instead of replaying the stale value.
    const nowMs = Date.now()
    const expSecs = props.expirationTimeSeconds ?? 0
    const expirationTime =
      expSecs > 0
        ? new Date(nowMs + expSecs * 1000).toISOString()
        : undefined
    // notBefore = now: the message is immediately valid. The server's policy
    // value is the *tolerance* (validateSiweTimestamps rejects values > now +
    // tolerance + grace), not an activation delay.
    const notBefore =
      (props.notBeforeToleranceSeconds ?? 0) > 0
        ? new Date(nowMs).toISOString()
        : undefined

    const message = createSiweMessage({
      domain: window.location.host,
      address: currentAddress,
      uri: window.location.origin,
      chainId: currentChainId,
      nonce: props.nonce,
      statement: 'Sign in with Ethereum',
      expirationTime,
      notBefore,
      resources: props.redirectUri ? [props.redirectUri] : undefined,
    })

    step.value = 'signing'
    let signature: string
    try {
      signature = await signMessageAsync({ message })
    } catch (e: unknown) {
      if (isUserRejection(e)) {
        failWith('Signature rejected by user.')
      } else {
        const err = e as { shortMessage?: string; message?: string }
        failWith(err.shortMessage || err.message || 'Failed to sign message.')
      }
      return
    }

    step.value = 'verifying'
    try {
      const response = await fetch(`/api/interaction/${props.uid}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, signature }),
      })

      if (!response.ok) {
        const error = await response
          .json()
          .catch(() => ({ statusMessage: 'Verification failed' }))
        throw new Error(error.statusMessage || 'Verification failed')
      }

      const data = await response.json()
      redirectTo.value = data.redirectTo
    } catch (e: unknown) {
      const err = e as { message?: string }
      failWith(err.message || 'Verification failed.')
      return
    }

    step.value = 'complete'

    if (redirectTo.value) {
      try {
        await navigateTo(redirectTo.value, { external: true })
      } catch (e: unknown) {
        // Server completed the interaction but navigation failed (popup
        // blocker, intercepted URL, etc). Surface as a recoverable error so
        // the user isn't stuck on the "Redirecting…" spinner.
        const err = e as { message?: string }
        failWith(err.message || 'Failed to navigate to the application.')
        return
      }
    } else {
      // 200 with no redirectTo — provider didn't complete the interaction.
      // Don't strand the UI on "Redirecting…".
      failWith('Sign-in completed but no redirect was issued. Please retry.')
      return
    }
  } finally {
    inFlight.value = false
    // Consume the auto-sign intent — a later auto-reconnect shouldn't sign
    // again without an explicit user click.
    if (step.value !== 'idle') userInitiated.value = false
  }
}

// Auto-sign when user actively connects via EvmConnect
watch([isConnected, address], ([connected, addr]) => {
  if (
    connected &&
    addr &&
    step.value === 'idle' &&
    userInitiated.value &&
    !inFlight.value
  ) {
    handleSignIn()
  }
})
</script>

<template>
  <div class="siwe-login">
    <Loading
      v-if="isBusy"
      spinner
      stacked
      :txt="step === 'complete' ? 'Redirecting…' : statusText"
    />

    <template v-else-if="isConnected && step === 'error'">
      <Alert type="error">
        <p>{{ errorMessage }}</p>
      </Alert>
      <Button
        class="danger block"
        @click="handleSignIn"
      >
        Try again
      </Button>
    </template>

    <template v-if="isConnected && address">
      <Button
        v-if="step === 'idle'"
        class="primary block"
        @click="handleSignIn"
      >
        Sign in with Ethereum
      </Button>
      <Button
        v-if="!isBusy"
        class="tertiary block"
        @click="disconnect()"
      >
        Switch wallet (<EvmAccount
          :address="address"
          class="siwe-address"
        />)
      </Button>
    </template>

    <EvmConnect
      v-else-if="!isBusy"
      @connecting="userInitiated = true"
    />
  </div>
</template>

<style scoped>
.siwe-login {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--spacer);
  padding: var(--spacer);

  > * {
    inline-size: 100%;
  }
}
</style>
