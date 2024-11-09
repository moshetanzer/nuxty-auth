<script setup lang="ts">
async function useActivateMfa() {
  try {
    await $fetch('/api/auth/mfa/email/activate', {
      method: 'POST'
    })
  } catch (error) {
    console.error(error)
  }
}

async function useDeactivateMfa() {
  try {
    await $fetch('/api/auth/mfa/email/deactivate', {
      method: 'POST'
    })
  } catch (error) {
    console.error(error)
  }
}
const otp = ref('')
async function useVerifyMfa() {
  try {
    await $fetch('/api/auth/mfa/email/activate/verify', {
      method: 'POST',
      body: JSON.stringify({
        otp: otp.value
      })
    })
  } catch (error) {
    console.error(error)
  }
}
async function useVerifyMfaDeactivate() {
  try {
    await $fetch('/api/auth/mfa/email/deactivate/verify', {
      method: 'POST',
      body: JSON.stringify({
        otp: otp.value
      })
    })
  } catch (error) {
    console.error(error)
  }
}
const mfaActive = useUser().value?.mfa
</script>

<template>
  <div>
    <div v-if="!mfaActive">
      <h1>Activate MFA</h1>
      <button @click="useActivateMfa()">
        Activate Email MFA
      </button>
      <form @submit.prevent="useVerifyMfa()">
        <input
          v-model="otp"
          type="text"
          name="otp"
        >
        <button type="submit">
          Activate Mfa
        </button>
      </form>
    </div>
    <div v-else>
      <h1>MFA is active</h1>
      <button @click="useDeactivateMfa()">
        Deactivate MFA
      </button>
      <form @submit.prevent="useVerifyMfaDeactivate()">
        <input
          v-model="otp"
          type="text"
          name="otp"
        >
        <button type="submit">
          Deactivate Mfa
        </button>
      </form>
    </div>
  </div>
</template>
