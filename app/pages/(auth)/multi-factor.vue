<template>
  <div>
    multi-factor

    <form
      method="post"
      @submit.prevent="useVerifyMfa()"
    >
      <input
        v-model="otp"
        type="text"
        placeholder="Code"
      >
      <button>Submit</button>
    </form>
  </div>
</template>

<script setup lang="ts">
async function sendOtp() {
  try {
    await $fetch('/api/auth/mfa/email/generate',
      { method: 'POST' }
    )
  } catch (error) {
    console.error(error)
  }
}
await sendOtp()
const otp = ref('')
async function useVerifyMfa() {
  try {
    await $fetch('/api/auth/mfa/email', {
      method: 'POST',
      body: JSON.stringify({
        otp: otp.value
      })
    })
  } catch (error) {
    console.error(error)
  }
}
</script>
